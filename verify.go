package irma

import (
	"crypto/rsa"
	"time"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/revocation"
)

// ProofStatus is the status of the complete proof
type ProofStatus string

// Status is the proof status of a single attribute
type AttributeProofStatus string

const (
	ProofStatusValid             = ProofStatus("VALID")              // Proof is valid
	ProofStatusInvalid           = ProofStatus("INVALID")            // Proof is invalid
	ProofStatusInvalidTimestamp  = ProofStatus("INVALID_TIMESTAMP")  // Attribute-based signature had invalid timestamp
	ProofStatusUnmatchedRequest  = ProofStatus("UNMATCHED_REQUEST")  // Proof does not correspond to a specified request
	ProofStatusMissingAttributes = ProofStatus("MISSING_ATTRIBUTES") // Proof does not contain all requested attributes
	ProofStatusExpired           = ProofStatus("EXPIRED")            // Attributes were expired at proof creation time (now, or according to timestamp in case of abs)

	AttributeProofStatusPresent = AttributeProofStatus("PRESENT") // Attribute is disclosed and matches the value
	AttributeProofStatusExtra   = AttributeProofStatus("EXTRA")   // Attribute is disclosed, but wasn't requested in request
	AttributeProofStatusNull    = AttributeProofStatus("NULL")    // Attribute is disclosed but is null
)

// DisclosedAttribute represents a disclosed attribute.
type DisclosedAttribute struct {
	RawValue         *string                 `json:"rawvalue"`
	Value            TranslatedString        `json:"value"` // Value of the disclosed attribute
	Identifier       AttributeTypeIdentifier `json:"id"`
	Status           AttributeProofStatus    `json:"status"`
	IssuanceTime     Timestamp               `json:"issuancetime"`
	NotRevoked       bool                    `json:"notrevoked,omitempty"`
	NotRevokedBefore *Timestamp              `json:"notrevokedbefore,omitempty"`
}

// ProofList is a gabi.ProofList with some extra methods.
type ProofList gabi.ProofList

var ErrMissingPublicKey = errors.New("Missing public key")

// ExtractPublicKeys returns the public keys of each proof in the proofList, in the same order,
// for later use in verification of the proofList. If one of the proofs is not a ProofD
// an error is returned.
func (pl ProofList) ExtractPublicKeys(configuration *Configuration) ([]*gabikeys.PublicKey, error) {
	var publicKeys = make([]*gabikeys.PublicKey, 0, len(pl))

	for _, v := range pl {
		switch v.(type) {
		case *gabi.ProofD:
			proof := v.(*gabi.ProofD)
			metadata := MetadataFromInt(proof.ADisclosed[1], configuration) // index 1 is metadata attribute
			publicKey, err := metadata.PublicKey()
			if err != nil {
				return nil, err
			}
			if publicKey == nil {
				return nil, ErrMissingPublicKey
			}
			publicKeys = append(publicKeys, publicKey)
		default:
			return nil, errors.New("Cannot extract public key, not a disclosure proofD")
		}
	}
	return publicKeys, nil
}

// Expired returns true if any of the contained disclosure proofs is specified at the specified time,
// or now, when the specified time is nil.
func (pl ProofList) Expired(configuration *Configuration, t *time.Time) (bool, error) {
	if t == nil {
		temp := time.Now()
		t = &temp
	}
	for _, proof := range pl {
		proofd, ok := proof.(*gabi.ProofD)
		if !ok {
			continue
		}
		metadata := MetadataFromInt(proofd.ADisclosed[1], configuration) // index 1 is metadata attribute
		if metadata.Expiry().Before(*t) {
			return true, nil
		}
		pk, err := metadata.PublicKey()
		if err != nil {
			return false, err
		}
		if metadata.SigningDate().Unix() > pk.ExpiryDate {
			return true, nil
		}
	}
	return false, nil
}

func extractAttribute(pl gabi.ProofList, index *DisclosedAttributeIndex, notrevoked *time.Time, conf *Configuration) (*DisclosedAttribute, *string, error) {
	if len(pl) < index.CredentialIndex {
		return nil, nil, errors.New("Credential index out of range")
	}
	proofd, ok := pl[index.CredentialIndex].(*gabi.ProofD)
	if !ok {
		// If with the index the user told us to look for the required attribute at this specific location,
		// and the proof here is not a disclosure proof, then reject
		return nil, nil, errors.New("ProofList contained proof of invalid type")
	}

	metadata := MetadataFromInt(proofd.ADisclosed[1], conf) // index 1 is metadata attribute
	attr, str, err := parseAttribute(index.AttributeIndex, metadata, proofd.ADisclosed[index.AttributeIndex])
	if err != nil {
		return nil, nil, err
	}
	attr.NotRevokedBefore = (*Timestamp)(notrevoked)
	attr.NotRevoked = proofd.NonRevocationProof != nil
	return attr, str, nil
}

// VerifyProofs verifies the proofs cryptographically.
func (pl ProofList) VerifyProofs(
	configuration *Configuration,
	request SessionRequest,
	context *big.Int, nonce *big.Int,
	publickeys []*gabikeys.PublicKey,
	validAt *time.Time,
	isSig bool,
) (bool, map[int]*time.Time, error) {
	// Empty proof lists are allowed (if consistent with the session request, which is checked elsewhere)
	if len(pl) == 0 {
		return true, nil, nil
	}

	if publickeys == nil {
		var err error
		publickeys, err = pl.ExtractPublicKeys(configuration)
		if err != nil {
			return false, nil, err
		}
	}

	if len(pl) != len(publickeys) {
		return false, nil, errors.New("Insufficient public keys to verify the proofs")
	}

	// Compute slice to inform gabi of which proofs should be verified to share the same secret key
	keyshareServers := make([]string, len(pl))
	for i := range pl {
		schemeID := NewIssuerIdentifier(publickeys[i].Issuer).SchemeManagerIdentifier()
		if !configuration.SchemeManagers[schemeID].Distributed() {
			keyshareServers[i] = "." // dummy value: no IRMA scheme will ever have this name
		} else {
			keyshareServers[i] = schemeID.Name()
		}
	}

	if !gabi.ProofList(pl).Verify(publickeys, context, nonce, isSig, keyshareServers) {
		return false, nil, nil
	}

	// Perform per-proof verifications for each proof:
	// - verify that any singleton credential occurs at most once in the prooflist
	// - verify that all required nonrevocation proofs are present
	singletons := map[CredentialTypeIdentifier]bool{}
	revocationtime := map[int]*time.Time{} // per proof, stores up to what time it is known to be not revoked
	var revParams NonRevocationParameters
	if request != nil {
		revParams = request.Base().Revocation
	}
	for i, proof := range pl {
		proofd, ok := proof.(*gabi.ProofD)
		if !ok {
			continue
		}
		typ := MetadataFromInt(proofd.ADisclosed[1], configuration).CredentialType()
		if typ == nil {
			return false, nil, errors.New("Received unknown credential type")
		}
		id := typ.Identifier()
		if typ.IsSingleton {
			if !singletons[id] { // Seen for the first time
				singletons[id] = true
			} else { // Seen for the second time
				return false, nil, nil
			}
		}

		// The cryptographic validity of all included nonrevocation proofs has already been checked
		// by ProofList.Verify() above, so all that remains here is to check if all expected
		// nonrevocation proofs are present, and against the expected accumulator value:
		// the last one in the update message set we provided along with the session request,
		// OR a newer one included in the proofs itself.
		if !proofd.HasNonRevocationProof() {
			if revParams[id] != nil {
				// no nonrevocation proof is included but one was required in the session request
				return false, nil, nil
			} else {
				continue
			}
		}

		sig := proofd.NonRevocationProof.SignedAccumulator
		pk, err := RevocationKeys{configuration}.PublicKey(typ.IssuerIdentifier(), sig.PKCounter)
		if err != nil {
			return false, nil, nil
		}
		acc, err := proofd.NonRevocationProof.SignedAccumulator.UnmarshalVerify(pk)
		if err != nil {
			return false, nil, nil
		}

		theirs := acc.Index
		acctime := time.Unix(acc.Time, 0)
		settings := configuration.Revocation.settings.Get(id)
		var ours uint64
		var updates map[uint]*revocation.Update
		if revParams[id] != nil {
			updates = revParams[id].Updates
		}
		if u := updates[sig.PKCounter]; u != nil {
			ours = u.Events[len(u.Events)-1].Index
		}
		if ours > theirs {
			return false, nil, nil
		}
		if ours == theirs {
			if settings.updated.After(acctime) {
				acctime = settings.updated
			}
		}
		if validAt == nil {
			t := time.Now()
			validAt = &t
		}
		tolerance := settings.Tolerance
		if s := revParams[id]; s != nil && s.Tolerance != 0 {
			tolerance = s.Tolerance
		}
		if uint64(validAt.Sub(acctime).Seconds()) > tolerance {
			revocationtime[i] = &acctime
		}
	}

	return true, revocationtime, nil
}

func (d *Disclosure) extraIndices(condiscon AttributeConDisCon) []*DisclosedAttributeIndex {
	disclosed := make([]map[int]struct{}, len(d.Proofs))
	for i, proof := range d.Proofs {
		proofd, ok := proof.(*gabi.ProofD)
		if !ok {
			continue
		}
		disclosed[i] = map[int]struct{}{}
		for j := range proofd.ADisclosed {
			if j <= 1 {
				continue
			}
			disclosed[i][j] = struct{}{}
		}
	}

	for i, set := range d.Indices {
		if len(condiscon) <= i {
			continue
		}
		for _, index := range set {
			delete(disclosed[index.CredentialIndex], index.AttributeIndex)
		}
	}

	var extra []*DisclosedAttributeIndex
	for i, attrs := range disclosed {
		for j := range attrs {
			extra = append(extra, &DisclosedAttributeIndex{CredentialIndex: i, AttributeIndex: j})
		}
	}

	return extra
}

// DisclosedAttributes returns a slice containing for each item in the conjunction the disclosed
// attributes that are present in the proof list. If a non-empty and non-nil AttributeDisjunctionList
// is included, then the first attributes in the returned slice match with the disjunction list in
// the disjunction list. The first return parameter of this function indicates whether or not all
// disjunctions (if present) are satisfied.
func (d *Disclosure) DisclosedAttributes(configuration *Configuration, condiscon AttributeConDisCon, revtimes map[int]*time.Time) (bool, [][]*DisclosedAttribute, error) {
	if revtimes == nil {
		revtimes = map[int]*time.Time{}
	}
	complete, list, err := condiscon.Satisfy(d, revtimes, configuration)
	if err != nil {
		return false, nil, err
	}

	var extra []*DisclosedAttribute
	indices := d.extraIndices(condiscon)
	for _, index := range indices {
		attr, _, err := extractAttribute(d.Proofs, index, revtimes[index.CredentialIndex], configuration)
		if err != nil {
			return false, nil, err
		}
		attr.Status = AttributeProofStatusExtra
		extra = append(extra, attr)
	}
	if len(extra) > 0 {
		list = append(list, extra)
	}

	return complete, list, nil
}

func parseAttribute(index int, metadata *MetadataAttribute, attr *big.Int) (*DisclosedAttribute, *string, error) {
	var attrid AttributeTypeIdentifier
	var attrval *string
	credtype := metadata.CredentialType()
	if credtype == nil {
		return nil, nil, errors.New("ProofList contained a disclosure proof of an unknown credential type")
	}
	if index == 1 {
		attrid = NewAttributeTypeIdentifier(credtype.Identifier().String())
		p := "present"
		attrval = &p
	} else {
		attrid = credtype.AttributeTypes[index-2].GetAttributeTypeIdentifier()
		if credtype.AttributeTypes[index-2].RandomBlind {
			attrval = DecodeRandomBlind(attr)
		} else {
			attrval = DecodeAttribute(attr, metadata.Version())
		}
	}
	status := AttributeProofStatusPresent
	if attrval == nil {
		status = AttributeProofStatusNull
	}
	return &DisclosedAttribute{
		Identifier:   attrid,
		RawValue:     attrval,
		Value:        NewTranslatedString(attrval),
		Status:       status,
		IssuanceTime: Timestamp(metadata.SigningDate()),
	}, attrval, nil
}

func (d *Disclosure) VerifyAgainstRequest(
	configuration *Configuration,
	request SessionRequest,
	context, nonce *big.Int,
	publickeys []*gabikeys.PublicKey,
	validAt *time.Time,
	issig bool,
) ([][]*DisclosedAttribute, ProofStatus, error) {
	// Cryptographically verify all included IRMA proofs
	valid, revtimes, err := ProofList(d.Proofs).VerifyProofs(configuration, request, context, nonce, publickeys, validAt, issig)
	if !valid || err != nil {
		return nil, ProofStatusInvalid, err
	}

	// Next extract the contained attributes from the proofs, and match them to the signature request if present
	var required AttributeConDisCon
	if request != nil {
		required = request.Disclosure().Disclose
	}
	allmatched, list, err := d.DisclosedAttributes(configuration, required, revtimes)
	if err != nil {
		return nil, ProofStatusInvalid, err
	}

	// Return MISSING_ATTRIBUTES as proofstatus if one of the disjunctions in the request (if present) is not satisfied
	if !allmatched {
		return list, ProofStatusMissingAttributes, nil
	}

	// Check that all credentials were unexpired
	expired, err := ProofList(d.Proofs).Expired(configuration, validAt)
	if err != nil {
		return nil, ProofStatusInvalid, err
	}
	if expired {
		return list, ProofStatusExpired, nil
	}

	return list, ProofStatusValid, nil
}

func (d *Disclosure) Verify(configuration *Configuration, request *DisclosureRequest) ([][]*DisclosedAttribute, ProofStatus, error) {
	return d.VerifyAgainstRequest(configuration, request, request.GetContext(), request.GetNonce(nil), nil, nil, false)
}

// Verify the attribute-based signature, optionally against a corresponding signature request. If the request is present
// (i.e. not nil), then the first attributes in the returned result match with the disjunction list in the request
// (that is, the i'th attribute in the result should satisfy the i'th disjunction in the request). If the request is not
// fully satisfied in this fashion, the Status of the result is ProofStatusMissingAttributes. Any remaining attributes
// (i.e. not asked for by the request) are also included in the result, after the attributes that match disjunctions
// in the request.
//
// The signature request is optional; if it is nil then the attribute-based signature is still verified, and all
// containing attributes returned in the result.
func (sm *SignedMessage) Verify(configuration *Configuration, request *SignatureRequest) ([][]*DisclosedAttribute, ProofStatus, error) {
	var message string

	if len(sm.Signature) == 0 {
		return nil, ProofStatusInvalid, nil
	}

	// First check if this signature matches the request
	if request != nil {
		if !sm.MatchesNonceAndContext(request) {
			return nil, ProofStatusUnmatchedRequest, nil
		}
		// If there is a request, then the signed message must be that of the request
		message = request.Message
	} else {
		// If not, we just verify that the signed message is a valid signature over its contained message
		message = sm.Message
	}

	// Next, verify the timestamp so we can safely use its time
	t := time.Now()
	if sm.Timestamp != nil {
		if err := sm.VerifyTimestamp(message, configuration); err != nil {
			return nil, ProofStatusInvalidTimestamp, nil
		}
		t = time.Unix(sm.Timestamp.Time, 0)
	}

	// Finally, cryptographically verify the IRMA disclosure proofs in the signature
	// and verify that it satisfies the signature request, if present
	var r SessionRequest // wrapper for request to avoid avoid https://golang.org/doc/faq#nil_error
	if request != nil {
		r = request
	}
	return sm.Disclosure().VerifyAgainstRequest(configuration, r, sm.Context, sm.GetNonce(), nil, &t, true)
}

// ExpiredError indicates that something (e.g. a JWT) has expired.
type ExpiredError struct {
	Err error // underlying error
}

func (e ExpiredError) Error() string {
	return "irmago: expired (" + e.Err.Error() + ")"
}

// ParseApiServerJwt verifies and parses a JWT as returned by an irma_api_server after a disclosure request into a key-value pair.
func ParseApiServerJwt(inputJwt string, signingKey *rsa.PublicKey) (map[AttributeTypeIdentifier]*DisclosedAttribute, error) {
	claims := struct {
		jwt.StandardClaims
		Attributes map[AttributeTypeIdentifier]string `json:"attributes"`
	}{}
	_, err := jwt.ParseWithClaims(inputJwt, claims, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil {
		if err, ok := err.(*jwt.ValidationError); ok && (err.Errors&jwt.ValidationErrorExpired) != 0 {
			return nil, ExpiredError{err}
		} else {
			return nil, err
		}
	}

	if claims.Subject != "disclosure_result" {
		return nil, errors.New("JWT is not a disclosure result")
	}

	disclosedAttributes := make(map[AttributeTypeIdentifier]*DisclosedAttribute, len(claims.Attributes))
	for id, value := range claims.Attributes {
		disclosedAttributes[id] = &DisclosedAttribute{
			Identifier: id,
			RawValue:   &value,
			Value:      NewTranslatedString(&value),
			Status:     AttributeProofStatusPresent,
		}
	}

	return disclosedAttributes, nil
}
