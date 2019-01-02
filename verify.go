package irma

import (
	"crypto/rsa"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
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

	AttributeProofStatusPresent      = AttributeProofStatus("PRESENT")       // Attribute is disclosed and matches the value
	AttributeProofStatusExtra        = AttributeProofStatus("EXTRA")         // Attribute is disclosed, but wasn't requested in request
	AttributeProofStatusMissing      = AttributeProofStatus("MISSING")       // Attribute is NOT disclosed, but should be according to request
	AttributeProofStatusInvalidValue = AttributeProofStatus("INVALID_VALUE") // Attribute is disclosed, but has invalid value according to request
)

// DisclosedAttribute represents a disclosed attribute.
type DisclosedAttribute struct {
	RawValue   *string                 `json:"rawvalue"`
	Value      TranslatedString        `json:"value"` // Value of the disclosed attribute
	Identifier AttributeTypeIdentifier `json:"id"`
	Status     AttributeProofStatus    `json:"status"`
}

// ProofList is a gabi.ProofList with some extra methods.
type ProofList gabi.ProofList

var ErrorMissingPublicKey = errors.New("Missing public key")

// ExtractPublicKeys returns the public keys of each proof in the proofList, in the same order,
// for later use in verification of the proofList. If one of the proofs is not a ProofD
// an error is returned.
func (pl ProofList) ExtractPublicKeys(configuration *Configuration) ([]*gabi.PublicKey, error) {
	var publicKeys = make([]*gabi.PublicKey, 0, len(pl))

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
				return nil, ErrorMissingPublicKey
			}
			publicKeys = append(publicKeys, publicKey)
		default:
			return nil, errors.New("Cannot extract public key, not a disclosure proofD")
		}
	}
	return publicKeys, nil
}

// VerifyProofs verifies the proofs cryptographically.
func (pl ProofList) VerifyProofs(configuration *Configuration, context *big.Int, nonce *big.Int, publickeys []*gabi.PublicKey, isSig bool) (bool, error) {
	if publickeys == nil {
		var err error
		publickeys, err = pl.ExtractPublicKeys(configuration)
		if err != nil {
			return false, err
		}
	}

	if len(pl) != len(publickeys) {
		return false, errors.New("Insufficient public keys to verify the proofs")
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

	return gabi.ProofList(pl).Verify(publickeys, context, nonce, isSig, keyshareServers), nil
}

// Expired returns true if any of the contained disclosure proofs is specified at the specified time,
// or now, when the specified time is nil.
func (pl ProofList) Expired(configuration *Configuration, t *time.Time) bool {
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
			return true
		}
	}
	return false
}

// DisclosedAttributes returns a slice containing the disclosed attributes that are present in the proof list.
// If a non-empty and non-nil AttributeDisjunctionList is included, then the first attributes in the returned slice match
// with the disjunction list in the disjunction list. If any of the given disjunctions is not matched by one
// of the disclosed attributes, then the corresponding item in the returned slice has status AttributeProofStatusMissing.
// The first return parameter of this function indicates whether or not all disjunctions (if present) are satisfied.
func (d *Disclosure) DisclosedAttributes(configuration *Configuration, disjunctions AttributeDisjunctionList) (bool, []*DisclosedAttribute, error) {
	if d.Indices == nil || len(disjunctions) == 0 {
		return ProofList(d.Proofs).DisclosedAttributes(configuration, disjunctions)
	}

	list := make([]*DisclosedAttribute, len(disjunctions))
	usedAttrs := map[int]map[int]struct{}{} // keep track of attributes that satisfy the disjunctions

	// For each of the disjunctions, lookup the attribute that the user sent to satisfy this disjunction,
	// using the indices specified by the user in d.Indices. Then see if the attribute satisfies the disjunction.
	for i, disjunction := range disjunctions {
		index := d.Indices[i][0]
		proofd, ok := d.Proofs[index.CredentialIndex].(*gabi.ProofD)
		if !ok {
			// If with the index the user told us to look for the required attribute at this specific location,
			// and the proof here is not a disclosure proof, then reject
			return false, nil, errors.New("ProofList contained proof of invalid type")
		}

		metadata := MetadataFromInt(proofd.ADisclosed[1], configuration) // index 1 is metadata attribute
		attr, attrval, err := parseAttribute(index.AttributeIndex, metadata, proofd.ADisclosed[index.AttributeIndex])
		if err != nil {
			return false, nil, err
		}

		if disjunction.attemptSatisfy(attr.Identifier, attrval) {
			list[i] = attr
			if disjunction.satisfied() {
				list[i].Status = AttributeProofStatusPresent
			} else {
				list[i].Status = AttributeProofStatusInvalidValue
			}
			if usedAttrs[index.CredentialIndex] == nil {
				usedAttrs[index.CredentialIndex] = map[int]struct{}{}
			}
			usedAttrs[index.CredentialIndex][index.AttributeIndex] = struct{}{}
		} else {
			list[i] = &DisclosedAttribute{Status: AttributeProofStatusMissing}
		}
	}

	// Loop over any extra attributes in d.Proofs not requested in any of the disjunctions
	for i, proof := range d.Proofs {
		proofd, ok := proof.(*gabi.ProofD)
		if !ok {
			continue
		}
		metadata := MetadataFromInt(proofd.ADisclosed[1], configuration) // index 1 is metadata attribute
		for attrIndex, attrInt := range proofd.ADisclosed {
			if attrIndex == 0 || attrIndex == 1 { // Never add secret key or metadata (i.e. no-attribute disclosure) as extra
				continue // Note that the secret should never be disclosed by the client, but we skip it to be sure
			}
			if _, used := usedAttrs[i][attrIndex]; used {
				continue
			}

			attr, _, err := parseAttribute(attrIndex, metadata, attrInt)
			if err != nil {
				return false, nil, err
			}
			attr.Status = AttributeProofStatusExtra
			list = append(list, attr)
		}
	}

	return len(disjunctions) == 0 || disjunctions.satisfied(), list, nil
}

func parseAttribute(index int, metadata *MetadataAttribute, attr *big.Int) (*DisclosedAttribute, *string, error) {
	var attrid AttributeTypeIdentifier
	var attrval *string
	credtype := metadata.CredentialType()
	if credtype == nil {
		return nil, nil, errors.New("ProofList contained a disclosure proof of an unkown credential type")
	}
	if index == 1 {
		attrid = NewAttributeTypeIdentifier(credtype.Identifier().String())
		p := "present"
		attrval = &p
	} else {
		attrid = credtype.AttributeTypes[index-2].GetAttributeTypeIdentifier()
		attrval = decodeAttribute(attr, metadata.Version())
	}
	return &DisclosedAttribute{
		Identifier: attrid,
		RawValue:   attrval,
		Value:      translateAttribute(attrval),
	}, attrval, nil
}

func (pl ProofList) DisclosedAttributes(configuration *Configuration, disjunctions AttributeDisjunctionList) (bool, []*DisclosedAttribute, error) {
	var list []*DisclosedAttribute
	list = make([]*DisclosedAttribute, len(disjunctions))
	for i := range list {
		// Populate list with AttributeProofStatusMissing; if an attribute that satisfies a disjunction
		// is found below, the corresponding entry in the list is overwritten
		list[i] = &DisclosedAttribute{
			Status: AttributeProofStatusMissing,
		}
	}

	// Temp slice for attributes that have not yet been matched to one of the disjunctions of the request
	// When we are done matching disclosed attributes against the request, filling the first few slots of list,
	// we append these to list just before returning
	extraAttrs := map[AttributeTypeIdentifier]*DisclosedAttribute{}

	for _, proof := range pl {
		proofd, ok := proof.(*gabi.ProofD)
		if !ok {
			continue
		}
		metadata := MetadataFromInt(proofd.ADisclosed[1], configuration) // index 1 is metadata attribute

		for attrIndex, attrInt := range proofd.ADisclosed {
			if attrIndex == 0 {
				continue // Should never be disclosed, but skip it to be sure
			}

			attr, attrval, err := parseAttribute(attrIndex, metadata, attrInt)
			if err != nil {
				return false, nil, err
			}

			if attrIndex > 1 { // Never add metadata (i.e. no-attribute disclosure) as extra
				extraAttrs[attr.Identifier] = attr
			}
			if len(disjunctions) == 0 {
				continue
			}

			// See if the current attribute satisfies one of the disjunctions, if so, delete it from extraAttrs
			for i, disjunction := range disjunctions {
				if disjunction.attemptSatisfy(attr.Identifier, attrval) {
					if disjunction.satisfied() {
						attr.Status = AttributeProofStatusPresent
					} else {
						attr.Status = AttributeProofStatusInvalidValue
					}
					list[i] = attr
					delete(extraAttrs, attr.Identifier)
				}
			}
		}
	}

	// Any attributes still in here do not satisfy any of the specified disjunctions; append them now
	for _, attr := range extraAttrs {
		attr.Status = AttributeProofStatusExtra
		list = append(list, attr)
	}

	return len(disjunctions) == 0 || disjunctions.satisfied(), list, nil
}

func (d *Disclosure) VerifyAgainstDisjunctions(
	configuration *Configuration,
	required AttributeDisjunctionList,
	context, nonce *big.Int,
	publickeys []*gabi.PublicKey,
	issig bool,
) ([]*DisclosedAttribute, ProofStatus, error) {
	// Cryptographically verify the IRMA disclosure proofs in the signature
	valid, err := ProofList(d.Proofs).VerifyProofs(configuration, context, nonce, publickeys, issig)
	if !valid || err != nil {
		return nil, ProofStatusInvalid, err
	}

	// Next extract the contained attributes from the proofs, and match them to the signature request if present
	allmatched, list, err := d.DisclosedAttributes(configuration, required)
	if err != nil {
		return nil, ProofStatusInvalid, err
	}

	// Return MISSING_ATTRIBUTES as proofstatus if one of the disjunctions in the request (if present) is not satisfied
	if !allmatched {
		return list, ProofStatusMissingAttributes, nil
	}

	return list, ProofStatusValid, nil
}

func (d *Disclosure) Verify(configuration *Configuration, request *DisclosureRequest) ([]*DisclosedAttribute, ProofStatus, error) {
	list, status, err := d.VerifyAgainstDisjunctions(configuration, request.Content, request.Context, request.Nonce, nil, false)
	if err != nil {
		return list, status, err
	}

	now := time.Now()
	if expired := ProofList(d.Proofs).Expired(configuration, &now); expired {
		return list, ProofStatusExpired, nil
	}

	return list, status, nil
}

// Verify the attribute-based signature, optionally against a corresponding signature request. If the request is present
// (i.e. not nil), then the first attributes in the returned result match with the disjunction list in the request
// (that is, the i'th attribute in the result should satisfy the i'th disjunction in the request). If the request is not
// fully satisfied in this fasion, the Status of the result is ProofStatusMissingAttributes. Any remaining attributes
// (i.e. not asked for by the request) are also included in the result, after the attributes that match disjunctions
// in the request.
//
// The signature request is optional; if it is nil then the attribute-based signature is still verified, and all
// containing attributes returned in the result.
func (sm *SignedMessage) Verify(configuration *Configuration, request *SignatureRequest) ([]*DisclosedAttribute, ProofStatus, error) {
	var message string

	// First check if this signature matches the request
	if request != nil {
		request.Timestamp = sm.Timestamp
		if !sm.MatchesNonceAndContext(request) {
			return nil, ProofStatusUnmatchedRequest, nil
		}
		// If there is a request, then the signed message must be that of the request
		message = request.Message
	} else {
		// If not, we just verify that the signed message is a valid signature over its contained message
		message = sm.Message
	}

	// Verify the timestamp
	if sm.Timestamp != nil {
		if err := sm.VerifyTimestamp(message, configuration); err != nil {
			return nil, ProofStatusInvalidTimestamp, nil
		}
	}

	// Now, cryptographically verify the IRMA disclosure proofs in the signature
	var required AttributeDisjunctionList
	if request != nil {
		required = request.Content
	}
	result, status, err := sm.Disclosure().VerifyAgainstDisjunctions(configuration, required, sm.Context, sm.GetNonce(), nil, true)
	if status != ProofStatusValid || err != nil {
		return result, status, err
	}

	// Check if a credential is expired
	var t time.Time
	if sm.Timestamp != nil {
		t = time.Unix(sm.Timestamp.Time, 0)
	}
	if expired := ProofList(sm.Signature).Expired(configuration, &t); expired {
		// The ABS contains attributes that were expired at the time of creation of the ABS.
		return result, ProofStatusExpired, nil
	}

	// All disjunctions satisfied and nothing expired, proof is valid!
	return result, ProofStatusValid, nil
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
			Value:      translateAttribute(&value),
			Status:     AttributeProofStatusPresent,
		}
	}

	return disclosedAttributes, nil
}
