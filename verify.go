package irma

import (
	"math/big"
	"time"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
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

	// The contained attributes are currently expired, but it is not certain if they already were expired
	// during creation of the attribute-based signature.
	ProofStatusExpired = ProofStatus("EXPIRED")

	AttributeProofStatusPresent      = AttributeProofStatus("PRESENT")       // Attribute is disclosed and matches the value
	AttributeProofStatusExtra        = AttributeProofStatus("EXTRA")         // Attribute is disclosed, but wasn't requested in request
	AttributeProofStatusMissing      = AttributeProofStatus("MISSING")       // Attribute is NOT disclosed, but should be according to request
	AttributeProofStatusInvalidValue = AttributeProofStatus("INVALID_VALUE") // Attribute is disclosed, but has invalid value according to request
)

// VerificationResult is a result of verification of a SignedMessage or disclosure proof, containing all the disclosed attributes
type VerificationResult struct {
	Attributes []*DisclosedAttribute
	Status     ProofStatus
}

// DisclosedAttribute represents a disclosed attribute.
type DisclosedAttribute struct {
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

	// If the secret key comes from a credential whose scheme manager has a keyshare server,
	// then the secretkey = userpart + keysharepart.
	// So, we can only expect two secret key responses to be equal if their credentials
	// are both associated to either no keyshare server, or the same keyshare server.
	// (We have to check this here instead of in gabi, because gabi is unaware of schemes
	// and whether or not they are distributed.)
	secretkeyResponses := make(map[SchemeManagerIdentifier]*big.Int)
	nonKssSchemeID := NewSchemeManagerIdentifier(".") // We use this id for all schemes that don't use a kss
	for i, proof := range pl {
		schemeID := NewIssuerIdentifier(publickeys[i].Issuer).SchemeManagerIdentifier()
		if !configuration.SchemeManagers[schemeID].Distributed() {
			schemeID = nonKssSchemeID
		}
		if response, contains := secretkeyResponses[schemeID]; !contains {
			secretkeyResponses[schemeID] = proof.SecretKeyResponse()
		} else {
			if response.Cmp(proof.SecretKeyResponse()) != 0 {
				return false, nil
			}
		}
	}

	return gabi.ProofList(pl).Verify(publickeys, context, nonce, isSig), nil
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
		credtype := metadata.CredentialType()
		if credtype == nil {
			return false, nil, errors.New("ProofList contained a disclosure proof of an unkown credential type")
		}

		for k, v := range proofd.ADisclosed {
			if k < 2 {
				continue // skip metadata attribute
			}

			attrid := credtype.Attributes[k-2].GetAttributeTypeIdentifier()
			attrval := decodeAttribute(v, metadata.Version())
			attr := &DisclosedAttribute{
				Value:      translateAttribute(attrval),
				Identifier: attrid,
				Status:     AttributeProofStatusExtra,
			}
			extraAttrs[attrid] = attr
			if len(disjunctions) == 0 {
				continue
			}

			// See if the current attribute satisfies one of the disjunctions, if so, delete it from extraAttrs
			for i, disjunction := range disjunctions {
				if disjunction.attemptSatisfy(attrid, attrval) {
					if disjunction.satisfied() {
						attr.Status = AttributeProofStatusPresent
					} else {
						attr.Status = AttributeProofStatusInvalidValue
					}
					list[i] = attr
					delete(extraAttrs, attrid)
				}
			}
		}
	}

	// Any attributes still in here do not satisfy any of the specified disjunctions; append them now
	for _, attr := range extraAttrs {
		list = append(list, attr)
	}

	return len(disjunctions) == 0 || disjunctions.satisfied(), list, nil
}

func (pl ProofList) VerifyAgainstDisjunctions(
	configuration *Configuration,
	required AttributeDisjunctionList,
	context, nonce *big.Int,
	publickeys []*gabi.PublicKey,
	issig bool,
) ([]*DisclosedAttribute, ProofStatus, error) {
	// Cryptographically verify the IRMA disclosure proofs in the signature
	valid, err := pl.VerifyProofs(configuration, context, nonce, publickeys, issig)
	if !valid || err != nil {
		return nil, ProofStatusInvalid, err
	}

	// Next extract the contained attributes from the proofs, and match them to the signature request if present
	allmatched, list, err := pl.DisclosedAttributes(configuration, required)
	if err != nil {
		return nil, ProofStatusInvalid, err
	}

	// Return MISSING_ATTRIBUTES as proofstatus if one of the disjunctions in the request (if present) is not satisfied
	if !allmatched {
		return list, ProofStatusMissingAttributes, nil
	}

	return list, ProofStatusValid, nil
}

func (pl ProofList) Verify(configuration *Configuration, request *DisclosureRequest) ([]*DisclosedAttribute, ProofStatus, error) {
	list, status, err := pl.VerifyAgainstDisjunctions(configuration, request.Content, request.Context, request.Nonce, nil, false)
	if err != nil {
		return list, status, err
	}

	now := time.Now()
	if expired := pl.Expired(configuration, &now); expired {
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
	pl := ProofList(sm.Signature)
	var required AttributeDisjunctionList
	if request != nil {
		required = request.Content
	}
	result, status, err := pl.VerifyAgainstDisjunctions(configuration, required, sm.Context, sm.GetNonce(), nil, true)
	if status != ProofStatusValid || err != nil {
		return result, status, err
	}

	// Check if a credential is expired
	var t time.Time
	if sm.Timestamp != nil {
		t = time.Unix(sm.Timestamp.Time, 0)
	}
	if expired := pl.Expired(configuration, &t); expired {
		if sm.Timestamp == nil {
			// At least one of the contained attributes has currently expired. We don't know the
			// creation time of the ABS so we can't ascertain that the attributes were still valid then.
			// Otherwise the signature is valid.
			status = ProofStatusExpired
		} else {
			// The ABS contains attributes that were expired at the time of creation of the ABS.
			// This must not happen and in this case the signature is invalid
			status = ProofStatusInvalid
		}
		return result, status, nil
	}

	// All disjunctions satisfied and nothing expired, proof is valid!
	return result, ProofStatusValid, nil
}
