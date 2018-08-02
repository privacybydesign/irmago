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
	ProofStatusValid             = ProofStatus("VALID")
	ProofStatusInvalidCrypto     = ProofStatus("INVALID_CRYPTO")
	ProofStatusInvalidTimestamp  = ProofStatus("INVALID_TIMESTAMP")
	ProofStatusUnmatchedRequest  = ProofStatus("UNMATCHED_REQUEST")
	ProofStatusMissingAttributes = ProofStatus("MISSING_ATTRIBUTES")

	// The contained attributes are currently expired, but it is not certain if they already were expired
	// during creation of the ABS.
	ProofStatusExpired = ProofStatus("EXPIRED")

	AttributeProofStatusPresent      = AttributeProofStatus("PRESENT")       // Attribute is disclosed and matches the value
	AttributeProofStatusExtra        = AttributeProofStatus("EXTRA")         // Attribute is disclosed, but wasn't requested in request
	AttributeProofStatusMissing      = AttributeProofStatus("MISSING")       // Attribute is NOT disclosed, but should be according to request
	AttributeProofStatusInvalidValue = AttributeProofStatus("INVALID_VALUE") // Attribute is disclosed, but has invalid value according to request
)

// DisclosedCredential contains raw disclosed credentials, without any extra parsing information
type DisclosedCredential struct {
	metadataAttribute *MetadataAttribute
	rawAttributes     map[AttributeTypeIdentifier]*string
	Attributes        map[AttributeTypeIdentifier]TranslatedString `json:"attributes"`
}

type DisclosedCredentialList []*DisclosedCredential

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

// Returns true if one of the disclosed credentials is expired at the specified time
func (disclosed DisclosedCredentialList) IsExpired(t time.Time) bool {
	for _, cred := range disclosed {
		if cred.IsExpired(t) {
			return true
		}
	}
	return false
}

func ExtractDisclosedCredentials(conf *Configuration, proofList gabi.ProofList) (DisclosedCredentialList, error) {
	var credentials = make(DisclosedCredentialList, 0, len(proofList))

	for _, v := range proofList {
		switch v.(type) {
		case *gabi.ProofD:
			proof := v.(*gabi.ProofD)
			cred := newDisclosedCredential(proof.ADisclosed, conf)
			credentials = append(credentials, cred)
		case *gabi.ProofU: // nop
		default:
			return nil, errors.New("Cannot extract credentials from proof, not a disclosure proofD")
		}
	}

	return credentials, nil
}

func (cred *DisclosedCredential) IsExpired(t time.Time) bool {
	return cred.metadataAttribute.Expiry().Before(t)
}

func newDisclosedCredential(aDisclosed map[int]*big.Int, configuration *Configuration) *DisclosedCredential {
	rawAttributes := make(map[AttributeTypeIdentifier]*string)
	attributes := make(map[AttributeTypeIdentifier]TranslatedString)

	metadata := MetadataFromInt(aDisclosed[1], configuration) // index 1 is metadata attribute
	cred := metadata.CredentialType()

	for k, v := range aDisclosed {
		if k < 2 {
			continue
		}

		id := cred.Attributes[k-2].GetAttributeTypeIdentifier()
		attributeValue := decodeAttribute(v, metadata.Version())
		rawAttributes[id] = attributeValue
		attributes[id] = translateAttribute(attributeValue)
	}

	return &DisclosedCredential{
		metadataAttribute: metadata,
		rawAttributes:     rawAttributes,
		Attributes:        attributes,
	}
}

// extractPublicKeys returns the public keys of each proof in the proofList, in the same order,
// for later use in verification of the proofList. If one of the proofs is not a ProofD
// an error is returned.
func extractPublicKeys(configuration *Configuration, proofList gabi.ProofList) ([]*gabi.PublicKey, error) {
	var publicKeys = make([]*gabi.PublicKey, 0, len(proofList))

	for _, v := range proofList {
		switch v.(type) {
		case *gabi.ProofD:
			proof := v.(*gabi.ProofD)
			metadata := MetadataFromInt(proof.ADisclosed[1], configuration) // index 1 is metadata attribute
			publicKey, err := metadata.PublicKey()
			if err != nil {
				return nil, err
			}
			publicKeys = append(publicKeys, publicKey)
		default:
			return nil, errors.New("Cannot extract public key, not a disclosure proofD!")
		}
	}
	return publicKeys, nil
}

// verify an IRMA proofList cryptographically.
func verify(configuration *Configuration, proofList gabi.ProofList, context *big.Int, nonce *big.Int, isSig bool) bool {
	// Extract public keys
	pks, err := extractPublicKeys(configuration, proofList)
	if err != nil {
		return false
	}

	return proofList.Verify(pks, context, nonce, true, isSig)
}

func (disclosed DisclosedCredentialList) attributeList(configuration *Configuration, sigRequest *SignatureRequest) (bool, []*DisclosedAttribute) {
	var list []*DisclosedAttribute
	if sigRequest != nil {
		list = make([]*DisclosedAttribute, len(sigRequest.Content))
		for i := range list {
			list[i] = &DisclosedAttribute{
				Status: AttributeProofStatusMissing,
			}
		}
	}

	// attributes that have not yet been matched to one of the disjunctions of the request
	extraAttrs := map[AttributeTypeIdentifier]*DisclosedAttribute{}

	for _, cred := range disclosed {
		for attrid, value := range cred.Attributes {
			attr := &DisclosedAttribute{
				Value:      value,
				Identifier: attrid,
				Status:     AttributeProofStatusExtra,
			}
			extraAttrs[attrid] = attr
			if sigRequest == nil {
				continue
			}
			for i, disjunction := range sigRequest.Content {
				if disjunction.attemptSatisfy(attrid, cred.rawAttributes[attrid]) {
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

	for _, attr := range extraAttrs {
		list = append(list, attr)
	}

	return sigRequest == nil || sigRequest.Content.satisfied(), list
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
func (sm *SignedMessage) Verify(configuration *Configuration, request *SignatureRequest) (result *VerificationResult) {
	var message string
	result = &VerificationResult{}

	// First check if this signature matches the request
	if request != nil {
		request.Timestamp = sm.Timestamp
		if !sm.MatchesNonceAndContext(request) {
			result.Status = ProofStatusUnmatchedRequest
			return
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
			result.Status = ProofStatusInvalidTimestamp
			return
		}
	}

	// Now, cryptographically verify the IRMA disclosure proofs in the signature
	if !verify(configuration, sm.Signature, sm.Context, sm.GetNonce(), true) {
		result.Status = ProofStatusInvalidCrypto
		return
	}

	// Next extract the contained attributes from the signature, and match them to the signature request if present
	var allmatched bool
	disclosed, err := ExtractDisclosedCredentials(configuration, sm.Signature)
	if err != nil {
		result.Status = ProofStatusInvalidCrypto
		return
	}
	allmatched, result.Attributes = disclosed.attributeList(configuration, request)

	// Return MISSING_ATTRIBUTES as proofstatus if one of the disjunctions in the request (if present) is not satisfied
	// This status takes priority over 'EXPIRED'
	if !allmatched {
		result.Status = ProofStatusMissingAttributes
		return
	}

	// Check if a credential is expired
	if sm.Timestamp == nil {
		if disclosed.IsExpired(time.Now()) {
			// At least one of the contained attributes has currently expired. We don't know the
			// creation time of the ABS so we can't ascertain that the attributes were still valid then.
			// Otherwise the signature is valid.
			result.Status = ProofStatusExpired
			return
		}
	} else {
		if disclosed.IsExpired(time.Unix(sm.Timestamp.Time, 0)) {
			// The ABS contains attributes that were expired at the time of creation of the ABS.
			// This must not happen and in this case the signature is invalid
			result.Status = ProofStatusInvalidCrypto
			return
		}
	}

	// All disjunctions satisfied and nothing expired, proof is valid!
	result.Status = ProofStatusValid
	return
}
