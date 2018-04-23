package irma

import (
	"fmt"
	"math/big"
	"time"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

// ProofStatus is the status of the complete proof
type ProofStatus string

const (
	VALID              = ProofStatus("VALID")
	EXPIRED            = ProofStatus("EXPIRED")
	INVALID_CRYPTO     = ProofStatus("INVALID_CRYPTO")
	UNMATCHED_REQUEST  = ProofStatus("UNMATCHED_REQUEST")
	MISSING_ATTRIBUTES = ProofStatus("MISSING_ATTRIBUTES")
)

// ProofResult is a result of a complete proof, containing all the disclosed attributes and corresponding request
type ProofResult struct {
	disjunctions []*DisclosedAttributeDisjunction
	ProofStatus  ProofStatus
}

type SignatureProofResult struct {
	*ProofResult
	message string
}

// DisclosedCredential contains raw disclosed credentials, without any extra parsing information
type DisclosedCredential struct {
	metadataAttribute *MetadataAttribute
	Attributes        map[AttributeTypeIdentifier]*string `json:"attributes"`
}

type DisclosedCredentialList []*DisclosedCredential

// Helper function to check if an attribute is satisfied against a list of disclosed attributes
// This is the case if:
// attribute is contained in disclosed AND if a value is present: equal to that value
// al can be nil if you don't want to include attribute status for proof
func (disclosed DisclosedCredentialList) isAttributeSatisfied(attributeId AttributeTypeIdentifier, requestedValue *string) (bool, *AttributeResult) {
	ar := AttributeResult{
		AttributeId: attributeId,
	}

	for _, cred := range disclosed {
		disclosedAttributeValue := cred.Attributes[attributeId]

		// Continue to next credential if requested attribute isn't disclosed in this credential
		if disclosedAttributeValue == nil {
			continue
		}

		// If this is the disclosed attribute, check if value matches
		// Attribute is satisfied if:
		// - Attribute is disclosed (i.e. not nil)
		// - Value is empty OR value equal to disclosedValue
		ar.AttributeValue = *disclosedAttributeValue

		if requestedValue == nil || *disclosedAttributeValue == *requestedValue {
			ar.AttributeProofStatus = PRESENT
			return true, &ar
		} else {
			// If attribute is disclosed and present, but not equal to required value, mark it as invalid_value
			// We won't return true and continue searching in other disclosed attributes
			ar.AttributeProofStatus = INVALID_VALUE
		}
	}

	// If there is never a value assigned, then this attribute isn't disclosed, and thus missing
	if ar.AttributeValue == "" {
		ar.AttributeProofStatus = MISSING
	}
	return false, &ar
}

// Create a signature proof result and check disclosed credentials against a signature request
func (disclosed DisclosedCredentialList) createAndCheckSignatureProofResult(configuration *Configuration, sigRequest *SignatureRequest) *SignatureProofResult {
	signatureProofResult := SignatureProofResult{
		ProofResult: &ProofResult{},
		message:     sigRequest.Message,
	}
	for _, content := range sigRequest.Content {
		isSatisfied, disjunction := content.SatisfyDisclosed(disclosed, configuration)
		signatureProofResult.disjunctions = append(signatureProofResult.disjunctions, disjunction)

		// If satisfied, continue to next one
		if isSatisfied {
			continue
		}

		// Else, set proof status to missing_attributes, but check other as well to add other disjunctions to result
		// (so user also knows attribute status of other disjunctions)
		signatureProofResult.ProofStatus = MISSING_ATTRIBUTES
	}

	signatureProofResult.disjunctions = addExtraAttributes(disclosed, signatureProofResult.ProofResult)
	return &signatureProofResult
}

// Returns true if one of the disclosed credentials is expired
func (disclosed DisclosedCredentialList) IsExpired() bool {
	for _, cred := range disclosed {
		if cred.IsExpired() {
			return true
		}
	}
	return false
}

func (proofResult *ProofResult) ToAttributeResultList() AttributeResultList {
	var resultList AttributeResultList

	for _, v := range proofResult.disjunctions {
		result := AttributeResult{
			AttributeValue:       v.DisclosedValue,
			AttributeId:          v.DisclosedId,
			AttributeProofStatus: v.ProofStatus,
		}

		resultList = append(resultList, &result)
	}
	return resultList
}

// Returns true if this attrId is present in one of the disjunctions
func (proofResult *ProofResult) ContainsAttribute(attrId AttributeTypeIdentifier) bool {
	for _, disj := range proofResult.disjunctions {
		for _, attr := range disj.Attributes {
			if attr == attrId {
				return true
			}
		}
	}

	return false
}

// Get string value of disclosed attribute, or nil if request attribute isn't disclosed in this credential
//func (cred *DisclosedCredential) GetAttributeValue(id AttributeTypeIdentifier) string {
//	attr := cred.Attributes[id]
//	if attr != nil {
//		return string(attr.Bytes())
//	}
//	return ""
//}

func (cred *DisclosedCredential) IsExpired() bool {
	return cred.metadataAttribute.Expiry().Before(time.Now())
}

func NewDisclosedCredentialFromADisclosed(aDisclosed map[int]*big.Int, configuration *Configuration) *DisclosedCredential {
	attributes := make(map[AttributeTypeIdentifier]*string)

	metadata := MetadataFromInt(aDisclosed[1], configuration) // index 1 is metadata attribute
	cred := metadata.CredentialType()

	for k, v := range aDisclosed {
		if k < 2 {
			continue
		}

		description := cred.Attributes[k-2]
		attributeValue := string(v.Bytes())
		attributes[description.GetAttributeTypeIdentifier(cred.Identifier())] = &attributeValue
	}

	return &DisclosedCredential{
		metadataAttribute: metadata,
		Attributes:        attributes,
	}
}

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

func extractDisclosedCredentials(conf *Configuration, proofList gabi.ProofList) (DisclosedCredentialList, error) {
	var credentials = make(DisclosedCredentialList, 0, len(proofList))

	for _, v := range proofList {
		switch v.(type) {
		case *gabi.ProofD:
			proof := v.(*gabi.ProofD)
			cred := NewDisclosedCredentialFromADisclosed(proof.ADisclosed, conf)
			credentials = append(credentials, cred)
		default:
			return nil, errors.New("Cannot extract credentials from proof, not a disclosure proofD!")
		}
	}

	return credentials, nil
}

// Add extra disclosed attributes to an existing and checked ProofResult in 'dummy disjunctions'
func addExtraAttributes(disclosed DisclosedCredentialList, proofResult *ProofResult) []*DisclosedAttributeDisjunction {
	returnDisjunctions := make([]*DisclosedAttributeDisjunction, len(proofResult.disjunctions))
	copy(returnDisjunctions, proofResult.disjunctions)

	for _, cred := range disclosed {
		for attrId := range cred.Attributes {
			if proofResult.ContainsAttribute(attrId) {
				continue
			}

			dummyDisj := DisclosedAttributeDisjunction{
				DisclosedValue: *cred.Attributes[attrId],
				DisclosedId:    attrId,
				ProofStatus:    EXTRA,
			}
			returnDisjunctions = append(returnDisjunctions, &dummyDisj)
		}
	}

	return returnDisjunctions
}

// Check an gabi prooflist against a signature proofrequest
func checkProofWithRequest(configuration *Configuration, proofList gabi.ProofList, sigRequest *SignatureRequest) *SignatureProofResult {
	disclosed, err := extractDisclosedCredentials(configuration, proofList)

	if err != nil {
		fmt.Println(err)
		return &SignatureProofResult{
			ProofResult: &ProofResult{
				ProofStatus: INVALID_CRYPTO,
			},
		}
	}

	signatureProofResult := disclosed.createAndCheckSignatureProofResult(configuration, sigRequest)

	// Return MISSING_ATTRIBUTES as proofstatus if one attribute is missing
	// This status takes priority over 'EXPIRED'
	if signatureProofResult.ProofStatus == MISSING_ATTRIBUTES {
		return signatureProofResult
	}

	// If all disjunctions are satisfied, check if a credential is expired
	if disclosed.IsExpired() {
		signatureProofResult.ProofStatus = EXPIRED
		return signatureProofResult
	}

	// All disjunctions satisfied and nothing expired, proof is valid!
	signatureProofResult.ProofStatus = VALID
	return signatureProofResult
}

// Verify an IRMA proof cryptographically
func verify(configuration *Configuration, proofList gabi.ProofList, context *big.Int, nonce *big.Int, isSig bool) bool {
	// Extract public keys
	pks, err := extractPublicKeys(configuration, proofList)
	if err != nil {
		return false
	}

	return proofList.Verify(pks, context, nonce, true, isSig)
}

// Verify a signature proof and check if the attributes match the attributes in the original request
func VerifySig(configuration *Configuration, irmaSignature *IrmaSignedMessage, sigRequest *SignatureRequest) *SignatureProofResult {
	// First, check if nonce and context of the signature match those of the signature request
	if !irmaSignature.MatchesNonceAndContext(sigRequest) {
		return &SignatureProofResult{
			ProofResult: &ProofResult{
				ProofStatus: UNMATCHED_REQUEST,
			},
		}
	}

	// Now, cryptographically verify the signature
	if !verify(configuration, *irmaSignature.Signature, sigRequest.GetContext(), sigRequest.GetNonce(), true) {
		return &SignatureProofResult{
			ProofResult: &ProofResult{
				ProofStatus: INVALID_CRYPTO,
			},
		}
	}

	// Finally, check whether attribute values in proof satisfy the original signature request
	return checkProofWithRequest(configuration, *irmaSignature.Signature, sigRequest)
}

// Verify a signature cryptographically, but do not check/compare with a signature request
func VerifySigWithoutRequest(configuration *Configuration, irmaSignature *IrmaSignedMessage) (ProofStatus, DisclosedCredentialList) {
	// First, cryptographically verify the signature
	if !verify(configuration, *irmaSignature.Signature, irmaSignature.Context, irmaSignature.GetNonce(), true) {
		return INVALID_CRYPTO, nil
	}

	// Extract attributes and return result
	disclosed, err := extractDisclosedCredentials(configuration, *irmaSignature.Signature)

	if err != nil {
		fmt.Println(err)
		return INVALID_CRYPTO, nil
	}

	if disclosed.IsExpired() {
		return EXPIRED, disclosed
	}

	return VALID, disclosed
}
