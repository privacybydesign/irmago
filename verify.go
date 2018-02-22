package irma

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"math/big"
	"time"
)

// ProofStatus is the status of the complete proof
type ProofStatus string

const (
	VALID              = ProofStatus("VALID")
	EXPIRED            = ProofStatus("EXPIRED")
	INVALID_CRYPTO     = ProofStatus("INVALID_CRYPTO")
	INVALID_SYNTAX     = ProofStatus("INVALID_SYNTAX")
	MISSING_ATTRIBUTES = ProofStatus("MISSING_ATTRIBUTES")
)

// ProofResult is a result of a complete proof, containing all the disclosed attributes and corresponding request
type ProofResult struct {
	disjunctions []*DisclosedAttributeDisjunction
	ProofStatus  ProofStatus
}

type SignatureProofResult struct {
	ProofResult
	message string
}

// DisclosedCredential contains raw disclosed credentials, without any extra parsing information
type DisclosedCredential struct {
	metadataAttribute *MetadataAttribute
	Attributes        map[AttributeTypeIdentifier]*big.Int
}

func (proofResult *ProofResult) ToAttributeResultList() *AttributeResultList {
	var resultList AttributeResultList

	for _, v := range proofResult.disjunctions {
		result := AttributeResult{
			AttributeValue:       v.DisclosedValue,
			AttributeId:          v.DisclosedId,
			AttributeProofStatus: v.ProofStatus,
		}

		resultList.Append(&result)
	}
	return &resultList
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
func (cred *DisclosedCredential) GetAttributeValue(id AttributeTypeIdentifier) string {
	attr := cred.Attributes[id]
	if attr != nil {
		return string(attr.Bytes())
	}

	return ""
}

func (cred *DisclosedCredential) IsExpired() bool {
	return cred.metadataAttribute.Expiry().Before(time.Now())
}

func NewDisclosedCredentialFromADisclosed(aDisclosed map[int]*big.Int, configuration *Configuration) *DisclosedCredential {
	attributes := make(map[AttributeTypeIdentifier]*big.Int)

	metadata := MetadataFromInt(aDisclosed[1], configuration) // index 1 is metadata attribute
	cred := metadata.CredentialType()

	for k, v := range aDisclosed {
		if k < 2 {
			continue
		}

		description := cred.Attributes[k-2]
		attributes[description.GetAttributeTypeIdentifier(cred.Identifier())] = v
	}

	return &DisclosedCredential{
		metadataAttribute: metadata,
		Attributes:        attributes,
	}
}

func extractPublicKeys(configuration *Configuration, proofList *gabi.ProofList) ([]*gabi.PublicKey, error) {
	var publicKeys []*gabi.PublicKey

	for _, v := range *proofList {
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

func extractDisclosedCredentials(conf *Configuration, proofList *gabi.ProofList) ([]*DisclosedCredential, error) {
	var credentials []*DisclosedCredential

	for _, v := range *proofList {
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
func addExtraAttributes(credentials []*DisclosedCredential, proofResult *ProofResult) []*DisclosedAttributeDisjunction {
	returnDisjunctions := append(proofResult.disjunctions)

	for _, cred := range credentials {
		for attrId := range cred.Attributes {
			if proofResult.ContainsAttribute(attrId) {
				continue
			}

			dummyDisj := DisclosedAttributeDisjunction{
				DisclosedValue: cred.GetAttributeValue(attrId),
				DisclosedId:    attrId,
				ProofStatus:    EXTRA,
			}
			returnDisjunctions = append(returnDisjunctions, &dummyDisj)
		}
	}

	return returnDisjunctions
}

// Create a signature proof result and check disclosed credentials against a signature request
func createAndCheckSignatureProofResult(configuration *Configuration, credentials []*DisclosedCredential, sigRequest *SignatureRequest) *SignatureProofResult {
	signatureProofResult := SignatureProofResult{
		message: sigRequest.Message,
	}
	for _, content := range sigRequest.Content {
		isSatisfied, disjunction := content.SatisfyDisclosed(credentials, configuration)
		signatureProofResult.disjunctions = append(signatureProofResult.disjunctions, disjunction)

		// If satisfied, continue to next one
		if isSatisfied {
			continue
		}

		// Else, set proof status to missing_attributes, but check other as well to add other disjunctions to result
		// (so user also knows attribute status of other disjunctions)
		signatureProofResult.ProofStatus = MISSING_ATTRIBUTES
	}

	signatureProofResult.disjunctions = addExtraAttributes(credentials, &signatureProofResult.ProofResult)
	return &signatureProofResult
}

// Check an gabi prooflist against a signature proofrequest
func checkProofWithRequest(configuration *Configuration, proofList *gabi.ProofList, sigRequest *SignatureRequest) *SignatureProofResult {
	credentials, err := extractDisclosedCredentials(configuration, proofList)

	if err != nil {
		fmt.Println(err)
		return &SignatureProofResult{
			ProofResult: ProofResult{
				ProofStatus: INVALID_CRYPTO,
			},
		}
	}

	signatureProofResult := createAndCheckSignatureProofResult(configuration, credentials, sigRequest)

	// Return MISSING_ATTRIBUTES as proofstatus if one attribute is missing
	// This status takes priority over 'EXPIRED'
	if signatureProofResult.ProofStatus == MISSING_ATTRIBUTES {
		return signatureProofResult
	}

	// If all disjunctions are satisfied, check if a credential is expired
	for _, cred := range credentials {
		if cred.IsExpired() {
			signatureProofResult.ProofStatus = EXPIRED
			return signatureProofResult
		}
	}

	// All disjunctions satisfied and nothing expired, proof is valid!
	signatureProofResult.ProofStatus = VALID
	return signatureProofResult
}

// Verify an IRMA proof cryptographically
func verify(configuration *Configuration, proofList *gabi.ProofList, context *big.Int, nonce *big.Int, isSig bool) bool {
	// Extract public keys
	pks, err := extractPublicKeys(configuration, proofList)
	if err != nil {
		return false
	}

	return proofList.Verify(pks, context, nonce, true, isSig)
}

// Verify a signature proof and check if the attributes match the attributes in the original request
func VerifySig(configuration *Configuration, proofString string, sigRequest *SignatureRequest) *SignatureProofResult {

	// First, unmarshal proof and check if all the attributes in the proofstring match the signature request
	var proofList gabi.ProofList
	proofBytes := []byte(proofString)

	err := proofList.UnmarshalJSON(proofBytes)
	if err != nil {
		return &SignatureProofResult{
			ProofResult: ProofResult{
				ProofStatus: INVALID_SYNTAX,
			},
		}
	}

	// Now, cryptographically verify the signature
	if !verify(configuration, &proofList, sigRequest.GetContext(), sigRequest.GetNonce(), true) {
		return &SignatureProofResult{
			ProofResult: ProofResult{
				ProofStatus: INVALID_CRYPTO,
			},
		}
	}

	// Finally, check whether attribute values in proof satisfy the original signature request
	return checkProofWithRequest(configuration, &proofList, sigRequest)
}
