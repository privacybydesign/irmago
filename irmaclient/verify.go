package irmaclient

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"math/big"
)

// TODO: move to irma package?
type ProofResult struct {
	proofStatus ProofStatus // The overall proofstatus, should be VALID in order to accept the proof
	attributes  []irma.AttributeResult
}

type ProofStatus string

const (
	VALID              = ProofStatus("VALID")
	EXPIRED            = ProofStatus("EXPIRED")
	INVALID_CRYPTO     = ProofStatus("INVALID_CRYPTO")
	INVALID_JSON       = ProofStatus("INVALID_JSON")
	MISSING_ATTRIBUTES = ProofStatus("MISSING_ATTRIBUTES")
)

func extractPublicKeys(configuration *irma.Configuration, proofList *gabi.ProofList) ([]*gabi.PublicKey, error) {
	var publicKeys []*gabi.PublicKey

	for _, v := range *proofList {
		switch v.(type) {
		case *gabi.ProofD:
			proof := v.(*gabi.ProofD)
			metadata := irma.MetadataFromInt(proof.ADisclosed[1], configuration) // index 1 is metadata attribute
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

func extractDisclosedCredentials(configuration *irma.Configuration, proofList *gabi.ProofList) ([]*irma.CredentialInfo, error) {
	var credentials []*irma.CredentialInfo

	for _, v := range *proofList {
		switch v.(type) {
		case *gabi.ProofD:
			proof := v.(*gabi.ProofD)
			irmaCredentialInfo, err := irma.NewCredentialInfoFromADisclosed(proof.AResponses, proof.ADisclosed, configuration)
			if err != nil {
				return nil, err
			}
			credentials = append(credentials, irmaCredentialInfo)
		default:
			return nil, errors.New("Cannot extract attributes from proof, not a disclosure proofD!")
		}
	}
	return credentials, nil
}

func checkProofWithRequest(configuration *irma.Configuration, proofList *gabi.ProofList, sigRequest *irma.SignatureRequest) (ProofStatus, *irma.AttributeResultList) {
	credentials, err := extractDisclosedCredentials(configuration, proofList)

	if err != nil {
		fmt.Println(err)
		return INVALID_CRYPTO, nil
	}

	al := irma.AttributeResultListFromDisclosed(credentials, configuration)
	for _, content := range sigRequest.Content {
		if !content.SatisfyDisclosed(credentials, configuration, al) {
			return MISSING_ATTRIBUTES, al
		}
	}

	// Check if a credential is expired
	for _, cred := range credentials {
		if cred.IsExpired() {
			return EXPIRED, al
		}
	}

	return VALID, al
}

// Verify an IRMA proof cryptographically
func verify(configuration *irma.Configuration, proofList *gabi.ProofList, context *big.Int, nonce *big.Int, isSig bool) bool {
	// Extract public keys
	pks, err := extractPublicKeys(configuration, proofList)
	if err != nil {
		fmt.Printf("Error extracting public key: %v\n", err)
		return false
	}

	return proofList.Verify(pks, context, nonce, true, isSig)
}

// Verify a signature proof and check if the attributes match the attributes in the original request
func VerifySig(configuration *irma.Configuration, proofString string, sigRequest *irma.SignatureRequest) (ProofStatus, *irma.AttributeResultList) {

	// First, unmarshal proof and check if all the attributes in the proofstring match the signature request
	var proofList gabi.ProofList
	proofBytes := []byte(proofString)

	err := proofList.UnmarshalJSON(proofBytes)
	if err != nil {
		fmt.Printf("Error unmarshalling JSON: %v\n", err)
		return INVALID_JSON, nil
	}

	// Now, cryptographically verify the signature
	if !verify(configuration, &proofList, sigRequest.GetContext(), sigRequest.GetNonce(), true) {
		return INVALID_CRYPTO, nil
	}

	// Finally, check whether attribute values in proof satisfy the original signature request
	return checkProofWithRequest(configuration, &proofList, sigRequest)
}
