package irmaclient

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"math/big"
)

func extractPublicKeys(client *Client, proofList *gabi.ProofList) ([]*gabi.PublicKey, error) {
	var publicKeys []*gabi.PublicKey

	for _, v := range *proofList {
		switch v.(type) {
		case *gabi.ProofD:
			proof := v.(*gabi.ProofD)
			metadata := irma.MetadataFromInt(proof.ADisclosed[1], client.Configuration) // index 1 is metadata attribute
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

func extractDisclosedCredentials(client *Client, proofList *gabi.ProofList) ([]*irma.CredentialInfo, error) {
	var credentials []*irma.CredentialInfo

	for _, v := range *proofList {
		switch v.(type) {
		case *gabi.ProofD:
			proof := v.(*gabi.ProofD)
			irmaCredentialInfo, err := irma.NewCredentialInfoFromADisclosed(proof.AResponses, proof.ADisclosed, client.Configuration)
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

func checkProofWithRequest(client *Client, proofList *gabi.ProofList, sigRequest *irma.SignatureRequest) bool {
	credentials, err := extractDisclosedCredentials(client, proofList)

	if err != nil {
		fmt.Println(err)
		return false
	}

	for _, content := range sigRequest.Content {
		if !content.SatisfyDisclosed(credentials, client.Configuration) {
			return false
		}
	}
	return true
}

func verify(client *Client, proofList *gabi.ProofList, context *big.Int, nonce *big.Int, isSig bool) bool {
	// Extract public keys
	pks, err := extractPublicKeys(client, proofList)
	if err != nil {
		fmt.Printf("Error extracting public key: %v\n", err)
		return false
	}

	return proofList.Verify(pks, context, nonce, true, isSig)
}

// Verify a signature proof and check if the attributes match the attributes in the original request
func verifySig(client *Client, proofString string, sigRequest *irma.SignatureRequest) bool {

	// First, unmarshal proof and check if all the attributes in the proofstring match the signature request
	var proofList gabi.ProofList
	proofBytes := []byte(proofString)

	err := proofList.UnmarshalJSON(proofBytes)
	if err != nil {
		fmt.Printf("Error unmarshalling JSON: %v\n", err)
		return false
	}

	// Now, cryptographically verify the signature
	if !verify(client, &proofList, sigRequest.GetContext(), sigRequest.GetNonce(), true) {
		return false
	}

	// Finally, check whether attribute values in proof satisfy the original signature request
	return checkProofWithRequest(client, &proofList, sigRequest)
}
