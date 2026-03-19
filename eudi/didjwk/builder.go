package didjwk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/did"
)

type DocumentBuilder struct{}

// FromJwk creates a DID Document from a given JWK, based on the did:jwk method specification, found here: https://github.com/quartzjer/did-jwk/blob/main/spec.md
// Note that the JWK is expected to be a public key. If it contains private key material, an error will be returned.
func (b *DocumentBuilder) FromJwk(key jwk.Key) (*did.Document, error) {
	isPrivateKey, err := jwk.IsPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to determine if JWK contains private key material: %v", err)
	}
	if isPrivateKey {
		return nil, fmt.Errorf("cannot create did:jwk DID Document from a JWK containing private key material")
	}

	// Serialize JWK to UTF-8 encoded string
	// Note: json.Marshal uses key ordering, which is important to generate a consistent encoded string for the same key
	jwkBytes, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}

	// Base64URL encode the serialized JWK
	encodedJwk := base64.RawURLEncoding.EncodeToString(jwkBytes)

	// Add the "did:jwk:" prefix to the encoded string to form the DID
	didJwk := "did:jwk:" + encodedJwk
	kid := didJwk + "#0"

	// Create a DID Document with the generated DID and appropriate verification method
	doc := &did.Document{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		ID: didJwk,
		VerificationMethod: []did.VerificationMethod{
			{
				ID:           kid,
				Type:         "JsonWebKey2020",
				Controller:   didJwk,
				PublicKeyJwk: &key,
			},
		},
	}

	keyUsage, keyUsageSet := key.KeyUsage()
	if keyUsageSet {
		if jwk.KeyUsageType(keyUsage) == jwk.ForSignature {
			doc.Authentication = []did.VerificationRef{kid}
			doc.AssertionMethod = []did.VerificationRef{kid}
			// TODO: add capabilityInvocation and capabilityDelegation ?
		}
		if jwk.KeyUsageType(keyUsage) == jwk.ForEncryption {
			doc.KeyAgreement = []did.VerificationRef{kid}
		}
	}

	return doc, nil
}
