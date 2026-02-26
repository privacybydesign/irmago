package did

import (
	"encoding/base64"
	"encoding/json"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type Builder struct {
}

// FromJwk creates a DID Document from a given JWK, based on the did:jwk method specification, found here: https://github.com/quartzjer/did-jwk/blob/main/spec.md
// Note that the JWK is expected to be a public key. If it contains private key material, this WILL BE included in the resulting DID Document!
func (b *Builder) FromJwk(key jwk.Key) (*DIDDocument, error) {
	// Serialize JWK to UTF-8 encoded string
	jwkBytes, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}

	// Base64URL encode the serialized JWK
	encodedJwk := base64.URLEncoding.EncodeToString(jwkBytes)

	// Add the "did:jwk:" prefix to the encoded string to form the DID
	did := "did:jwk:" + encodedJwk
	kid := did + "#0"

	// Create a DID Document with the generated DID and appropriate verification method
	doc := &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		ID: did,
		VerificationMethod: []VerificationMethod{
			{
				ID:           kid,
				Type:         "JsonWebKey2020",
				Controller:   did,
				PublicKeyJwk: key,
			},
		},
	}

	keyUsage, keyUsageSet := key.KeyUsage()
	if keyUsageSet {
		if jwk.KeyUsageType(keyUsage) == jwk.ForSignature {
			doc.Authentication = []VerificationRef{kid}
			doc.AssertionMethod = []VerificationRef{kid}
			// TODO: add capabilityInvocation and capabilityDelegation ?
		}
		if jwk.KeyUsageType(keyUsage) == jwk.ForEncryption {
			doc.KeyAgreement = []VerificationRef{kid}
		}
	}

	return doc, nil
}
