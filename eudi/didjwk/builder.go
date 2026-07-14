package didjwk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/did"
)

const Prefix = "did:jwk:"

// Resolve parses a did:jwk DID string and returns the embedded JWK public key.
// The DID string may include a fragment (e.g., "did:jwk:eyJ...#0") which is stripped.
func Resolve(didJwk string) (jwk.Key, error) {
	// Strip fragment
	if idx := strings.Index(didJwk, "#"); idx != -1 {
		didJwk = didJwk[:idx]
	}

	if !strings.HasPrefix(didJwk, Prefix) {
		return nil, fmt.Errorf("invalid did:jwk: %s", didJwk)
	}

	encoded := strings.TrimPrefix(didJwk, Prefix)
	jwkBytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64url-decode did:jwk: %v", err)
	}

	key, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK from did:jwk: %v", err)
	}

	return key, nil
}

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

	didJwk := Prefix + encodedJwk
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
