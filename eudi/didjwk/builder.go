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

// keyFragment is the only fragment the did:jwk method defines: a resolved DID Document
// contains exactly one verification method, identified by "<did>#0".
const keyFragment = "0"

// Resolve parses a did:jwk DID URL and returns the embedded JWK public key.
// The DID URL may include the "#0" fragment (e.g. "did:jwk:eyJ...#0"), which is stripped.
func Resolve(didJwk string) (jwk.Key, error) {
	_, key, err := resolve(didJwk)
	return key, err
}

// ResolveDocument parses a did:jwk DID URL and returns the DID Document it resolves to,
// per the did:jwk method specification: https://github.com/quartzjer/did-jwk/blob/main/spec.md
//
// Unlike resolving the key and handing it to DocumentBuilder.FromJwk, this keeps the DID
// exactly as it was given. The DID is the base64url encoding of whatever JSON the other
// party produced, and re-serializing the parsed key does not necessarily reproduce that
// same JSON, since marshalling sorts the JWK members and the spec requires no particular
// order. Rebuilding the DID would then yield a document whose id and verification method
// id no longer match the DID that was resolved.
func ResolveDocument(didJwk string) (*did.Document, error) {
	didOnly, key, err := resolve(didJwk)
	if err != nil {
		return nil, err
	}
	return newDocument(didOnly, key), nil
}

// resolve splits off and validates the fragment, decodes the DID and parses the JWK.
// It returns the DID without its fragment alongside the key.
func resolve(didJwk string) (string, jwk.Key, error) {
	didOnly, fragment, hasFragment := strings.Cut(didJwk, "#")
	if hasFragment && fragment != keyFragment {
		return "", nil, fmt.Errorf("invalid did:jwk fragment %q: only #%s exists", fragment, keyFragment)
	}

	if !strings.HasPrefix(didOnly, Prefix) {
		return "", nil, fmt.Errorf("invalid did:jwk: %s", didJwk)
	}

	encoded := strings.TrimPrefix(didOnly, Prefix)
	jwkBytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", nil, fmt.Errorf("failed to base64url-decode did:jwk: %v", err)
	}

	key, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse JWK from did:jwk: %v", err)
	}

	// The spec is explicit that a did:jwk never carries secret key material: "a JWK for a
	// private key must never be used and must be rejected by all implementations".
	if err := requirePublicKey(key); err != nil {
		return "", nil, err
	}

	return didOnly, key, nil
}

// requirePublicKey returns an error unless the key is an asymmetric public key.
func requirePublicKey(key jwk.Key) error {
	isPrivateKey, err := jwk.IsPrivateKey(key)
	if err != nil {
		// jwk.IsPrivateKey only answers for asymmetric keys, so anything else is a
		// symmetric key, which is secret key material and never belongs in a did:jwk.
		return fmt.Errorf("did:jwk requires an asymmetric public key: %v", err)
	}
	if isPrivateKey {
		return fmt.Errorf("did:jwk cannot contain private key material")
	}
	return nil
}

type DocumentBuilder struct{}

// FromJwk creates a DID Document from a given JWK, based on the did:jwk method specification, found here: https://github.com/quartzjer/did-jwk/blob/main/spec.md
// Note that the JWK is expected to be a public key. If it contains private key material, an error will be returned.
func (b *DocumentBuilder) FromJwk(key jwk.Key) (*did.Document, error) {
	if err := requirePublicKey(key); err != nil {
		return nil, err
	}

	// Serialize JWK to UTF-8 encoded string
	// Note: json.Marshal uses key ordering, which is important to generate a consistent encoded string for the same key
	jwkBytes, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}

	// Base64URL encode the serialized JWK
	encodedJwk := base64.RawURLEncoding.EncodeToString(jwkBytes)

	return newDocument(Prefix+encodedJwk, key), nil
}

// newDocument builds the DID Document the spec prescribes for the given did:jwk and its key.
func newDocument(didJwk string, key jwk.Key) *did.Document {
	kid := didJwk + "#" + keyFragment

	doc := &did.Document{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		ID: didJwk,
		VerificationMethod: []did.VerificationMethod{
			{
				ID:           kid,
				Type:         did.VerificationMethodType_JsonWebKey2020,
				Controller:   didJwk,
				PublicKeyJwk: &key,
			},
		},
	}

	// The spec's document template carries every verification relationship, narrowed by the
	// JWK "use" member: "sig" leaves out keyAgreement, "enc" leaves in only keyAgreement.
	// Any other value, including no "use" at all, keeps the full set.
	keyUsage, _ := key.KeyUsage()
	usage := jwk.KeyUsageType(keyUsage)

	if usage != jwk.ForEncryption {
		doc.Authentication = []did.VerificationRef{kid}
		doc.AssertionMethod = []did.VerificationRef{kid}
		doc.CapabilityInvocation = []did.VerificationRef{kid}
		doc.CapabilityDelegation = []did.VerificationRef{kid}
	}
	if usage != jwk.ForSignature {
		doc.KeyAgreement = []did.VerificationRef{kid}
	}

	return doc
}
