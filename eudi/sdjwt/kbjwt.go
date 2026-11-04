package sdjwt

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/eudi/didjwk"
	"github.com/privacybydesign/irmago/eudi/didkey"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

// systemClock is a minimal jwt.Clock backed by the system clock. Defined
// here instead of reused from eudi/jwt because that package transitively
// imports eudi/scheme (via eudi/utils' X.509 certificate-extension
// helpers), which sdjwt must not depend on.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// extractOptionalWith parses claims[key] with valueParser, returning the zero
// value when the key is absent. Defined here instead of reused from
// eudi/utils for the same reason as systemClock.
func extractOptionalWith[T any](claims map[string]any, key string, valueParser func(any) (T, error)) (T, error) {
	value, ok := claims[key]
	if !ok {
		var zero T
		return zero, nil
	}
	return valueParser(value)
}

// KeyBindingJwt is a string containing the key binding jwt (just the jwt, no ~ or something)
type KeyBindingJwt string

type KeyBindingJwtPayload struct {
	// REQUIRED: the hash over the **COMPLETE** issuer signed JWT part of the SD-JWT
	IssuerSignedJwtHash string `json:"sd_hash"`

	// REQUIRED: the nonce for this, should correspond to the one from the authorization
	Nonce string `json:"nonce"`

	// REQUIRED: the time of issuance
	IssuedAt int64 `json:"iat"`

	// Should equal "client_id" field from the openid4vp auth request
	Audience string `json:"aud"`
}

type CnfField struct {
	Jwk *jwk.Key `json:"jwk,omitempty"`
	// Note: kid can be any value, but for now we only support the did:jwk and did:key methods, so it should be a string DID URL referencing a key in the database with keybinding keys
	Kid *string `json:"kid,omitempty"`
}

// DuplicateConfirmation returns the index of the first confirmation that names
// the same holder key as another one, or -1 when every key is distinct. Nil
// confirmations are skipped. Each one-time-use copy in a batch must be bound
// to its own key, or presentations of the copies can be linked.
func DuplicateConfirmation(cnfs []*CnfField) int {
	for i, cnf := range cnfs {
		if cnf == nil {
			continue
		}
		for _, other := range cnfs[i+1:] {
			if other != nil &&
				((cnf.Jwk != nil && other.Jwk != nil && jwk.Equal(*other.Jwk, *cnf.Jwk)) ||
					(cnf.Kid != nil && other.Kid != nil && *other.Kid == *cnf.Kid)) {
				return i
			}
		}
	}
	return -1
}

func CreateKbJwt(sdJwt SdJwt, creator KeyBinder, nonce string, audience string) (KeyBindingJwt, error) {
	alg, holderKey, err := ExtractHashingAlgorithmAndHolderPubKey(sdJwt)
	if err != nil {
		return "", err
	}

	hash, err := iana.CreateUrlEncodedHash(alg, string(sdJwt))
	if err != nil {
		return "", err
	}

	// The binder adds iat.
	payload := map[string]any{
		"sd_hash": hash,
		"nonce":   nonce,
		"aud":     audience,
	}
	kbjwt, err := creator.CreateHolderSignedJwt(holderKey, map[string]any{"typ": KbJwtTyp}, payload)
	return KeyBindingJwt(kbjwt), err
}

// WithIssuedAt returns a copy of claims with iat set to now, for a KeyBinder
// implementation to stamp the time of signing.
func WithIssuedAt(claims map[string]any, now time.Time) map[string]any {
	stamped := maps.Clone(claims)
	if stamped == nil {
		stamped = map[string]any{}
	}
	stamped[jwt.IssuedAtKey] = now.Unix()
	return stamped
}

func ExtractHashingAlgorithmAndHolderPubKey(sdJwt SdJwt) (iana.HashingAlgorithm, jwk.Key, error) {
	issuerSignedJwt, _, err := Split(sdJwt)
	if err != nil {
		return "", nil, err
	}
	_, claims, err := DecodeJwtWithoutCheckingSignature(string(issuerSignedJwt))
	if err != nil {
		return "", nil, err
	}

	// SD-JWT spec Section 4.1.1: default to sha-256 if _sd_alg is absent.
	alg, ok := claims[SdAlgKey].(string)
	if !ok {
		alg = string(iana.SHA256)
	}

	confirm, err := extractOptionalWith(claims, ConfirmationKey, ParseConfirmField)
	if err != nil {
		return "", nil, err
	}

	key, err := resolveHolderKey(confirm)
	if err != nil {
		return "", nil, err
	}

	return iana.HashingAlgorithm(alg), key, nil
}

// resolveHolderKey extracts the holder public key from a cnf field.
// Supports both direct JWK (`cnf.jwk`) and DID-based key references (`cnf.kid`).
// For `did:jwk:` DIDs, the public key is embedded in the DID string itself.
func resolveHolderKey(cnf *CnfField) (jwk.Key, error) {
	// cnf field is mandatory when creating a KB-JWT
	if cnf == nil {
		return nil, fmt.Errorf("cnf field is required but missing from JWT claims")
	}

	if cnf.Jwk != nil {
		keyJson, err := json.Marshal(cnf.Jwk)
		if err != nil {
			return nil, err
		}
		return jwk.ParseKey(keyJson)
	}

	if cnf.Kid != nil {
		return resolveKeyFromDid(*cnf.Kid)
	}

	return nil, fmt.Errorf("cnf field has neither jwk nor kid")
}

// resolveKeyFromDid extracts a public key from a DID URL.
// Currently supports did:key and did:jwk where the key is base64url-encoded in the DID itself.
func resolveKeyFromDid(kid string) (jwk.Key, error) {
	if strings.HasPrefix(kid, didjwk.Prefix) || strings.HasPrefix(strings.SplitN(kid, "#", 2)[0], didjwk.Prefix) {
		key, err := didjwk.Resolve(kid)
		if err != nil {
			return nil, err
		}
		// Store the kid (DID URL) on the key so callers can use it for lookups
		key.Set(jwk.KeyIDKey, kid)
		return key, nil
	} else if strings.HasPrefix(kid, didkey.Prefix) {
		pubkey, err := didkey.Resolve(kid)
		if err != nil {
			return nil, err
		}

		// Create a JWK from the resolved public key
		key, err := jwk.Import[jwk.Key](pubkey)
		if err != nil {
			return nil, err
		}

		// Store the kid (DID URL) on the key so callers can use it for lookups
		key.Set(jwk.KeyIDKey, kid)
		return key, nil
	}

	return nil, fmt.Errorf("unsupported DID method in cnf.kid: %s", kid)
}
