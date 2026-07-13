package proofs

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/didjwk"
	"github.com/privacybydesign/irmago/eudi/didkey"
)

// ES256SignFunc signs the ASCII JWS signing input ("base64url(header).base64url(payload)")
// and returns the raw 64-byte r||s ES256 signature. It lets the holder key live
// outside this process (e.g. in a WSCA/HSM): the proof JWT is assembled here but
// signed by whoever holds the key.
type ES256SignFunc func(signingInput []byte) (sig []byte, err error)

type CryptographicBindingMethod string

const (
	CryptographicBindingMethod_JWK     CryptographicBindingMethod = "jwk"
	CryptographicBindingMethod_DID_KEY CryptographicBindingMethod = "did:key"
	CryptographicBindingMethod_DID_JWK CryptographicBindingMethod = "did:jwk"
	CryptographicBindingMethod_COSE    CryptographicBindingMethod = "cose_key"
)

type ProofBuilder interface {
	// TODO: input any type of private key (not just ECDSA)
	Build(key *ecdsa.PrivateKey) (any, error)
}

/// --- JWT proof builder --- ///

type JwtProofBuilder struct {
	issuer   string
	audience string
	nonce    *string
	alg      jwa.SignatureAlgorithm
	clock    jwt.Clock
	method   CryptographicBindingMethod
}

func NewJwtProofBuilder(issuer string, audience string, alg jwa.SignatureAlgorithm, nonce *string, clock jwt.Clock, method CryptographicBindingMethod) *JwtProofBuilder {
	return &JwtProofBuilder{
		issuer:   issuer,
		audience: audience,
		nonce:    nonce,
		alg:      alg,
		clock:    clock,
		method:   method,
	}
}

func (b *JwtProofBuilder) Build(privKey *ecdsa.PrivateKey) (any, error) {
	proofBuilder := jwt.NewBuilder()

	// Build the proof JWT
	proofBuilder = proofBuilder.
		Audience([]string{b.audience}).
		Issuer(b.issuer).
		IssuedAt(b.clock.Now())

	if b.nonce != nil {
		proofBuilder = proofBuilder.Claim("nonce", *b.nonce)
	}

	proofPayload, err := proofBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build proof payload: %v", err)
	}

	// Flatten the "aud" claim to a single string if it contains only one value, to be compliant with the OID4VCI JWT proof spec
	proofPayload.Options().Enable(jwt.FlattenAudience)

	privJwk, err := jwk.Import(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ecdsa priv key to jwk: %v", err)
	}

	pubJwk, err := privJwk.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain pub key from priv key jwk: %v", err)
	}

	// Set public key metadata that this key is meant for signature verification
	err = pubJwk.Set(jwk.KeyUsageKey, jwk.ForSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to set key usage on pub jwk: %v", err)
	}

	headers := jws.NewHeaders()
	headers.Set(jws.AlgorithmKey, b.alg.String())
	headers.Set(jws.TypeKey, "openid4vci-proof+jwt")

	switch b.method {
	case CryptographicBindingMethod_JWK:
		// For JWK method, include the public key in the JWT header
		headers.Set(jws.JWKKey, pubJwk)
	case CryptographicBindingMethod_DID_KEY:
		did, err := didkey.Create(privKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create did:key from public key: %v", err)
		}
		headers.Set(jws.KeyIDKey, did)
	case CryptographicBindingMethod_DID_JWK:
		// TODO: the issuer should be a `did:web:...` reference. We need to perform some kind of check somewhere to ensure that the issuer DID is actually controlled by the issuer, otherwise an attacker could generate a random DID and include it in the proof JWT to trick the client into using a key that is not actually controlled by the issuer
		didBuilder := didjwk.DocumentBuilder{}
		did, err := didBuilder.FromJwk(pubJwk)
		if err != nil {
			return nil, fmt.Errorf("failed to create did from jwk: %v", err)
		}

		// For DID method, we set `kid` to be the assertion method of the DID, which contains the public key, and the verifier can then resolve the DID to obtain the public key
		if len(did.AssertionMethod) == 0 {
			return nil, fmt.Errorf("did created from jwk does not contain an assertion method; is the key usage of the jwk set correctly?")
		}
		headers.Set(jws.KeyIDKey, did.AssertionMethod[0])
	default:
		return nil, fmt.Errorf("unsupported cryptographic binding method: %s", b.method)
	}

	serializedJwt, err := jwt.Sign(proofPayload, jwt.WithKey(b.alg, privJwk, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, fmt.Errorf("failed to sign proof jwt: %v", err)
	}

	return string(serializedJwt), nil
}

// BuildWithES256Signer assembles the same openid4vci-proof+jwt as Build but signs
// it through an external ES256 signer, given only the holder public key. This is
// the path used when the holder private key lives in a WSCA/HSM and never enters
// this process. Only ES256 is supported (b.alg must be ES256).
func (b *JwtProofBuilder) BuildWithES256Signer(pub *ecdsa.PublicKey, sign ES256SignFunc) (string, error) {
	if b.alg.String() != "ES256" {
		return "", fmt.Errorf("BuildWithES256Signer only supports ES256, got %s", b.alg.String())
	}

	// Public JWK, marked for signature use (mirrors Build).
	pubJwk, err := jwk.Import(pub)
	if err != nil {
		return "", fmt.Errorf("failed to import holder public key: %v", err)
	}
	if err := pubJwk.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return "", fmt.Errorf("failed to set key usage on pub jwk: %v", err)
	}

	// Header — identical fields to Build, per cryptographic binding method.
	header := map[string]any{
		"alg": "ES256",
		"typ": "openid4vci-proof+jwt",
	}
	switch b.method {
	case CryptographicBindingMethod_JWK:
		header["jwk"] = pubJwk
	case CryptographicBindingMethod_DID_KEY:
		did, err := didkey.Create(*pub)
		if err != nil {
			return "", fmt.Errorf("failed to create did:key from public key: %v", err)
		}
		header["kid"] = did
	case CryptographicBindingMethod_DID_JWK:
		didBuilder := didjwk.DocumentBuilder{}
		did, err := didBuilder.FromJwk(pubJwk)
		if err != nil {
			return "", fmt.Errorf("failed to create did from jwk: %v", err)
		}
		if len(did.AssertionMethod) == 0 {
			return "", fmt.Errorf("did created from jwk does not contain an assertion method")
		}
		header["kid"] = did.AssertionMethod[0]
	default:
		return "", fmt.Errorf("unsupported cryptographic binding method: %s", b.method)
	}

	// Payload — aud flattened to a single string, matching Build's FlattenAudience.
	payload := map[string]any{
		"aud": b.audience,
		"iss": b.issuer,
		"iat": b.clock.Now().Unix(),
	}
	if b.nonce != nil {
		payload["nonce"] = *b.nonce
	}

	signingInput, err := jwsSigningInput(header, payload)
	if err != nil {
		return "", err
	}
	sig, err := sign(signingInput)
	if err != nil {
		return "", fmt.Errorf("failed to sign proof jwt: %v", err)
	}
	jws := append(signingInput, '.')
	jws = append(jws, []byte(base64.RawURLEncoding.EncodeToString(sig))...)
	return string(jws), nil
}

// jwsSigningInput returns "base64url(header).base64url(payload)" for a compact JWS.
func jwsSigningInput(header, payload map[string]any) ([]byte, error) {
	hdrBytes, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal jws header: %w", err)
	}
	plBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal jws payload: %w", err)
	}
	enc := base64.RawURLEncoding
	out := make([]byte, 0, enc.EncodedLen(len(hdrBytes))+1+enc.EncodedLen(len(plBytes)))
	out = append(out, enc.EncodeToString(hdrBytes)...)
	out = append(out, '.')
	out = append(out, enc.EncodeToString(plBytes)...)
	return out, nil
}
