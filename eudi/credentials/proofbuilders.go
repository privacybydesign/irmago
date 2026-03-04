package credentials

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/did"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
)

type ProofBuilder interface {
	// TODO: input any type of private key (not just ECDSA)
	Build(key *ecdsa.PrivateKey) (interface{}, error)
}

/// --- JWT proof builder --- ///

type JwtProofBuilder struct {
	issuer   string
	audience string
	nonce    *string
	alg      jwa.SignatureAlgorithm
	clock    jwt.Clock
	method   openid4vci.CryptographicBindingMethod
}

func NewJwtProofBuilder(issuer string, audience string, alg jwa.SignatureAlgorithm, nonce *string, clock jwt.Clock, method openid4vci.CryptographicBindingMethod) *JwtProofBuilder {
	return &JwtProofBuilder{
		issuer:   issuer,
		audience: audience,
		nonce:    nonce,
		alg:      alg,
		clock:    clock,
		method:   method,
	}
}

func (b *JwtProofBuilder) Build(privKey *ecdsa.PrivateKey) (interface{}, error) {
	proofBuilder := jwt.NewBuilder()

	// Build the proof JWT
	proofBuilder = proofBuilder.
		Issuer(b.issuer).
		Audience([]string{b.audience}).
		IssuedAt(b.clock.Now())

	if b.nonce != nil {
		proofBuilder = proofBuilder.Claim("nonce", *b.nonce)
	}

	proofPayload, err := proofBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build proof payload: %v", err)
	}

	privJwk, err := jwk.Import(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ecdsa priv key to jwk: %v", err)
	}

	pubJwk, err := privJwk.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain pub key from priv key jwk: %v", err)
	}

	// Set public key metadata
	err = pubJwk.Set(jwk.KeyUsageKey, jwk.ForSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to set key usage on pub jwk: %v", err)
	}

	headers := jws.NewHeaders()
	headers.Set(jws.AlgorithmKey, b.alg.String())
	headers.Set(jws.TypeKey, "openid4vci-proof+jwt")

	switch b.method {
	case openid4vci.CryptographicBindingMethod_JWK:
		// For JWK method, include the public key in the JWT header
		headers.Set(jws.JWKKey, pubJwk)
	case openid4vci.CryptographicBindingMethod_DID_KEY:
		// TODO: should we store the DID (or at least the generated b64url value) as the identifier in the key storage, so that we can easily retrieve the correct private key when given the DID in the request?

		// TODO: the issuer should be a `did:web:...` reference. We need to perform some kind of check somewhere to ensure that the issuer DID is actually controlled by the issuer, otherwise an attacker could generate a random DID and include it in the proof JWT to trick the client into using a key that is not actually controlled by the issuer
		didBuilder := did.Builder{}
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
