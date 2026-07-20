package openid4vci

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"mdoc"
)

// ============================================================
// PROOF OF POSSESSION — the holder proves it controls the device key it
// wants bound into the mdoc, at the credential endpoint
//
// [OID4VCI] 1.0 Appendix F.1 defines the "jwt" proof type Annex A §A.10's
// Credential Request example carries (proofs.jwt: [...]), decoded here:
//
//	header:  {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": {...}}
//	payload: {"aud": "<credential_issuer>", "iat": <unix>, "nonce": "<c_nonce>"}
//
// iss is deliberately ABSENT from ProofJWTClaims, not merely omitted: per
// Appendix F.1, "the iss claim MAY be omitted by a public client", and
// this profile has no client authentication at all (Annex A §A.5 — see
// credentialoffer.go's file comment), so there is no client_id for iss to
// carry in the first place.
//
// This is a hand-rolled JWS (RFC 7515) compact serialization, ES256 (RFC
// 7518 §3.4) — not a general-purpose JOSE library, the same way
// issuerAuth/deviceAuth are hand-built COSE_Sign1 rather than pulled in
// from elsewhere. Note the signature encoding differs from COSE despite
// using the same ES256 algorithm and P-256 key: JWS requires the raw
// R||S concatenation (two fixed 32-byte big-endian coordinates), not the
// ASN.1 DER encoding crypto/ecdsa.SignASN1 (or go-cose) would produce.
//
// SignProofOfPossession is a free function taking *mdoc.Holder, not a
// method on it: Go doesn't allow defining methods on a type from another
// package, and Holder must stay in the root mdoc package (it's shared by
// every protocol, not just this one). It only ever touches Holder's
// private key indirectly through Holder.SignRawDigest — the same "ask
// the Secure Enclave to sign, never extract the key" model the rest of
// this package uses.
//
// VerifyProofOfPossession deliberately does not check iat freshness or
// enforce single-use — replay protection for this flow comes from the
// issuer tracking that a given c_nonce (from nonceendpoint.go) has not
// already been redeemed, which is real issuer-side session state this
// stateless wire-format package doesn't model, the same way it doesn't
// track whether a pre-authorized_code has already been redeemed either.
// ============================================================

const proofJWTType = "openid4vci-proof+jwt"
const proofJWTAlg = "ES256"

// JWK is the subset of RFC 7518 §6.2.1's EC JWK this profile needs to
// embed the holder's device public key directly in the proof JWT header
// — this profile has no DID/kid infrastructure, so the wallet always
// presents its raw key, never a reference to one.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ProofJWTHeader is the proof JWT's JOSE header, matching Annex A
// §A.10's decoded worked example field-for-field.
type ProofJWTHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	JWK JWK    `json:"jwk"`
}

// ProofJWTClaims is the proof JWT's payload. No Iss field — see file
// comment above.
type ProofJWTClaims struct {
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Nonce string `json:"nonce"`
}

// jwkFromECDSA converts an ECDSA public key into the JWK this profile's
// proof JWT header embeds. Mirrors mdoc's own coseKeyFromECDSA
// coordinate extraction but produces JSON/base64url, not CBOR/COSE.
func jwkFromECDSA(pub *ecdsa.PublicKey) (JWK, error) {
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return JWK{}, fmt.Errorf("convert pub key: %w", err)
	}
	pubBytes := ecdhPub.Bytes() // 65 bytes: 04 || X(32) || Y(32)
	return JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pubBytes[1:33]),
		Y:   base64.RawURLEncoding.EncodeToString(pubBytes[33:]),
	}, nil
}

// ecdsaPublicKeyFromJWK reconstructs a *ecdsa.PublicKey from a JWK — the
// issuer-side inverse of jwkFromECDSA, used by VerifyProofOfPossession to
// recover the key a proof JWT claims to be signed by. Delegates the
// actual on-curve validation to mdoc.ECDSAPublicKeyFromCoordinates, the
// same helper mdoc's own COSE key reconstruction uses, rather than
// duplicating that logic here.
func ecdsaPublicKeyFromJWK(k JWK) (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" {
		return nil, fmt.Errorf("unsupported kty %q (want EC)", k.Kty)
	}
	if k.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported crv %q (want P-256)", k.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}
	return mdoc.ECDSAPublicKeyFromCoordinates(new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes))
}

// signingInput builds the JWS compact serialization's signing input:
// base64url(header) + "." + base64url(payload) — RFC 7515 §5.1.
func signingInput(header ProofJWTHeader, claims ProofJWTClaims) (string, error) {
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes), nil
}

// SignProofOfPossession builds and signs the proof-of-possession JWT the
// holder presents at the credential endpoint (Annex A §A.10's
// proofs.jwt), binding its device key to aud (the credential issuer
// identifier) and nonce (the c_nonce from the Nonce Endpoint — see
// nonceendpoint.go). Fresh per credential request, never reused, the
// same way Holder.SignDeviceAuth builds a fresh deviceAuth per
// presentation.
func SignProofOfPossession(h *mdoc.Holder, aud, nonce string) (string, error) {
	jwk, err := jwkFromECDSA(h.PublicKey())
	if err != nil {
		return "", fmt.Errorf("build jwk: %w", err)
	}
	header := ProofJWTHeader{Typ: proofJWTType, Alg: proofJWTAlg, JWK: jwk}
	claims := ProofJWTClaims{Aud: aud, Iat: time.Now().Unix(), Nonce: nonce}

	input, err := signingInput(header, claims)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256([]byte(input))
	r, s, err := h.SignRawDigest(digest[:])
	if err != nil {
		return "", fmt.Errorf("sign proof jwt: %w", err)
	}

	// JWS ES256 signatures are the raw R||S concatenation (RFC 7518
	// §3.4) — two fixed 32-byte big-endian coordinates for P-256 — NOT
	// the ASN.1 DER encoding ecdsa.SignASN1/COSE would produce.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyProofOfPossession is the issuer-side counterpart to
// SignProofOfPossession: parses a proof JWT, checks it targets
// expectedAud and carries expectedNonce, verifies its signature against
// the public key embedded in its own header, and returns that key —
// which the issuer can now trust to embed as deviceKeyInfo, having just
// confirmed the holder actually controls the matching private key
// (unlike Issue()'s current holderPub parameter, which is simply
// trusted with no such proof). Rejects a mismatched typ, alg, aud, or
// nonce, or an invalid signature, rather than silently accepting a
// malformed or misdirected proof.
func VerifyProofOfPossession(jwt, expectedAud, expectedNonce string) (*ecdsa.PublicKey, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed proof jwt: expected 3 dot-separated parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	var header ProofJWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("unmarshal header: %w", err)
	}
	if header.Typ != proofJWTType {
		return nil, fmt.Errorf("unexpected typ %q, expected %q", header.Typ, proofJWTType)
	}
	if header.Alg != proofJWTAlg {
		return nil, fmt.Errorf("unexpected alg %q, expected %q", header.Alg, proofJWTAlg)
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims ProofJWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	if claims.Aud != expectedAud {
		return nil, fmt.Errorf("unexpected aud %q, expected %q", claims.Aud, expectedAud)
	}
	if claims.Nonce != expectedNonce {
		return nil, fmt.Errorf("unexpected nonce %q, expected %q", claims.Nonce, expectedNonce)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != 64 {
		return nil, fmt.Errorf("unexpected signature length %d, expected 64 (raw R||S for P-256)", len(sig))
	}

	pub, err := ecdsaPublicKeyFromJWK(header.JWK)
	if err != nil {
		return nil, fmt.Errorf("recover public key from jwk: %w", err)
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, fmt.Errorf("proof jwt signature invalid")
	}

	return pub, nil
}
