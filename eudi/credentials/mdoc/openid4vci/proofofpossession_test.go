package openid4vci

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"mdoc"
)

// TestSignProofOfPossessionVerifies confirms a JWT built by
// SignProofOfPossession is accepted by VerifyProofOfPossession, which
// recovers the exact same public key the holder signed with.
func TestSignProofOfPossessionVerifies(t *testing.T) {
	holder, err := mdoc.NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}

	jwt, err := SignProofOfPossession(holder, "https://credential-issuer.example.com", "some-c-nonce")
	if err != nil {
		t.Fatalf("SignProofOfPossession: %v", err)
	}

	pub, err := VerifyProofOfPossession(jwt, "https://credential-issuer.example.com", "some-c-nonce")
	if err != nil {
		t.Fatalf("VerifyProofOfPossession: %v", err)
	}
	if !pub.Equal(holder.PublicKey()) {
		t.Fatalf("recovered public key does not match holder's device key")
	}
}

// TestProofJWTHeaderShape confirms the decoded header matches Annex A
// §A.10's worked example shape: typ, alg, and an EC/P-256 jwk.
func TestProofJWTHeaderShape(t *testing.T) {
	holder, err := mdoc.NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	jwt, err := SignProofOfPossession(holder, "aud", "nonce")
	if err != nil {
		t.Fatalf("SignProofOfPossession: %v", err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 dot-separated parts, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header ProofJWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header.Typ != "openid4vci-proof+jwt" {
		t.Fatalf("expected typ %q, got %q", "openid4vci-proof+jwt", header.Typ)
	}
	if header.Alg != "ES256" {
		t.Fatalf("expected alg %q, got %q", "ES256", header.Alg)
	}
	if header.JWK.Kty != "EC" || header.JWK.Crv != "P-256" {
		t.Fatalf("unexpected jwk: %+v", header.JWK)
	}
}

// TestProofJWTClaimsOmitIss confirms the claims JSON has no "iss" field
// at all — not merely an empty one — matching this profile having no
// client authentication (see file comment).
func TestProofJWTClaimsOmitIss(t *testing.T) {
	holder, err := mdoc.NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	jwt, err := SignProofOfPossession(holder, "aud", "nonce")
	if err != nil {
		t.Fatalf("SignProofOfPossession: %v", err)
	}

	parts := strings.Split(jwt, ".")
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if _, ok := claims["iss"]; ok {
		t.Fatalf("expected no iss claim, got %v", claims["iss"])
	}
}

// TestVerifyProofOfPossessionRejectsWrongAud confirms a JWT signed for
// one audience is rejected when verified against a different one.
func TestVerifyProofOfPossessionRejectsWrongAud(t *testing.T) {
	holder, err := mdoc.NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	jwt, err := SignProofOfPossession(holder, "https://issuer-a.example.com", "nonce")
	if err != nil {
		t.Fatalf("SignProofOfPossession: %v", err)
	}
	if _, err := VerifyProofOfPossession(jwt, "https://issuer-b.example.com", "nonce"); err == nil {
		t.Fatalf("expected error for mismatched aud, got none")
	}
}

// TestVerifyProofOfPossessionRejectsWrongNonce confirms a JWT signed over
// one nonce is rejected when verified against a different one.
func TestVerifyProofOfPossessionRejectsWrongNonce(t *testing.T) {
	holder, err := mdoc.NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	jwt, err := SignProofOfPossession(holder, "aud", "nonce-a")
	if err != nil {
		t.Fatalf("SignProofOfPossession: %v", err)
	}
	if _, err := VerifyProofOfPossession(jwt, "aud", "nonce-b"); err == nil {
		t.Fatalf("expected error for mismatched nonce, got none")
	}
}

// TestVerifyProofOfPossessionRejectsMalformedJWT confirms a string that
// isn't a well-formed 3-part JWT is rejected rather than panicking.
func TestVerifyProofOfPossessionRejectsMalformedJWT(t *testing.T) {
	if _, err := VerifyProofOfPossession("not-a-jwt", "aud", "nonce"); err == nil {
		t.Fatalf("expected error for malformed jwt, got none")
	}
}

// TestVerifyProofOfPossessionRejectsTamperedSignature confirms flipping a
// byte in the signature causes verification to fail.
func TestVerifyProofOfPossessionRejectsTamperedSignature(t *testing.T) {
	holder, err := mdoc.NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	jwt, err := SignProofOfPossession(holder, "aud", "nonce")
	if err != nil {
		t.Fatalf("SignProofOfPossession: %v", err)
	}

	parts := strings.Split(jwt, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	sig[0] ^= 0xFF // flip a byte
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)

	if _, err := VerifyProofOfPossession(tampered, "aud", "nonce"); err == nil {
		t.Fatalf("expected error for tampered signature, got none")
	}
}

// TestVerifyProofOfPossessionRejectsWrongTyp confirms a JWT whose header
// carries a different typ is rejected, even if otherwise well-formed and
// validly signed.
func TestVerifyProofOfPossessionRejectsWrongTyp(t *testing.T) {
	holder, err := mdoc.NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	jwk, err := jwkFromECDSA(holder.PublicKey())
	if err != nil {
		t.Fatalf("jwkFromECDSA: %v", err)
	}
	header := ProofJWTHeader{Typ: "jwt", Alg: proofJWTAlg, JWK: jwk} // wrong typ
	claims := ProofJWTClaims{Aud: "aud", Iat: time.Now().Unix(), Nonce: "nonce"}
	jwt := signAndAssemble(t, holder, header, claims)

	if _, err := VerifyProofOfPossession(jwt, "aud", "nonce"); err == nil {
		t.Fatalf("expected error for wrong typ, got none")
	}
}

// signAndAssemble builds and signs a proof JWT with an arbitrary
// header/claims pair — used only to construct deliberately malformed
// JWTs for negative tests, mirroring SignProofOfPossession's own signing
// logic since that function fixes typ/alg internally. Signs via
// Holder.SignRawDigest — the only way to get a real signature from a
// device key without this package needing access to Holder's unexported
// private key field.
func signAndAssemble(t *testing.T, holder *mdoc.Holder, header ProofJWTHeader, claims ProofJWTClaims) string {
	t.Helper()
	input, err := signingInput(header, claims)
	if err != nil {
		t.Fatalf("signingInput: %v", err)
	}
	digest := sha256.Sum256([]byte(input))
	r, s, err := holder.SignRawDigest(digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
