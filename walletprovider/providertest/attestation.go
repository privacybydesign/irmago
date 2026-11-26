package providertest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// InstanceAttestationType is the typ of a wallet instance attestation: an
// OAuth client attestation (draft-ietf-oauth-attestation-based-client-auth).
const InstanceAttestationType = "oauth-client-attestation+jwt"

// MaxInstanceAttestationLifetime is the longest a WIA may be valid (TS3: less
// than 24 hours).
const MaxInstanceAttestationLifetime = 24 * time.Hour

// InstanceAttestation is what ParseInstanceAttestation found in a WIA.
type InstanceAttestation struct {
	// Subject is the client_id the wallet authenticates as.
	Subject string
	// Key is the key the WIA binds (cnf.jwk), which signs its PoPs.
	Key    *ecdsa.PublicKey
	Expiry time.Time
	// Chain is the x5c chain, leaf first. Its leaf signed the WIA; whether its
	// root is trusted is for the caller to decide.
	Chain []*x509.Certificate
	// StatusIndex and StatusURI locate the WIA in its Token Status List
	// (client_status), which the provider maintains until StatusExpiry.
	StatusIndex  int
	StatusURI    string
	StatusExpiry time.Time
	Claims       map[string]any
}

// ParseInstanceAttestation checks a WIA's shape and signature: an ES256 JWS
// with typ oauth-client-attestation+jwt, signed by the leaf of its x5c chain,
// which is not self-signed and chains through the rest; a sub; a cnf.jwk
// holding a P-256 public key; an exp in the future, at most
// MaxInstanceAttestationLifetime away; and a client_status whose status list
// reference has an index, a URI and a maintenance exp no earlier than the
// WIA's own. It does not decide whether the chain's root is trusted.
func ParseInstanceAttestation(wia []byte) (*InstanceAttestation, error) {
	header, claims, chain, err := parseSignedJWT(string(wia))
	if err != nil {
		return nil, err
	}
	if header["typ"] != InstanceAttestationType {
		return nil, fmt.Errorf("typ is %v, want %s", header["typ"], InstanceAttestationType)
	}

	a := &InstanceAttestation{Chain: chain, Claims: claims}
	a.Subject, _ = claims["sub"].(string)
	if a.Subject == "" {
		return nil, errors.New("no sub")
	}
	exp, ok := numericDate(claims["exp"])
	if !ok {
		return nil, errors.New("no exp")
	}
	a.Expiry = exp
	if until := time.Until(exp); until <= 0 || until > MaxInstanceAttestationLifetime {
		return nil, fmt.Errorf("exp %v is not within %v from now", exp, MaxInstanceAttestationLifetime)
	}

	cnf, _ := claims["cnf"].(map[string]any)
	jwk, _ := cnf["jwk"].(map[string]any)
	if jwk == nil {
		return nil, errors.New("no cnf.jwk")
	}
	if a.Key, err = PublicKeyFromJWK(jwk); err != nil {
		return nil, fmt.Errorf("cnf.jwk: %w", err)
	}

	status, _ := claims["client_status"].(map[string]any)
	list, _ := status["status"].(map[string]any)
	ref, _ := list["status_list"].(map[string]any)
	if ref == nil {
		return nil, errors.New("no client_status.status.status_list")
	}
	idx, ok := ref["idx"].(float64)
	if !ok || idx < 0 || idx != float64(int(idx)) {
		return nil, errors.New("client_status has no valid idx")
	}
	a.StatusIndex = int(idx)
	a.StatusURI, _ = ref["uri"].(string)
	if a.StatusURI == "" {
		return nil, errors.New("client_status has no uri")
	}
	if a.StatusExpiry, ok = numericDate(status["exp"]); !ok {
		return nil, errors.New("client_status has no exp")
	}
	if a.StatusExpiry.Before(a.Expiry) {
		return nil, errors.New("the status is maintained for less long than the WIA is valid")
	}
	return a, nil
}

// JWK returns the public JWK of a P-256 key.
func JWK(pub *ecdsa.PublicKey) map[string]any {
	point, err := pub.Bytes() // 0x04 ‖ x ‖ y
	if err != nil || len(point) != 65 {
		panic(fmt.Sprintf("providertest: not a P-256 public key: %v", err))
	}
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]any{"kty": "EC", "crv": "P-256", "x": enc(point[1:33]), "y": enc(point[33:])}
}

// PublicKeyFromJWK parses the public JWK of a P-256 key, refusing one that
// holds a private key.
func PublicKeyFromJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
		return nil, fmt.Errorf("not a P-256 key: kty %v, crv %v", jwk["kty"], jwk["crv"])
	}
	if _, private := jwk["d"]; private {
		return nil, errors.New("holds a private key")
	}
	point := []byte{4}
	for _, name := range []string{"x", "y"} {
		s, _ := jwk[name].(string)
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("invalid %s", name)
		}
		point = append(point, b...)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, errors.New("not a point on P-256")
	}
	return pub, nil
}

// parseSignedJWT parses a compact ES256 JWS carrying its signer's chain in
// x5c, and checks that the chain's leaf signed it, that the leaf is not
// self-signed and that each certificate is signed by the next.
func parseSignedJWT(token string) (header, claims map[string]any, chain []*x509.Certificate, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, nil, errors.New("not a compact JWS")
	}
	decode := func(part string, v any) error {
		data, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, v)
	}
	if err := decode(parts[0], &header); err != nil {
		return nil, nil, nil, fmt.Errorf("header: %w", err)
	}
	if err := decode(parts[1], &claims); err != nil {
		return nil, nil, nil, fmt.Errorf("claims: %w", err)
	}
	if header["alg"] != "ES256" {
		return nil, nil, nil, fmt.Errorf("alg is %v, want ES256", header["alg"])
	}

	x5c, _ := header["x5c"].([]any)
	if len(x5c) == 0 {
		return nil, nil, nil, errors.New("no x5c")
	}
	for i, entry := range x5c {
		s, _ := entry.(string)
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("x5c[%d]: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("x5c[%d]: %w", i, err)
		}
		chain = append(chain, cert)
	}
	leaf := chain[0]
	if leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil {
		return nil, nil, nil, errors.New("the x5c leaf is self-signed")
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return nil, nil, nil, fmt.Errorf("x5c[%d] is not signed by x5c[%d]: %w", i, i+1, err)
		}
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, nil, errors.New("the x5c leaf is not an ECDSA key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("signature: %w", err)
	}
	if !verifyES256(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, nil, nil, errors.New("the signature does not verify under the x5c leaf")
	}
	return header, claims, chain, nil
}

func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

// KeyAttestationType is the typ of a key attestation (OpenID4VCI 1.0
// Appendix D).
const KeyAttestationType = "key-attestation+jwt"

// KeyAttestation is what ParseKeyAttestation found in a KA.
type KeyAttestation struct {
	AttestedKeys []*ecdsa.PublicKey
	// Nonce is the issuer's c_nonce, empty when the KA carries none.
	Nonce  string
	Expiry time.Time
	// KeyStorage and UserAuthentication are the claimed attack potential
	// resistance levels, empty when not claimed.
	KeyStorage         []string
	UserAuthentication []string
	// StatusIndex and StatusURI locate the KA in its Token Status List, which
	// the provider maintains until StatusExpiry (TS3 key_storage_status).
	StatusIndex  int
	StatusURI    string
	StatusExpiry time.Time
	Chain        []*x509.Certificate
	Claims       map[string]any
}

// ParseKeyAttestation checks a KA's shape and signature: an ES256 JWS with
// typ key-attestation+jwt, signed by the leaf of its x5c chain (as for
// ParseInstanceAttestation); an iat; an exp in the future, which a KA used
// with the jwt proof type must have; a non-empty attested_keys of P-256
// public JWKs; key_storage and user_authentication, when present, as
// non-empty string arrays; a nonce, when present, as a string; and a status
// reference both as Appendix D's status and as TS3's key_storage_status,
// naming the same entry, maintained no shorter than the KA is valid. It does
// not decide whether the chain's root is trusted.
func ParseKeyAttestation(ka []byte) (*KeyAttestation, error) {
	header, claims, chain, err := parseSignedJWT(string(ka))
	if err != nil {
		return nil, err
	}
	if header["typ"] != KeyAttestationType {
		return nil, fmt.Errorf("typ is %v, want %s", header["typ"], KeyAttestationType)
	}
	a := &KeyAttestation{Chain: chain, Claims: claims}
	if _, ok := numericDate(claims["iat"]); !ok {
		return nil, errors.New("no iat")
	}
	exp, ok := numericDate(claims["exp"])
	if !ok || !exp.After(time.Now()) {
		return nil, fmt.Errorf("exp %v is missing or passed", exp)
	}
	a.Expiry = exp

	keys, _ := claims["attested_keys"].([]any)
	if len(keys) == 0 {
		return nil, errors.New("no attested_keys")
	}
	for i, k := range keys {
		jwk, _ := k.(map[string]any)
		pub, err := PublicKeyFromJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("attested_keys[%d]: %w", i, err)
		}
		a.AttestedKeys = append(a.AttestedKeys, pub)
	}

	for name, dst := range map[string]*[]string{"key_storage": &a.KeyStorage, "user_authentication": &a.UserAuthentication} {
		v, present := claims[name]
		if !present {
			continue
		}
		list, _ := v.([]any)
		if len(list) == 0 {
			return nil, fmt.Errorf("%s is not a non-empty array", name)
		}
		for _, entry := range list {
			s, ok := entry.(string)
			if !ok || s == "" {
				return nil, fmt.Errorf("%s holds a non-string", name)
			}
			*dst = append(*dst, s)
		}
	}
	if v, present := claims["nonce"]; present {
		if a.Nonce, ok = v.(string); !ok || a.Nonce == "" {
			return nil, errors.New("nonce is not a string")
		}
	}

	status, _ := claims["status"].(map[string]any)
	idx, uri, err := statusListReference(status)
	if err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	keyStorageStatus, _ := claims["key_storage_status"].(map[string]any)
	inner, _ := keyStorageStatus["status"].(map[string]any)
	idx2, uri2, err := statusListReference(inner)
	if err != nil {
		return nil, fmt.Errorf("key_storage_status: %w", err)
	}
	if idx != idx2 || uri != uri2 {
		return nil, errors.New("status and key_storage_status name different entries")
	}
	a.StatusIndex, a.StatusURI = idx, uri
	if a.StatusExpiry, ok = numericDate(keyStorageStatus["exp"]); !ok {
		return nil, errors.New("key_storage_status has no exp")
	}
	if a.StatusExpiry.Before(a.Expiry) {
		return nil, errors.New("the status is maintained for less long than the KA is valid")
	}
	return a, nil
}

// statusListReference reads {"status_list": {"idx": …, "uri": …}}.
func statusListReference(status map[string]any) (int, string, error) {
	ref, _ := status["status_list"].(map[string]any)
	if ref == nil {
		return 0, "", errors.New("no status_list")
	}
	idx, ok := ref["idx"].(float64)
	if !ok || idx < 0 || idx != float64(int(idx)) {
		return 0, "", errors.New("no valid idx")
	}
	uri, _ := ref["uri"].(string)
	if uri == "" {
		return 0, "", errors.New("no uri")
	}
	return int(idx), uri, nil
}
