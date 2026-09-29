package fake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// AttestationCA is the fake's attestation PKI: a root, and a signing key it
// certifies, which signs the attestations with its certificate in x5c, as
// HAIP asks (a leaf that is not self-signed, and no trust anchor).
type AttestationCA struct {
	Root *x509.Certificate
	leaf *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewAttestationCA creates a fresh root and signing key.
func NewAttestationCA() (*AttestationCA, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake wallet provider root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	root, err := createCertificate(rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	leaf, err := createCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Fake wallet provider attestations"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, root, &key.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	return &AttestationCA{Root: root, leaf: leaf, key: key}, nil
}

// Roots is a pool holding the CA's root, for a test issuer's trust store.
func (ca *AttestationCA) Roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Root)
	return pool
}

func createCertificate(tpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// sign returns a compact ES256 JWS over claims, with typ and the signing
// certificate in x5c.
func (ca *AttestationCA) sign(typ string, claims any) (string, error) {
	header, err := json.Marshal(map[string]any{
		"alg": "ES256",
		"typ": typ,
		"x5c": []string{base64.StdEncoding.EncodeToString(ca.leaf.Raw)},
	})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, ca.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("fake wallet provider: sign %s: %w", typ, err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// randomIndex is a status list index, drawn from a range wide enough that two
// attestations practically never share one.
func randomIndex() int {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<31))
	if err != nil {
		panic(err)
	}
	return int(n.Int64())
}
