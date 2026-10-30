package usage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"

	"github.com/go-errors/errors"
)

const accountKeyFileName = "account.key"

// LoadOrCreateKey returns the ES256 account key. A key in keyFile is always used and must exist.
// Otherwise the key is read from stateDir, and generated there on first use.
func LoadOrCreateKey(keyFile, stateDir string) (*ecdsa.PrivateKey, error) {
	if keyFile != "" {
		return readKey(keyFile)
	}
	if stateDir == "" {
		return nil, errors.New("usage reporting needs an account key that survives restarts: set an account key file or a state dir")
	}
	path := filepath.Join(stateDir, accountKeyFileName)
	if _, err := os.Stat(path); err == nil {
		return readKey(path)
	} else if !os.IsNotExist(err) {
		return nil, errors.WrapPrefix(err, "failed to read usage reporting account key", 0)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, errors.WrapPrefix(err, "failed to create usage reporting state dir", 0)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, errors.WrapPrefix(err, "failed to store usage reporting account key", 0)
	}
	return key, nil
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	bts, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.WrapPrefix(err, "failed to read usage reporting account key", 0)
	}
	block, _ := pem.Decode(bts)
	if block == nil {
		return nil, errors.Errorf("usage reporting account key %s is not PEM encoded", path)
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return checkCurve(key)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Errorf("usage reporting account key %s is not an EC private key", path)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.Errorf("usage reporting account key %s is not an EC private key", path)
	}
	return checkCurve(key)
}

func checkCurve(key *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	if key.Curve != elliptic.P256() {
		return nil, errors.New("usage reporting account key must be a P-256 key (ES256)")
	}
	return key, nil
}

// PublicKeyPEM returns the public key in the form the operator registers in the Portal.
func PublicKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

type jwk struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func publicJWK(key *ecdsa.PrivateKey) jwk {
	// The uncompressed point is 0x04 || X || Y, each coordinate 32 bytes for P-256.
	point, _ := key.PublicKey.Bytes()
	return jwk{
		Crv: "P-256",
		Kty: "EC",
		X:   b64(point[1:33]),
		Y:   b64(point[33:65]),
	}
}

// Thumbprint returns the RFC 7638 JWK thumbprint of the public key, which identifies the key in
// the Portal.
func Thumbprint(key *ecdsa.PrivateKey) string {
	// The members of jwk are declared in the lexicographic order RFC 7638 requires.
	bts, _ := json.Marshal(publicJWK(key))
	sum := sha256.Sum256(bts)
	return b64(sum[:])
}

// signJWS returns a flattened JWS JSON serialization of payload, as used by ACME (RFC 8555).
func signJWS(key *ecdsa.PrivateKey, protected map[string]any, payload []byte) ([]byte, error) {
	header, err := json.Marshal(protected)
	if err != nil {
		return nil, err
	}
	signingInput := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	signature := append(padded(r), padded(s)...)
	return json.Marshal(map[string]string{
		"protected": b64(header),
		"payload":   b64(payload),
		"signature": b64(signature),
	})
}

// padded returns n as a 32-byte big-endian integer, the size of a P-256 coordinate.
func padded(n *big.Int) []byte {
	return n.FillBytes(make([]byte, 32))
}

func b64(bts []byte) string {
	return base64.RawURLEncoding.EncodeToString(bts)
}
