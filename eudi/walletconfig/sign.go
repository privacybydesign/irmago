package walletconfig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/cert"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// Sign produces a signed wallet config: the counterpart of [Verify], and the one
// path a config is signed through, by tests and by the publisher alike.
//
// chain is leaf first, then the intermediates up to (not including) the root the
// wallets pin; it becomes the `x5c` header. key signs; it takes a [crypto.Signer]
// rather than a private key so a key in an HSM or KMS signs the same way as one
// in memory. ES256 is the only algorithm, so the key must be P-256.
//
// An invalid config is refused: a document that will not validate in the wallet
// should not get a signature.
func Sign(config *Config, key crypto.Signer, chain []*x509.Certificate) ([]byte, error) {
	if config == nil {
		return nil, errors.New("no config to sign")
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("refusing to sign an invalid config:\n%w", err)
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("encode config: %v", err)
	}
	return signPayload(payload, key, chain)
}

// signPayload signs arbitrary bytes with the headers a config carries. Kept
// below Sign so that the only way to sign something that is not a valid config
// is deliberately, from a test.
func signPayload(payload []byte, key crypto.Signer, chain []*x509.Certificate) ([]byte, error) {
	if key == nil {
		return nil, errors.New("no signing key")
	}
	if len(chain) == 0 {
		return nil, errors.New("no signing certificate")
	}
	publicKey, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, errors.New("ES256 needs a P-256 key")
	}
	if !publicKey.Equal(chain[0].PublicKey) {
		return nil, errors.New("signing key does not match the leaf certificate")
	}

	headers, err := protectedHeaders(Typ, chain)
	if err != nil {
		return nil, err
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, fmt.Errorf("sign: %v", err)
	}
	return signed, nil
}

// protectedHeaders builds `typ` and `x5c`. jwx adds `alg` itself from the key
// option.
func protectedHeaders(typ string, chain []*x509.Certificate) (jws.Headers, error) {
	x5c := &cert.Chain{}
	for _, certificate := range chain {
		if err := x5c.Add([]byte(base64.StdEncoding.EncodeToString(certificate.Raw))); err != nil {
			return nil, fmt.Errorf("build x5c: %v", err)
		}
	}
	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, typ); err != nil {
		return nil, err
	}
	if err := headers.Set(jws.X509CertChainKey, x5c); err != nil {
		return nil, err
	}
	return headers, nil
}
