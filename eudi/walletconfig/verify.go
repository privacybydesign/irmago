package walletconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

// Verified is a wallet config whose signature held against an environment's
// root, together with the bytes that held. Only a Verified ever reaches the
// store or the in-memory state: a Config on its own is something anyone could
// have written.
type Verified struct {
	Config *Config

	// Raw is exactly the document that verified. It is what the store keeps, so
	// a persisted config is re-verified against the root in force when read.
	Raw []byte

	// Signer is the end-entity certificate the signature verified with.
	Signer *x509.Certificate
}

// Verify checks a signed wallet config for env, at the moment now:
//
//  1. exactly one signature, `typ` is [Typ], `alg` is ES256, no critical
//     header parameters;
//  2. the `x5c` chain validates to env's signing root — and only that root, so
//     nothing an issuer or verifier CA issued can sign a config — with the
//     digitalSignature key usage on the leaf;
//  3. the signature holds under the leaf's key;
//  4. the payload is a valid [Config] declaring env's name.
//
// The config's own time bounds are not checked: an expired config is still a
// genuine one, and the [Manager] reports its freshness separately so a fetch
// failure and an expiry can be told apart.
func Verify(raw []byte, env Environment, now time.Time) (*Verified, error) {
	if env.SigningRoot == nil {
		return nil, fmt.Errorf("environment %q has no signing root", env.Name)
	}

	message, err := jws.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse JWS: %v", err)
	}
	signatures := message.Signatures()
	if len(signatures) != 1 {
		// jws.Verify accepts a document as soon as any one signature holds.
		return nil, fmt.Errorf("expected exactly one signature, got %d", len(signatures))
	}
	protected := signatures[0].ProtectedHeaders()

	if typ, ok := protected.Type(); !ok || typ != Typ {
		return nil, fmt.Errorf("typ is %q, expected %q", typ, Typ)
	}
	if alg, ok := protected.Algorithm(); !ok || alg != jwa.ES256() {
		return nil, fmt.Errorf("alg is %q, expected %s", alg, jwa.ES256())
	}
	// No critical extension is understood here, so declaring one cannot be
	// honoured and must be refused (RFC 7515 §4.1.11).
	if crit, ok := protected.Critical(); ok && len(crit) > 0 {
		return nil, fmt.Errorf("unsupported critical header parameters %v", crit)
	}

	chain, err := certificateChain(protected)
	if err != nil {
		return nil, err
	}
	leaf := chain[0]
	if err := verifySigningChain(leaf, chain[1:], env.SigningRoot, now); err != nil {
		return nil, fmt.Errorf("signing certificate: %v", err)
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, errors.New("signing certificate does not carry a P-256 key, which ES256 requires")
	}

	payload, err := jws.Verify(raw,
		jws.WithKey(jwa.ES256(), publicKey),
		jws.WithCritValidation(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verify signature: %v", err)
	}

	var config Config
	if err := json.Unmarshal(payload, &config); err != nil {
		return nil, fmt.Errorf("decode payload: %v", err)
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config:\n%w", err)
	}
	if config.Environment != env.Name {
		return nil, fmt.Errorf("config is for environment %q, expected %q", config.Environment, env.Name)
	}

	return &Verified{Config: &config, Raw: slices.Clone(raw), Signer: leaf}, nil
}

// certificateChain decodes `x5c`: leaf first, then any intermediates, as
// RFC 7515 §4.1.6 orders them.
func certificateChain(protected jws.Headers) ([]*x509.Certificate, error) {
	x5c, ok := protected.X509CertChain()
	if !ok || x5c == nil || x5c.Len() == 0 {
		return nil, errors.New("missing x5c header")
	}
	chain := make([]*x509.Certificate, 0, x5c.Len())
	for i := range x5c.Len() {
		encoded, _ := x5c.Get(i)
		der, err := base64.StdEncoding.DecodeString(string(encoded))
		if err != nil {
			return nil, fmt.Errorf("x5c[%d]: not base64: %v", i, err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("x5c[%d]: not a DER certificate: %v", i, err)
		}
		chain = append(chain, certificate)
	}
	return chain, nil
}

// verifySigningChain builds the chain from leaf through the presented
// intermediates to root, and root alone. The shared certificate check also
// requires the digitalSignature key usage on the leaf.
func verifySigningChain(leaf *x509.Certificate, intermediates []*x509.Certificate, root *x509.Certificate, now time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediatePool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		intermediatePool.AddCert(intermediate)
	}
	context := &eudi_jwt.StaticVerificationContext{
		VerifyOpts: x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediatePool,
			CurrentTime:   now,
			// Extended key usage is not constrained on a config signer; the key
			// usage that matters (digitalSignature) is checked by VerifyCertificate.
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		},
	}
	return eudi_jwt.VerifyCertificate(context, leaf, nil)
}
