package jades

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jws"
)

type SignOptions struct {
	// Typ is the payload's media type. JAdES does not constrain it, so it is the
	// caller's to choose; omitted when empty.
	Typ string

	// Chain is the signing certificate then any intermediates, published in `x5c`.
	// Clause 5.1.7 accepts any of four references to the signing certificate; this
	// is the one that also lets a verifier build a chain.
	Chain []*x509.Certificate

	Key crypto.Signer

	// SignedAt becomes the claimed signing time: the signer's own word, which
	// nothing may rely on.
	SignedAt time.Time
}

// SignBaselineB signs payload as a compact JAdES Baseline B signature.
//
// Everything a verifier needs sits in the protected header and is therefore signed.
// No `crit` is produced: clause 5.1.9 requires one only alongside `sigD`, and `iat`
// is an RFC 7519 parameter rather than a JAdES-defined one.
func SignBaselineB(payload []byte, opts SignOptions) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("refusing to sign an empty payload")
	}
	if len(opts.Chain) == 0 {
		return nil, fmt.Errorf("no signing certificate given, so `x5c` would be absent and " +
			"clause 5.1.7 requires a reference to the signing certificate")
	}
	if opts.Key == nil {
		return nil, fmt.Errorf("no signing key given")
	}
	if opts.SignedAt.IsZero() {
		return nil, fmt.Errorf("no signing time given: table 1 requires a claimed signing " +
			"time at every baseline level")
	}

	alg, err := SignatureAlgorithmFor(opts.Key)
	if err != nil {
		return nil, err
	}

	// RFC 7515 x5c is standard base64, unlike everything else in a JWS.
	x5c := &cert.Chain{}
	for _, certificate := range opts.Chain {
		if err := x5c.Add([]byte(base64.StdEncoding.EncodeToString(certificate.Raw))); err != nil {
			return nil, err
		}
	}

	headers := jws.NewHeaders()
	if opts.Typ != "" {
		if err := headers.Set(jws.TypeKey, opts.Typ); err != nil {
			return nil, err
		}
	}
	if err := headers.Set(jws.X509CertChainKey, x5c); err != nil {
		return nil, err
	}
	// Unix() truncates, which is what keeps the value the whole-second integer
	// clause 5.1.11 requires.
	if err := headers.Set(IatHeader, opts.SignedAt.Unix()); err != nil {
		return nil, err
	}

	return jws.Sign(payload, jws.WithKey(alg, opts.Key, jws.WithProtectedHeaders(headers)))
}
