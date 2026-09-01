package jades

import (
	"crypto/x509"
	"fmt"
	"math"
	"time"

	"github.com/lestrrat-go/jwx/v4/jws"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

type VerifyOptions struct {
	// AllowedTyps is the acceptable `typ` values, and is required. JAdES leaves
	// `typ` unconstrained, so this is not a conformance rule but the guard that
	// stops a signature minted for one purpose standing in for another.
	AllowedTyps []string
}

type Verified struct {
	Payload []byte

	// Signer is the end-entity certificate the signature was verified with. Whether
	// it chains to anything trustworthy is the caller's to decide.
	Signer *x509.Certificate

	// ClaimedSigningTime is when the signer says it signed. Its presence is
	// required and its value proves nothing — a forger writes it too. Read it for
	// display, never for a decision.
	ClaimedSigningTime time.Time
}

// VerifyBaselineB checks a compact JAdES Baseline B signature.
//
// Enforced, from table 1: exactly one signature, `alg`, a reference to the signing
// certificate — `x5c` specifically, since a verifier that cannot build a chain
// cannot anchor anything — a claimed signing time, and `crit` honoured per RFC 7515
// clause 4.1.11.
//
// No critical extension is declared, so any `crit` is refused. This verifier reads
// no JAdES parameter's value, so it understands none, and declaring a name without
// acting on it would defeat the check rather than pass it.
func VerifyBaselineB(raw []byte, opts VerifyOptions) (*Verified, error) {
	if len(opts.AllowedTyps) == 0 {
		return nil, fmt.Errorf("no allowed `typ` values configured, so every signature would " +
			"be rejected; the caller has to state what it expects")
	}

	// Resolving the key through the shared provider rather than parsing `x5c` here
	// guarantees the certificate reported below is the one the signature was
	// verified with, and not a decorative chain beside a `kid`-resolved key.
	keyProvider := eudi_jwt.NewJwtKeyProvider(opts.AllowedTyps, false)

	// jwx defaults crit validation off, which silently ignores every critical
	// extension — the failure a producer marks them critical to prevent.
	var msg jws.Message
	payload, err := jws.Verify(raw,
		jws.WithKeyProvider(keyProvider),
		jws.WithMessage(&msg),
		jws.WithCritValidation(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verify signature: %v", err)
	}

	signatures := msg.Signatures()
	if len(signatures) != 1 {
		// Verify accepts a document as soon as any one signature holds.
		return nil, fmt.Errorf("expected exactly one signature, got %d", len(signatures))
	}

	signedAt, err := claimedSigningTime(signatures[0].ProtectedHeaders())
	if err != nil {
		return nil, err
	}

	x509KeyProvider, ok := keyProvider.InnerKeyProvider.(*eudi_jwt.X509KeyProvider)
	if !ok {
		return nil, fmt.Errorf("missing 'x5c' header")
	}
	signer := x509KeyProvider.GetCert()
	if signer == nil {
		return nil, fmt.Errorf("signature verified but no end-entity certificate was resolved")
	}

	return &Verified{Payload: payload, Signer: signer, ClaimedSigningTime: signedAt}, nil
}

// claimedSigningTime reads whichever parameter provided it. Table 1 makes the
// service mandatory and lists both as provision options; clause 5.1.11 requires
// `iat` of a generator after 2025-07-15 but never tells a validator to refuse the
// older spelling.
func claimedSigningTime(protected jws.Headers) (time.Time, error) {
	if protected.Has(IatHeader) {
		// Numbers decode to float64, so the integer requirement is checked rather
		// than obtained from the type.
		seconds, err := jws.Get[float64](protected, IatHeader)
		if err != nil {
			return time.Time{}, fmt.Errorf("`iat` is not a number: %v", err)
		}
		if seconds != math.Trunc(seconds) {
			return time.Time{}, fmt.Errorf("`iat` is %v, but clause 5.1.11 forbids fractions "+
				"of a second", seconds)
		}
		return time.Unix(int64(seconds), 0).UTC(), nil
	}

	if protected.Has(SigTHeader) {
		stamp, err := jws.Get[string](protected, SigTHeader)
		if err != nil {
			return time.Time{}, fmt.Errorf("`sigT` is not a string: %v", err)
		}
		parsed, err := time.Parse(time.RFC3339, stamp)
		if err != nil {
			return time.Time{}, fmt.Errorf("`sigT` is not an RFC 3339 date-time: %v", err)
		}
		return parsed.UTC(), nil
	}

	return time.Time{}, fmt.Errorf("no claimed signing time: neither `iat` nor `sigT` is " +
		"present, and table 1 requires one at every baseline level")
}
