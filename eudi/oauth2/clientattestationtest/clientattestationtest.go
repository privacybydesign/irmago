// Package clientattestationtest checks attestation-based client
// authentication (draft-ietf-oauth-attestation-based-client-auth) the way a
// strict authorization server would, for tests of the wallet's client.
package clientattestationtest

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/privacybydesign/irmago/walletprovider/providertest"
)

// MaxAge is how old a PoP's iat may be.
const MaxAge = time.Minute

// Result is what a verified request established.
type Result struct {
	// ClientID is the WIA's sub, which the request's client_id (when present)
	// equals.
	ClientID    string
	Attestation *providertest.InstanceAttestation
	JwtID       string
	Challenge   string
}

// Verify checks the client attestation of r: exactly one
// OAuth-Client-Attestation and one OAuth-Client-Attestation-PoP header; a WIA
// that is well formed (providertest.ParseInstanceAttestation) and chains to
// roots; a PoP with typ oauth-client-attestation-pop+jwt and alg ES256, signed
// by the WIA's cnf key, for audience, with a recent iat and a jti, and
// carrying wantChallenge when that is non-empty; and a client_id form
// parameter, when present, equal to the WIA's sub.
func Verify(r *http.Request, roots *x509.CertPool, audience, wantChallenge string) (*Result, error) {
	wias := r.Header.Values("OAuth-Client-Attestation")
	pops := r.Header.Values("OAuth-Client-Attestation-PoP")
	if len(wias) != 1 || len(pops) != 1 {
		return nil, fmt.Errorf("want one attestation and one PoP header, got %d and %d", len(wias), len(pops))
	}

	a, err := providertest.ParseInstanceAttestation([]byte(wias[0]))
	if err != nil {
		return nil, fmt.Errorf("WIA: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, c := range a.Chain[1:] {
		intermediates.AddCert(c)
	}
	if _, err := a.Chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("the WIA's chain is not trusted: %w", err)
	}

	raw := []byte(pops[0])
	msg, err := jws.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("PoP is not a JWS: %w", err)
	}
	if len(msg.Signatures()) != 1 {
		return nil, errors.New("PoP must have exactly one signature")
	}
	headers := msg.Signatures()[0].ProtectedHeaders()
	if typ, _ := headers.Type(); typ != "oauth-client-attestation-pop+jwt" {
		return nil, fmt.Errorf("PoP typ is %q", typ)
	}
	if alg, _ := headers.Algorithm(); alg != jwa.ES256() {
		return nil, fmt.Errorf("PoP alg is %v, want ES256", alg)
	}
	cnf, err := jwk.Import[jwk.Key](a.Key)
	if err != nil {
		return nil, err
	}
	pop, err := jwt.Parse(raw, jwt.WithKey(jwa.ES256(), cnf), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("PoP is not signed by the WIA's cnf key: %w", err)
	}

	aud, _ := pop.Audience()
	if len(aud) != 1 || aud[0] != audience {
		return nil, fmt.Errorf("PoP aud is %v, want %q", aud, audience)
	}
	iat, ok := pop.IssuedAt()
	if !ok || time.Since(iat) > MaxAge || time.Until(iat) > MaxAge {
		return nil, fmt.Errorf("PoP iat %v is missing or not recent", iat)
	}
	jti, _ := pop.JwtID()
	if jti == "" {
		return nil, errors.New("PoP has no jti")
	}
	challenge, _ := jwt.Get[string](pop, "challenge")
	if wantChallenge != "" && challenge != wantChallenge {
		return nil, fmt.Errorf("PoP challenge is %q, want %q", challenge, wantChallenge)
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	if id := r.PostForm.Get("client_id"); id != "" && id != a.Subject {
		return nil, fmt.Errorf("client_id %q is not the WIA's sub %q", id, a.Subject)
	}
	return &Result{ClientID: a.Subject, Attestation: a, JwtID: jti, Challenge: challenge}, nil
}
