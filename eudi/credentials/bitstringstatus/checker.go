package bitstringstatus

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

const (
	// ListCredentialType is the `type` a status list credential carries next to
	// VerifiableCredential (W3C §2.2).
	ListCredentialType = "BitstringStatusListCredential"

	// MediaTypeVcJwt is the JOSE `typ` of a JWT-secured VCDM 2.0 credential
	// (VC-JOSE-COSE §3.1.1), the one securing this package verifies.
	MediaTypeVcJwt = "vc+jwt"

	MaxBodyDefault      = 5 * 1024 * 1024
	FetchTimeoutDefault = 10 * time.Second

	// ClockSkewSeconds matches statuslist.ClockSkewSeconds.
	ClockSkewSeconds = 180
)

// VerificationContext configures a Checker. It mirrors
// statuslist.VerificationContext, so both checkers are built from the same
// wallet trust configuration.
type VerificationContext struct {
	// X509Context verifies the x5c chain of a status list credential. Nil is
	// rejected at verify time when the credential carries x5c.
	X509Context eudi_jwt.X509VerificationContext

	// Clock supplies "now" for the JWT time claims and the validity period.
	// Nil falls back to time.Now().
	Clock jwt.Clock

	AllowInsecureDidWeb bool

	// HTTPClient fetches status list credentials. Nil falls back to
	// http.DefaultClient, bounded by FetchTimeout.
	HTTPClient *http.Client

	// MaxBodyBytes caps the response body. <= 0 falls back to MaxBodyDefault.
	MaxBodyBytes int64

	// FetchTimeout bounds each request. <= 0 falls back to FetchTimeoutDefault.
	FetchTimeout time.Duration
}

// Checker dereferences and verifies BitstringStatusListCredentials. It keeps no
// cache: the wallet stores each credential's last known status, and refreshes it
// once per list in a sweep, so a cache would save nothing.
//
// A Checker is safe for concurrent use.
type Checker struct {
	ctx VerificationContext
}

func NewChecker(ctx VerificationContext) *Checker {
	return &Checker{ctx: ctx}
}

// Check fetches the entry's status list credential and returns the status value
// at the entry's index. For a revocation or suspension entry, non-zero means
// revoked or suspended.
func (c *Checker) Check(ctx context.Context, entry Entry) (uint, error) {
	subject, err := c.Fetch(ctx, entry.StatusListCredential)
	if err != nil {
		return 0, err
	}
	return Check(entry, subject)
}

// Fetch dereferences the status list credential at listURL, verifies it, and
// returns its credentialSubject. Verification is the W3C §3.2 validate
// algorithm's proof step for a vc+jwt list: a trusted signature, a valid VCDM
// document of type BitstringStatusListCredential within its validity period,
// and an `id` equal to listURL, so a valid list for another URL cannot be
// substituted.
func (c *Checker) Fetch(ctx context.Context, listURL string) (ListCredentialSubject, error) {
	raw, err := c.fetch(ctx, listURL)
	if err != nil {
		return ListCredentialSubject{}, err
	}
	document, err := c.verify(raw)
	if err != nil {
		return ListCredentialSubject{}, err
	}

	if !document.HasType(ListCredentialType) {
		return ListCredentialSubject{}, fmt.Errorf("%w: type does not include %s", ErrUnauthorized, ListCredentialType)
	}
	if id, _ := document.ID(); id != listURL {
		return ListCredentialSubject{}, fmt.Errorf("%w: id %q does not match status list url %q", ErrUnauthorized, id, listURL)
	}
	if err := document.VerifyValidityPeriod(c.now(), ClockSkewSeconds*time.Second); err != nil {
		return ListCredentialSubject{}, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	subjects, err := document.CredentialSubjects()
	if err != nil || len(subjects) != 1 {
		return ListCredentialSubject{}, fmt.Errorf("%w: a status list has exactly one credentialSubject", ErrUnauthorized)
	}
	return ParseListCredentialSubject(subjects[0])
}

func (c *Checker) fetch(ctx context.Context, listURL string) ([]byte, error) {
	httpClient := c.ctx.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	timeout := c.ctx.FetchTimeout
	if timeout <= 0 {
		timeout = FetchTimeoutDefault
	}
	maxBody := c.ctx.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = MaxBodyDefault
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrFetch, err)
	}
	req.Header.Set("Accept", "application/"+MediaTypeVcJwt)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%w: non-2xx response: %s", ErrFetch, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrFetch, err)
	}
	if int64(len(body)) > maxBody {
		return nil, fmt.Errorf("%w: response body exceeds cap (%d bytes)", ErrFetch, maxBody)
	}
	return bytes.TrimSpace(body), nil
}

// verify checks the vc+jwt signature (x5c chained to the trust anchors, or a DID
// kid) and returns the credential it secures: the JWT claims set is the VCDM
// document (VC-JOSE-COSE §3.1.1).
func (c *Checker) verify(raw []byte) (vcdm.Document, error) {
	keyProvider := eudi_jwt.NewJwtKeyProvider([]string{MediaTypeVcJwt}, c.ctx.AllowInsecureDidWeb)
	options := []jwt.ParseOption{
		jwt.WithKeyProvider(keyProvider),
		jwt.WithAcceptableSkew(ClockSkewSeconds * time.Second),
		jwt.WithVerify(true),
	}
	if c.ctx.Clock != nil {
		options = append(options, jwt.WithClock(c.ctx.Clock))
	}
	if _, err := jwt.Parse(raw, options...); err != nil {
		return nil, fmt.Errorf("%w: parse/verify: %v", ErrUnauthorized, err)
	}

	if x509KeyProvider, ok := keyProvider.InnerKeyProvider.(*eudi_jwt.X509KeyProvider); ok {
		chain, err := x509KeyProvider.GetChain()
		if err != nil {
			return nil, fmt.Errorf("%w: failed to get certificate chain: %v", ErrUnauthorized, err)
		}
		if c.ctx.X509Context == nil {
			return nil, fmt.Errorf("%w: x5c chain present but no X509VerificationContext configured", ErrUnauthorized)
		}
		if err := eudi_jwt.VerifyCertificateChain(c.ctx.X509Context, chain, nil); err != nil {
			return nil, fmt.Errorf("%w: certificate validation: %v", ErrUnauthorized, err)
		}
	}

	// The signature verified over these exact bytes, so the payload segment
	// can be read directly.
	parts := bytes.Split(raw, []byte("."))
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a compact JWS", ErrUnauthorized)
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrUnauthorized, err)
	}
	var document vcdm.Document
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrUnauthorized, err)
	}
	if err := document.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	return document, nil
}

func (c *Checker) now() time.Time {
	if c.ctx.Clock != nil {
		return c.ctx.Clock.Now()
	}
	return time.Now()
}
