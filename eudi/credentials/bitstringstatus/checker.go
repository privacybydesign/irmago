package bitstringstatus

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/utils"
)

const (
	// ListCredentialType is the `type` a status list credential carries next to
	// VerifiableCredential (W3C §2.2).
	ListCredentialType = "BitstringStatusListCredential"

	// MediaTypeVcJwt is the JOSE `typ` of a JWT-secured VCDM 2.0 credential
	// (VC-JOSE-COSE §3.1.1).
	MediaTypeVcJwt = "vc+jwt"
	// MediaTypeVcSdJwt is the JOSE `typ` of an SD-JWT-secured VCDM 2.0
	// credential (VC-JOSE-COSE §3.2), as vcdmsdjwt.MediaTypeVcSdJwt, which this
	// package cannot import. A status list may be secured either way: W3C §3.6
	// has an issuer secure it as it secures the credentials that point to it.
	MediaTypeVcSdJwt = "vc+sd-jwt"

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
// revoked or suspended. issuer is the `issuer` of the credential carrying the
// entry; see Fetch.
func (c *Checker) Check(ctx context.Context, entry Entry, issuer string) (uint, error) {
	subject, err := c.Fetch(ctx, entry.StatusListCredential, issuer)
	if err != nil {
		return 0, err
	}
	return Check(entry, subject)
}

// Fetch dereferences the status list credential at listURL, verifies it, and
// returns its credentialSubject. Verification is the W3C §3.2 validate
// algorithm's proof step for a vc+jwt or vc+sd-jwt list: a trusted signature,
// a valid VCDM document of type BitstringStatusListCredential within its
// validity period,
// and, when it has an `id`, one equal to listURL, so a valid list for another
// URL cannot be substituted. W3C §2.2 makes the `id` optional, so a list
// without one is accepted.
//
// The list must also come from issuer, the issuer of the credential that points
// to it: its `issuer` equals issuer, a JWT `iss` equals that `issuer`
// (VC-JOSE-COSE §4.1.2), and an x5c leaf certificate names it. Otherwise any
// trusted party, or anyone with a self-certifying DID key, could publish the
// status of another issuer's credentials.
func (c *Checker) Fetch(ctx context.Context, listURL, issuer string) (ListCredentialSubject, error) {
	raw, err := c.fetch(ctx, listURL)
	if err != nil {
		return ListCredentialSubject{}, err
	}
	document, err := c.verify(raw, issuer)
	if err != nil {
		return ListCredentialSubject{}, err
	}

	if !document.HasType(ListCredentialType) {
		return ListCredentialSubject{}, fmt.Errorf("%w: type does not include %s", ErrUnauthorized, ListCredentialType)
	}
	if id, present := document[vcdm.IDKey]; present && id != listURL {
		return ListCredentialSubject{}, fmt.Errorf("%w: id %v does not match status list url %q", ErrUnauthorized, id, listURL)
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
	req.Header.Set("Accept", "application/"+MediaTypeVcJwt+", application/"+MediaTypeVcSdJwt)

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

// verify checks the signature of a vc+jwt or vc+sd-jwt list (x5c chained to
// the trust anchors, or a DID kid) and that the list was issued by issuer, and
// returns the credential it secures: the JWT claims set (VC-JOSE-COSE §3.1.1),
// with the Disclosures of an SD-JWT applied (§3.2).
func (c *Checker) verify(raw []byte, issuer string) (vcdm.Document, error) {
	// A compact JWS never contains a '~'; an SD-JWT always does.
	signed, disclosures, isSdJwt := raw, []sdjwt.EncodedDisclosure(nil), bytes.ContainsRune(raw, '~')
	typ := MediaTypeVcJwt
	if isSdJwt {
		issuerSignedJwt, encoded, _, kbJwt, err := sdjwt.SplitKb(sdjwt.SdJwtKb(raw))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
		}
		if kbJwt != nil {
			return nil, fmt.Errorf("%w: a status list carries no key binding JWT", ErrUnauthorized)
		}
		signed, disclosures, typ = []byte(issuerSignedJwt), encoded, MediaTypeVcSdJwt
	}

	keyProvider := eudi_jwt.NewJwtKeyProvider([]string{typ}, c.ctx.AllowInsecureDidWeb)
	options := []jwt.ParseOption{
		jwt.WithKeyProvider(keyProvider),
		jwt.WithAcceptableSkew(ClockSkewSeconds * time.Second),
		jwt.WithVerify(true),
	}
	if c.ctx.Clock != nil {
		options = append(options, jwt.WithClock(c.ctx.Clock))
	}
	token, err := jwt.Parse(signed, options...)
	if err != nil {
		return nil, fmt.Errorf("%w: parse/verify: %v", ErrUnauthorized, err)
	}

	var leafCert *x509.Certificate
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
		leafCert = chain[0]
	}

	document, err := c.listDocument(token, signed, disclosures)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	if err := document.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}

	listIssuer, err := document.IssuerID()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	if listIssuer != issuer {
		return nil, fmt.Errorf("%w: list issuer %q is not the credential issuer %q", ErrUnauthorized, listIssuer, issuer)
	}
	if iss, ok := token.Issuer(); ok && iss != listIssuer {
		return nil, fmt.Errorf("%w: JWT iss %q does not match list issuer %q", ErrUnauthorized, iss, listIssuer)
	}
	// A DID key is the key of the DID it was resolved from: `iss`, or, without
	// `iss`, the DID of an absolute kid. That DID must be the issuer.
	if didKeyProvider, ok := keyProvider.InnerKeyProvider.(*eudi_jwt.DidKeyProvider); ok && didKeyProvider.SignerDid != listIssuer {
		return nil, fmt.Errorf("%w: signed with a key of %q, not of the list issuer %q", ErrUnauthorized, didKeyProvider.SignerDid, listIssuer)
	}
	if leafCert != nil {
		if err := utils.VerifyCertificateUri(leafCert, listIssuer); err != nil {
			return nil, fmt.Errorf("%w: list issuer %q is not a SAN of the signing certificate: %v", ErrUnauthorized, listIssuer, err)
		}
	}
	return document, nil
}

// listDocument returns the VCDM document a verified list token secures: its
// claims set, with the Disclosures of an SD-JWT applied and their disclosed
// time claims checked as the signed ones are (RFC 9901 §7.1 step 6).
func (c *Checker) listDocument(token jwt.Token, signed []byte, disclosures []sdjwt.EncodedDisclosure) (vcdm.Document, error) {
	// The signature verified over these exact bytes, so the payload segment
	// can be read directly.
	parts := bytes.Split(signed, []byte("."))
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("payload: %v", err)
	}
	if disclosures == nil {
		return vcdm.Document(claims), nil
	}

	registered, err := sdjwt.ExtractRegisteredClaims(token)
	if err != nil {
		return nil, err
	}
	processed, _, err := sdjwt.VerifyAndProcessDisclosures(registered.SdAlg, &claims, disclosures)
	if err != nil {
		return nil, err
	}
	if err := registered.AddDisclosedClaims(processed); err != nil {
		return nil, err
	}
	if err := registered.VerifyTimes(c.now(), ClockSkewSeconds*time.Second); err != nil {
		return nil, err
	}
	return vcdm.Document(processed), nil
}

func (c *Checker) now() time.Time {
	if c.ctx.Clock != nil {
		return c.ctx.Clock.Now()
	}
	return time.Now()
}
