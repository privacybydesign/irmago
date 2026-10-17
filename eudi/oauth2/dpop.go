package oauth2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/eudi/internal/httpext"
)

// TokenTypeDPoP is the token_type of an access token bound to a DPoP key
// (RFC 9449 §5), and the Authorization scheme it is presented with.
const TokenTypeDPoP = "DPoP"

// errorUseDPoPNonce is the error a server answers with when a DPoP proof must
// carry a nonce it issued (RFC 9449 §8, §9).
const errorUseDPoPNonce = "use_dpop_nonce"

// SupportsDPoP reports whether the authorization server binds access tokens to
// DPoP keys with an algorithm this wallet signs with (ES256).
func (as *AuthorizationServerMetadata) SupportsDPoP() bool {
	return slices.Contains(as.DPoPSigningAlgValuesSupported, "ES256")
}

// DPoP holds the key an issuance session binds its access tokens to, and the
// nonces the servers of that session handed out (RFC 9449).
//
// The key is a software key, fresh for every issuance session and never
// stored: a DPoP key only has to outlive the access token it binds, which dies
// with the session, and a fresh one per session gives issuers nothing to
// recognise the wallet by across sessions. It is deliberately not the key a
// wallet instance attestation binds, even where an authorization server would
// accept one key for both (the attestation draft's "combined mode"), so that
// neither mechanism's proofs can stand in for the other's.
//
// A nil *DPoP is valid and means the session does not use DPoP: Do then sends
// requests unchanged.
type DPoP struct {
	key       *ecdsa.PrivateKey
	publicJwk jwk.Key
	now       func() time.Time

	mu sync.Mutex
	// nonces are the latest DPoP-Nonce values, per server origin: the
	// authorization server and the credential issuer each keep their own.
	nonces map[string]string
}

// NewDPoP creates the DPoP state of one session, with a fresh P-256 key.
func NewDPoP() (*DPoP, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DPoP key: %w", err)
	}
	pub, err := jwk.Import[jwk.Key](&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert DPoP key to a JWK: %w", err)
	}
	return &DPoP{key: key, publicJwk: pub, now: time.Now, nonces: map[string]string{}}, nil
}

// Thumbprint returns the base64url JWK SHA-256 thumbprint of the DPoP key
// (RFC 7638), the dpop_jkt authorization request parameter that binds an
// authorization code to the key when there is no PAR request to carry a proof
// (RFC 9449 §10).
func (d *DPoP) Thumbprint() (string, error) {
	tp, err := d.publicJwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to compute DPoP key thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// Proof returns a DPoP proof for one request (RFC 9449 §4.2). accessToken is
// empty for requests to the authorization server; for a request presenting an
// access token, the proof carries the token's hash.
func (d *DPoP) Proof(method string, target *url.URL, accessToken string) (string, error) {
	htu := *target
	htu.RawQuery, htu.Fragment, htu.RawFragment = "", "", ""
	if htu.Path == "" {
		// Servers compare htu after RFC 3986 normalization, which makes an
		// empty path "/", and that is the path they received.
		htu.Path, htu.RawPath = "/", ""
	}

	builder := jwt.NewBuilder().
		JwtID(uuid.NewString()).
		IssuedAt(d.now()).
		Claim("htm", method).
		Claim("htu", htu.String())
	if nonce := d.nonce(target); nonce != "" {
		builder = builder.Claim("nonce", nonce)
	}
	if accessToken != "" {
		ath := sha256.Sum256([]byte(accessToken))
		builder = builder.Claim("ath", base64.RawURLEncoding.EncodeToString(ath[:]))
	}
	token, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("failed to build DPoP proof: %w", err)
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, "dpop+jwt"); err != nil {
		return "", err
	}
	if err := headers.Set(jws.JWKKey, d.publicJwk); err != nil {
		return "", err
	}
	proof, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), d.key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("failed to sign DPoP proof: %w", err)
	}
	return string(proof), nil
}

// Do sends the request newRequest builds, with a DPoP proof, through client.
// It remembers the DPoP-Nonce the server returns, and when the server refuses
// the proof for lacking a nonce it has just supplied, it builds the request
// again and retries once. newRequest is called once per attempt, so it must
// return a request with a fresh body.
//
// On a nil *DPoP, Do sends the request without a proof.
func (d *DPoP) Do(client *http.Client, accessToken string, newRequest func() (*http.Request, error)) (*http.Response, error) {
	if d == nil {
		req, err := newRequest()
		if err != nil {
			return nil, err
		}
		return client.Do(req)
	}

	for attempt := 0; ; attempt++ {
		req, err := newRequest()
		if err != nil {
			return nil, err
		}
		sentNonce := d.nonce(req.URL)
		proof, err := d.Proof(req.Method, req.URL, accessToken)
		if err != nil {
			return nil, err
		}
		req.Header.Set("DPoP", proof)

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		d.ObserveNonce(resp)

		if attempt > 0 || d.nonce(req.URL) == sentNonce {
			return resp, nil
		}
		demanded, err := demandsNonce(resp)
		if err != nil {
			resp.Body.Close()
			return nil, err
		}
		if !demanded {
			return resp, nil
		}
		resp.Body.Close()
	}
}

// ObserveNonce remembers the DPoP-Nonce of a response, if it has one. Do calls
// it for the requests it sends; call it for a response to a request sent
// without a proof, such as the credential issuer's nonce endpoint, which may
// hand out the DPoP nonce for the credential endpoint (OpenID4VCI 1.0 §7.2).
func (d *DPoP) ObserveNonce(resp *http.Response) {
	if d == nil || resp == nil || resp.Request == nil {
		return
	}
	nonce := resp.Header.Get("DPoP-Nonce")
	if nonce == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nonces[origin(resp.Request.URL)] = nonce
}

func (d *DPoP) nonce(target *url.URL) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.nonces[origin(target)]
}

func origin(u *url.URL) string {
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// demandsNonce reports whether a response refuses a DPoP proof for lacking a
// server nonce: an authorization server says so in a 400 error body (RFC 9449
// §8), a resource server in a 401 WWW-Authenticate challenge (§9). A body it
// reads is put back, so the caller can still read it.
func demandsNonce(resp *http.Response) (bool, error) {
	switch resp.StatusCode {
	case http.StatusBadRequest:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("failed to read error response: %w", err)
		}
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		var errResponse ErrorResponse
		if json.Unmarshal(body, &errResponse) != nil {
			return false, nil
		}
		return errResponse.Error == errorUseDPoPNonce, nil
	case http.StatusUnauthorized:
		challenges, err := httpext.ParseWWWAuthenticate(resp.Header.Get("WWW-Authenticate"))
		if err != nil {
			return false, nil
		}
		for _, c := range challenges {
			if strings.EqualFold(c.Scheme, TokenTypeDPoP) && c.Params["error"] == errorUseDPoPNonce {
				return true, nil
			}
		}
	}
	return false, nil
}
