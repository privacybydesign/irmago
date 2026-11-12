package openid4vci

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/internal/httpext"
)

const (
	clientAttestationHeader    = "OAuth-Client-Attestation"
	clientAttestationPoPHeader = "OAuth-Client-Attestation-PoP"
	clientAttestationPoPTyp    = "oauth-client-attestation-pop+jwt"
	dpopHeader                 = "DPoP"
	dpopNonceHeader            = "DPoP-Nonce"
	dpopTyp                    = "dpop+jwt"
	dpopTokenType              = "DPoP"
	useDPoPNonceError          = "use_dpop_nonce"
)

// WalletAttester supplies the wallet (unit) attestation a wallet presents to a
// Credential Issuer: a client attestation for OAuth 2.0 Attestation-Based Client
// Authentication at PAR and token, and key attestations for the `jwt` proofs.
// A client without one sends neither, uses no DPoP, and keeps rejecting issuers
// that require key attestations.
type WalletAttester interface {
	// ClientAttestation returns a fresh client attestation for one issuance
	// session with credentialIssuer. It is used for that session only. A nil
	// attestation runs the session as if the client had no attester.
	ClientAttestation(credentialIssuer string) (*ClientAttestation, error)

	// KeyAttestation returns a key attestation JWT attesting key, for the
	// key_attestation header of the proof that key signs. An empty string means
	// the key cannot be attested and the proof goes without.
	KeyAttestation(credentialIssuer string, key *ecdsa.PublicKey, nonce *string) (string, error)
}

// ClientAttestation is a client attestation JWT plus access to its `cnf` key,
// which signs the attestation PoP and the DPoP proofs. The key can live outside
// this process.
type ClientAttestation struct {
	// JWT is the oauth-client-attestation+jwt.
	JWT string
	// ClientID is the attestation's `sub`, sent as client_id.
	ClientID string
	// Key is the public `cnf` key of the attestation.
	Key *ecdsa.PublicKey
	// Sign signs with the private half of Key.
	Sign proofs.ES256SignFunc
}

// SetWalletAttester makes every following session present wallet attestations.
// Sessions snapshot it when they start.
func (client *Client) SetWalletAttester(attester WalletAttester) {
	client.walletAttester = attester
}

// sessionAttestation is the attestation state of one session.
type sessionAttestation struct {
	attester         WalletAttester
	client           *ClientAttestation
	credentialIssuer string

	// dpopBoundToken is set when the access token is DPoP-bound, so resource
	// requests send it as a DPoP token with a proof.
	dpopBoundToken bool

	mu         sync.Mutex
	dpopNonces map[string]string // endpoint -> last DPoP-Nonce it sent
}

// newSessionAttestation returns nil when the attester has no attestation for
// this session.
func newSessionAttestation(attester WalletAttester, credentialIssuer string) (*sessionAttestation, error) {
	ca, err := attester.ClientAttestation(credentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("could not obtain client attestation: %w", err)
	}
	if ca == nil {
		return nil, nil
	}
	if ca.JWT == "" || ca.ClientID == "" || ca.Key == nil || ca.Sign == nil {
		return nil, fmt.Errorf("client attestation is incomplete")
	}
	return &sessionAttestation{
		attester:         attester,
		client:           ca,
		credentialIssuer: credentialIssuer,
		dpopNonces:       map[string]string{},
	}, nil
}

// clientID is the client_id the session authenticates as.
func (s *session) clientID() string {
	if s.attestation != nil {
		return s.attestation.client.ClientID
	}
	return YiviClientId
}

// addClientAttestation sets the client attestation and a fresh PoP for audience
// (the authorization server's issuer identifier).
func (a *sessionAttestation) addClientAttestation(req *http.Request, audience string) error {
	pop, err := a.signJWT(clientAttestationPoPTyp, nil, map[string]any{
		"iss": a.client.ClientID,
		"aud": audience,
		"jti": randomJTI(),
		"iat": time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("could not sign client attestation PoP: %w", err)
	}
	req.Header.Set(clientAttestationHeader, a.client.JWT)
	req.Header.Set(clientAttestationPoPHeader, pop)
	return nil
}

// addDPoP sets a DPoP proof for req, bound to accessToken when not empty.
func (a *sessionAttestation) addDPoP(req *http.Request, accessToken string) error {
	htu := dpopHTU(req.URL)
	claims := map[string]any{
		"jti": randomJTI(),
		"htm": req.Method,
		"htu": htu,
		"iat": time.Now().Unix(),
	}
	if nonce := a.dpopNonce(htu); nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	pub, err := jwk.Import[jwk.Key](a.client.Key)
	if err != nil {
		return fmt.Errorf("could not encode DPoP key: %w", err)
	}
	proof, err := a.signJWT(dpopTyp, map[string]any{"jwk": pub}, claims)
	if err != nil {
		return fmt.Errorf("could not sign DPoP proof: %w", err)
	}
	req.Header.Set(dpopHeader, proof)
	return nil
}

func (a *sessionAttestation) dpopNonce(htu string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dpopNonces[htu]
}

// rememberDPoPNonce keeps the DPoP-Nonce resp carries, and reports whether it
// sent one.
func (a *sessionAttestation) rememberDPoPNonce(req *http.Request, resp *http.Response) bool {
	nonce := resp.Header.Get(dpopNonceHeader)
	if nonce == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dpopNonces[dpopHTU(req.URL)] = nonce
	return true
}

func (a *sessionAttestation) signJWT(typ string, extraHeader, claims map[string]any) (string, error) {
	header := map[string]any{"alg": "ES256", "typ": typ}
	maps.Copy(header, extraHeader)
	hdr, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pl, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl)
	sig, err := a.client.Sign([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// keyAttester returns the key attestation hook for the session's proofs.
func (a *sessionAttestation) keyAttester(nonce *string) func(*ecdsa.PublicKey) (string, error) {
	return func(key *ecdsa.PublicKey) (string, error) {
		return a.attester.KeyAttestation(a.credentialIssuer, key, nonce)
	}
}

// postWithDPoPRetry sends the request newReq builds and, when the server asks
// for a DPoP nonce it did not get yet, sends a rebuilt request once more. The
// returned body is already read.
func (a *sessionAttestation) postWithDPoPRetry(httpClient *http.Client, newReq func() (*http.Request, error)) (*http.Response, []byte, error) {
	for attempt := 0; ; attempt++ {
		req, err := newReq()
		if err != nil {
			return nil, nil, err
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		gotNonce := a.rememberDPoPNonce(req, resp)
		if attempt == 0 && gotNonce && asksForDPoPNonce(resp, body) {
			continue
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, body, nil
	}
}

// asksForDPoPNonce reports a use_dpop_nonce error: in the JSON body of an
// authorization server response, or in the WWW-Authenticate challenge of a
// resource server response (RFC 9449 §8 and §9).
func asksForDPoPNonce(resp *http.Response, body []byte) bool {
	switch resp.StatusCode {
	case http.StatusBadRequest:
		var e struct {
			Error string `json:"error"`
		}
		return json.Unmarshal(body, &e) == nil && e.Error == useDPoPNonceError
	case http.StatusUnauthorized:
		challenges, err := httpext.ParseWWWAuthenticate(resp.Header.Get("WWW-Authenticate"))
		if err != nil {
			return false
		}
		for _, c := range challenges {
			for k, v := range c.Params {
				if strings.EqualFold(k, "error") && v == useDPoPNonceError {
					return true
				}
			}
		}
	}
	return false
}

// dpopHTU is the request URI without query and fragment (RFC 9449 §4.2).
func dpopHTU(u *url.URL) string {
	c := *u
	c.RawQuery, c.Fragment, c.RawFragment = "", "", ""
	return c.String()
}

func randomJTI() string {
	return rand.Text()
}
