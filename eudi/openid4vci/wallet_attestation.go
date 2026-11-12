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

// WalletAttester supplies the client attestation (PAR and token) and the key
// attestations (`jwt` proofs) a wallet presents to a Credential Issuer.
type WalletAttester interface {
	// ClientAttestation is used for one session; nil runs it without attestation.
	ClientAttestation(credentialIssuer string) (*ClientAttestation, error)

	// KeyAttestation returns "" when key cannot be attested.
	KeyAttestation(credentialIssuer string, key *ecdsa.PublicKey, nonce *string) (string, error)
}

// ClientAttestation is a client attestation JWT and its `cnf` key, which signs
// the attestation PoP and DPoP proofs.
type ClientAttestation struct {
	JWT string
	// ClientID is the attestation's `sub`.
	ClientID string
	Key      *ecdsa.PublicKey
	// Sign signs with Key's private half, which can live outside this process.
	Sign proofs.ES256SignFunc
}

// SetWalletAttester applies to sessions started after it.
func (client *Client) SetWalletAttester(attester WalletAttester) {
	client.walletAttester = attester
}

type sessionAttestation struct {
	attester         WalletAttester
	client           *ClientAttestation
	credentialIssuer string

	dpopBoundToken bool

	mu         sync.Mutex
	dpopNonces map[string]string // endpoint -> last DPoP-Nonce it sent
}

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

// audience is the authorization server's issuer identifier.
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

func (a *sessionAttestation) keyAttester(nonce *string) func(*ecdsa.PublicKey) (string, error) {
	return func(key *ecdsa.PublicKey) (string, error) {
		return a.attester.KeyAttestation(a.credentialIssuer, key, nonce)
	}
}

// postWithDPoPRetry retries once when the server asks for a DPoP nonce.
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

// RFC 9449 §8 (JSON body) and §9 (WWW-Authenticate).
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

// RFC 9449 §4.2: without query and fragment.
func dpopHTU(u *url.URL) string {
	c := *u
	c.RawQuery, c.Fragment, c.RawFragment = "", "", ""
	return c.String()
}

func randomJTI() string {
	return rand.Text()
}
