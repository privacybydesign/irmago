// Package usagetest provides a fake Yivi Portal usage API for tests. It checks requests the way the
// Portal does: an ES256 flattened JWS, a single-use nonce, the request URL, and a registered key.
package usagetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/privacybydesign/irmago/irma/server/usage"
)

type Portal struct {
	*httptest.Server

	mu         sync.Mutex
	nonces     map[string]bool
	nonceCount int
	registered map[string]bool // JWK thumbprints
	keys       map[string]jwk  // by thumbprint, which is also the account ID here
	reports    []*usage.Report
	seen       map[string]bool // report IDs
	status     int
}

// SetStatus makes the Portal answer report submissions with this status instead of accepting
// them; 0 accepts them again.
func (p *Portal) SetStatus(status int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status = status
}

func NewPortal(t *testing.T) *Portal {
	p := &Portal{nonces: map[string]bool{}, registered: map[string]bool{}, keys: map[string]jwk{}, seen: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/usage/v1/directory", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   p.URL + "/usage/v1/new-nonce",
			"newAccount": p.URL + "/usage/v1/new-account",
		})
	})
	mux.HandleFunc("/usage/v1/new-nonce", func(w http.ResponseWriter, r *http.Request) {
		p.addNonce(w)
	})
	mux.HandleFunc("/usage/v1/new-account", p.handleNewAccount)
	mux.HandleFunc("/usage/v1/accounts/", p.handleReports)
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// DirectoryURL is the URL to configure as the usage reporting portal URL.
func (p *Portal) DirectoryURL() string {
	return p.URL + "/usage/v1/directory"
}

// Register makes the Portal accept the key with this JWK thumbprint.
func (p *Portal) Register(thumbprint string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.registered[thumbprint] = true
}

// Deactivate makes the Portal refuse the key with this JWK thumbprint.
func (p *Portal) Deactivate(thumbprint string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.registered, thumbprint)
}

// Reports returns the reports the Portal accepted, in order of arrival.
func (p *Portal) Reports() []*usage.Report {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*usage.Report(nil), p.reports...)
}

func (p *Portal) addNonce(w http.ResponseWriter) {
	p.mu.Lock()
	p.nonceCount++
	nonce := fmt.Sprintf("nonce-%d", p.nonceCount)
	p.nonces[nonce] = true
	p.mu.Unlock()
	w.Header().Set("Replay-Nonce", nonce)
}

func problem(w http.ResponseWriter, status int, typ string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"type": typ})
}

type jwsBody struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type header struct {
	Alg   string          `json:"alg"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	Kid   string          `json:"kid"`
	JWK   json.RawMessage `json:"jwk"`
}

type jwk struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// verify checks the JWS against the key it carries, or the key named by its kid (the kid is the
// thumbprint here), and consumes its nonce. It returns the thumbprint and the payload.
func (p *Portal) verify(w http.ResponseWriter, r *http.Request) (string, []byte, bool) {
	p.addNonce(w)
	body := jwsBody{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed")
		return "", nil, false
	}
	hdrBytes, _ := base64.RawURLEncoding.DecodeString(body.Protected)
	hdr := header{}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil || hdr.Alg != "ES256" || hdr.URL != p.URL+r.URL.Path {
		problem(w, http.StatusUnauthorized, "urn:ietf:params:acme:error:unauthorized")
		return "", nil, false
	}

	p.mu.Lock()
	validNonce := p.nonces[hdr.Nonce]
	delete(p.nonces, hdr.Nonce)
	p.mu.Unlock()
	if !validNonce {
		problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:badNonce")
		return "", nil, false
	}

	var key jwk
	if hdr.Kid != "" {
		p.mu.Lock()
		k, ok := p.keys[strings.TrimPrefix(hdr.Kid, p.URL+"/usage/v1/accounts/")]
		p.mu.Unlock()
		if !ok {
			problem(w, http.StatusForbidden, "urn:ietf:params:acme:error:accountDoesNotExist")
			return "", nil, false
		}
		key = k
	} else if err := json.Unmarshal(hdr.JWK, &key); err != nil {
		problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed")
		return "", nil, false
	}

	x, _ := base64.RawURLEncoding.DecodeString(key.X)
	y, _ := base64.RawURLEncoding.DecodeString(key.Y)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	sig, _ := base64.RawURLEncoding.DecodeString(body.Signature)
	digest := sha256.Sum256([]byte(body.Protected + "." + body.Payload))
	if err != nil || len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		problem(w, http.StatusUnauthorized, "urn:ietf:params:acme:error:unauthorized")
		return "", nil, false
	}

	canonical, _ := json.Marshal(key)
	sum := sha256.Sum256(canonical)
	thumbprint := base64.RawURLEncoding.EncodeToString(sum[:])
	p.mu.Lock()
	registered := p.registered[thumbprint]
	p.keys[thumbprint] = key
	p.mu.Unlock()
	if !registered {
		problem(w, http.StatusForbidden, "urn:ietf:params:acme:error:accountDoesNotExist")
		return "", nil, false
	}

	payload, _ := base64.RawURLEncoding.DecodeString(body.Payload)
	return thumbprint, payload, true
}

func (p *Portal) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	thumbprint, _, ok := p.verify(w, r)
	if !ok {
		return
	}
	w.Header().Set("Location", p.URL+"/usage/v1/accounts/"+thumbprint)
	w.WriteHeader(http.StatusOK)
}

func (p *Portal) handleReports(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/reports") {
		http.NotFound(w, r)
		return
	}
	_, payload, ok := p.verify(w, r)
	if !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.status != 0 {
		w.WriteHeader(p.status)
		return
	}
	report := &usage.Report{}
	if err := json.Unmarshal(payload, report); err != nil {
		problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed")
		return
	}
	if p.seen[report.ReportID] {
		w.WriteHeader(http.StatusOK)
		return
	}
	p.seen[report.ReportID] = true
	p.reports = append(p.reports, report)
	w.WriteHeader(http.StatusCreated)
}
