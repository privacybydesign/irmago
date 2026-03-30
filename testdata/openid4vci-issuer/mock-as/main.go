// Mock OAuth2 Authorization Server for OpenID4VCI integration tests.
//
// Implements just enough of the OAuth2/OpenID spec for the veramo-agent
// issuer to complete an authorization code flow:
//
//   - Discovery  (/.well-known/oauth-authorization-server, /.well-known/openid-configuration)
//   - Authorize  (GET /authorize) — returns an auth code immediately (no real login)
//   - Token      (POST /token)    — exchanges code for an access token
//   - Introspect (POST /introspect) — lets the issuer verify the token and recover issuer_state
//   - JWKS       (GET /jwks)       — empty key set (signatures not checked in tests)
//
// Configuration via environment:
//
//	LISTEN_ADDR  — address to bind (default 0.0.0.0:9090)
//	EXTERNAL_URL — URL the wallet/client uses to reach us (default http://localhost:9090)
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

func main() {
	addr := envOr("LISTEN_ADDR", "0.0.0.0:9090")
	externalURL := envOr("EXTERNAL_URL", "http://localhost:9090")

	server := &authorizationServer{
		externalURL: externalURL,
		authCodes:   make(map[string]codeEntry),
		tokens:      make(map[string]tokenEntry),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", server.handleDiscovery)
	mux.HandleFunc("/.well-known/openid-configuration", server.handleDiscovery)
	mux.HandleFunc("/jwks", server.handleJWKS)
	mux.HandleFunc("/authorize", server.handleAuthorize)
	mux.HandleFunc("/token", server.handleToken)
	mux.HandleFunc("/introspect", server.handleIntrospect)

	log.Printf("mock authorization server: listening on %s (external URL: %s)", addr, externalURL)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ---------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------

type codeEntry struct {
	issuerState string
	clientState string
}

type tokenEntry struct {
	issuerState string
}

type authorizationServer struct {
	externalURL string

	mu        sync.Mutex
	authCodes map[string]codeEntry
	tokens    map[string]tokenEntry
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *authorizationServer) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"issuer":                               s.externalURL,
		"authorization_endpoint":               s.externalURL + "/authorize",
		"token_endpoint":                       s.externalURL + "/token",
		"jwks_uri":                             s.externalURL + "/jwks",
		"authorization_introspection_endpoint": s.externalURL + "/introspect",
		"response_types_supported":             []string{"code"},
		"grant_types_supported":                []string{"authorization_code"},
	})
}

func (s *authorizationServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"keys": []interface{}{}})
}

func (s *authorizationServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	issuerState := r.URL.Query().Get("issuer_state")
	clientState := r.URL.Query().Get("state")

	code := randomHex()

	s.mu.Lock()
	s.authCodes[code] = codeEntry{
		issuerState: issuerState,
		clientState: clientState,
	}
	s.mu.Unlock()

	log.Printf("/authorize issuer_state=%s → code=%s", issuerState, code[:16])

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code":  code,
		"state": clientState,
	})
}

func (s *authorizationServer) handleToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	code := r.FormValue("code")

	s.mu.Lock()
	entry, ok := s.authCodes[code]
	if ok {
		delete(s.authCodes, code)
	}
	s.mu.Unlock()

	if !ok {
		log.Printf("/token invalid code=%s", code)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	token := randomHex()

	s.mu.Lock()
	s.tokens[token] = tokenEntry{issuerState: entry.issuerState}
	s.mu.Unlock()

	log.Printf("/token code=%s → token=%s", code[:16], token[:16])

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": token,
		"token_type":   "bearer",
		"expires_in":   3600,
	})
}

func (s *authorizationServer) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	// The veramo-agent sends the token as "access-token" form parameter.
	token := r.FormValue("access-token")

	s.mu.Lock()
	entry, ok := s.tokens[token]
	s.mu.Unlock()

	if !ok || token == "" {
		log.Printf("/introspect unknown token")
		writeJSON(w, http.StatusOK, map[string]interface{}{})
		return
	}

	log.Printf("/introspect token=%s → issuer_state=%s", token[:16], entry.issuerState)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user_info": map[string]interface{}{
			"sub":   "test-user",
			"email": "test@example.com",
		},
		"token_details": map[string]interface{}{
			"issuer_state": entry.issuerState,
			"active":       true,
		},
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func randomHex() string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return hex.EncodeToString(h[:])
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
