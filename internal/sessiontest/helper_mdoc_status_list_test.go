package sessiontest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
)

// ============================================================================
// Status list server for the EUDI Python issuer's mdocs
//
// With revocation enabled (config_issuer_backend.yaml), the Python issuer asks
// its take_url for a status list entry for every credential it signs, and puts
// the JSON it gets back into the MSO's `status` field unchanged. Its own
// companion service for this (eudi-srv-statuslist-py) hands out entries but
// does not serve the Status List Token they point at, so these tests play that
// part themselves: this server answers take, and serves the token.
//
// The issuer reaches it through the tls_proxy (https://localhost:8443/
// mdoc-status-list/ forwards to this port on the host), and so does the
// wallet, since the token uri this server hands out is under the same prefix.
// While no test runs this server, nginx answers take with a 502 and the issuer
// signs the credential without a status, which is what keeps every other test
// on the credentials it always had.
//
// The token is signed with the issuer's own document signer key, so the wallet
// trusts it through the same root it trusts the MSO through.
// ============================================================================

const (
	// mdocStatusListListenAddr must match the proxy_pass port of
	// /mdoc-status-list/ in testdata/configurations/certs/nginx-tls-proxy.conf.
	// It sits in the 48680-48699 range CI keeps out of the ephemeral port range.
	// It listens on every interface, because the proxy reaches it from a
	// container through the host gateway.
	mdocStatusListListenAddr = ":48688"

	// mdocStatusListPublicURL is where the wallet and the issuer reach this
	// server through the tls_proxy.
	mdocStatusListPublicURL = "https://localhost:8443/mdoc-status-list"
)

type mdocStatusListEncoding int

const (
	mdocStatusListCWT mdocStatusListEncoding = iota
	mdocStatusListJWT
)

// mdocStatusListServer hands out one entry per credential the issuer signs, all
// in a single status list, and serves that list as a signed Status List Token.
type mdocStatusListServer struct {
	t        *testing.T
	server   *http.Server
	signer   *statuslist.TestStatusListSigner
	encoding mdocStatusListEncoding
	listID   string

	mu sync.Mutex
	// statuses holds the value of every entry handed out so far.
	statuses map[uint64]uint8
	next     uint64
	// newStatus is the value take gives each new entry.
	newStatus uint8
	// tokenUnavailable makes the token endpoint answer 503.
	tokenUnavailable bool
	// tokenFetches counts GETs of the Status List Token.
	tokenFetches int
}

// startMdocStatusListServer starts the server for the running test and stops it
// when the test ends.
func startMdocStatusListServer(t *testing.T, encoding mdocStatusListEncoding) *mdocStatusListServer {
	t.Helper()

	key, chain := pidIssuerSigningIdentity(t)
	cert, err := x509.ParseCertificate(chain[0])
	require.NoError(t, err)

	s := &mdocStatusListServer{
		t: t,
		// The issuer's own document signer, as an issuer running its own
		// status list would use.
		signer:   &statuslist.TestStatusListSigner{PrivKey: key, Cert: cert, DERBytes: chain[0]},
		encoding: encoding,
		// A fresh list per test, so the wallet cannot be served a token it
		// cached for another test's list.
		listID:   fmt.Sprintf("%d", time.Now().UnixNano()),
		statuses: map[uint64]uint8{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /take", s.handleTake)
	mux.HandleFunc("GET /lists/{id}", s.handleToken)

	listener, err := net.Listen("tcp", mdocStatusListListenAddr)
	require.NoError(t, err, "the mdoc status list server needs port %s", mdocStatusListListenAddr)

	s.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := s.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("mdoc status list server: %v", err)
		}
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(ctx)
	})

	return s
}

// withSigner swaps the key the token is signed with, for the tests about a
// token the wallet must not trust.
func (s *mdocStatusListServer) withSigner(signer *statuslist.TestStatusListSigner) *mdocStatusListServer {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signer = signer
	return s
}

// setNewStatus sets the value take gives each entry it hands out from now on.
func (s *mdocStatusListServer) setNewStatus(status uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.newStatus = status
}

// setTokenUnavailable makes every fetch of the token fail, while take keeps
// handing out entries that point at it.
func (s *mdocStatusListServer) setTokenUnavailable() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenUnavailable = true
}

// setAll sets every entry handed out so far to status. An mdoc is issued as a
// batch with one entry per instance, so this is how a test revokes "the
// credential": whichever instance the wallet reads, it reads status.
func (s *mdocStatusListServer) setAll(status uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(s.t, s.statuses, "no entries handed out yet: did the issuer call take?")
	for idx := range s.statuses {
		s.statuses[idx] = status
	}
}

// entriesHandedOut is the number of entries take has handed out.
func (s *mdocStatusListServer) entriesHandedOut() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.statuses)
}

// tokenFetchCount is the number of times the token has been fetched.
func (s *mdocStatusListServer) tokenFetchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenFetches
}

func (s *mdocStatusListServer) listURI() string {
	return mdocStatusListPublicURL + "/lists/" + s.listID
}

// handleTake answers the Python issuer's take call (a form POST naming the
// doctype, country and expiry date) in the shape of eudi-srv-statuslist-py.
// Only the PID mdoc gets an entry; for anything else take answers 404, so the
// issuer signs that credential without a status.
// The issuer requires identifier_list to be present and copies the whole
// object into the MSO, so the credential also carries a status mechanism the
// wallet does not support, next to the status_list it does.
func (s *mdocStatusListServer) handleTake(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if r.PostForm.Get("doctype") != pidMdocDocType {
		http.NotFound(w, r)
		return
	}

	idx := s.next
	s.next++
	s.statuses[idx] = s.newStatus

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status_list": map[string]any{
			"idx": idx,
			"uri": s.listURI(),
		},
		"identifier_list": map[string]any{
			"id":  fmt.Sprintf("%d", idx),
			"uri": mdocStatusListPublicURL + "/identifiers/" + s.listID,
		},
	})
}

// handleToken serves the list as it is now, freshly signed.
func (s *mdocStatusListServer) handleToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r.PathValue("id") != s.listID {
		http.NotFound(w, r)
		return
	}
	s.tokenFetches++
	if s.tokenUnavailable {
		http.Error(w, "status list unavailable", http.StatusServiceUnavailable)
		return
	}

	opts := statuslist.TestStatusListOpts{
		Subject:  s.listURI(),
		IssuedAt: time.Now(),
		Bits:     1,
		Statuses: s.statuses,
	}

	var body []byte
	switch s.encoding {
	case mdocStatusListJWT:
		w.Header().Set("Content-Type", statuslist.StatusListTokenContentType)
		body = s.signer.SignToken(s.t, opts)
	default:
		w.Header().Set("Content-Type", statuslist.StatusListTokenCWTContentType)
		body = s.signer.SignCWTToken(s.t, opts)
	}
	_, _ = w.Write(body)
}
