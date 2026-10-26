package oauth2_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/oauth2"
	"github.com/privacybydesign/irmago/eudi/oauth2/dpoptest"
)

func post(url string) func() (*http.Request, error) {
	return func() (*http.Request, error) {
		return http.NewRequest(http.MethodPost, url, strings.NewReader("a=b"))
	}
}

func TestSupportsDPoP(t *testing.T) {
	require.False(t, (&oauth2.AuthorizationServerMetadata{}).SupportsDPoP())
	require.False(t, (&oauth2.AuthorizationServerMetadata{DPoPSigningAlgValuesSupported: []string{"RS256"}}).SupportsDPoP())
	require.True(t, (&oauth2.AuthorizationServerMetadata{DPoPSigningAlgValuesSupported: []string{"RS256", "ES256"}}).SupportsDPoP())
}

func TestDPoPProofsVerifyAndBindToOneKey(t *testing.T) {
	d, err := oauth2.NewDPoP()
	require.NoError(t, err)
	jkt, err := d.Thumbprint()
	require.NoError(t, err)

	var proofs []*dpoptest.Proof
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if auth := r.Header.Get("Authorization"); auth != "" {
			token = strings.TrimPrefix(auth, "DPoP ")
		}
		p, err := dpoptest.Verify(r, token, "")
		require.NoError(t, err)
		proofs = append(proofs, p)
	}))
	defer srv.Close()

	// The query is not part of htu.
	_, err = d.Do(srv.Client(), "", post(srv.URL+"/token?x=1"))
	require.NoError(t, err)
	_, err = d.Do(srv.Client(), "the-token", func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/credential", nil)
		req.Header.Set("Authorization", "DPoP the-token")
		return req, err
	})
	require.NoError(t, err)

	require.Len(t, proofs, 2)
	require.Equal(t, jkt, proofs[0].Thumbprint, "dpop_jkt is the thumbprint of the proof key")
	require.Equal(t, jkt, proofs[1].Thumbprint)
	require.NotEqual(t, proofs[0].JwtID, proofs[1].JwtID)
}

func TestDPoPSessionsHaveTheirOwnKeys(t *testing.T) {
	a, err := oauth2.NewDPoP()
	require.NoError(t, err)
	b, err := oauth2.NewDPoP()
	require.NoError(t, err)
	ta, _ := a.Thumbprint()
	tb, _ := b.Thumbprint()
	require.NotEqual(t, ta, tb)
}

// nonceServer demands a DPoP nonce the way an authorization server (a 400
// error body) or a resource server (a 401 challenge) does, and accepts proofs
// carrying it.
func nonceServer(t *testing.T, resourceServer bool, calls *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		require.Equal(t, "a=b", string(body), "a retry sends the request body again")
		if _, err := dpoptest.Verify(r, "", "server-nonce"); err != nil {
			w.Header().Set("DPoP-Nonce", "server-nonce")
			if resourceServer {
				w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", error_description="nonce required"`)
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			}
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
}

func TestDPoPRetriesOnceWithTheDemandedNonce(t *testing.T) {
	for name, resourceServer := range map[string]bool{"authorization server": false, "resource server": true} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			srv := nonceServer(t, resourceServer, &calls)
			defer srv.Close()
			d, err := oauth2.NewDPoP()
			require.NoError(t, err)

			resp, err := d.Do(srv.Client(), "", post(srv.URL))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.EqualValues(t, 2, calls.Load())

			// The nonce is remembered: the next request carries it at once.
			resp, err = d.Do(srv.Client(), "", post(srv.URL))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.EqualValues(t, 3, calls.Load())
		})
	}
}

func TestDPoPDoesNotRetryWithoutANewNonce(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
	}))
	defer srv.Close()
	d, err := oauth2.NewDPoP()
	require.NoError(t, err)

	resp, err := d.Do(srv.Client(), "", post(srv.URL))
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.EqualValues(t, 1, calls.Load(), "a nonce demand without a nonce is not retried")
}

func TestDPoPLeavesOtherErrorsReadable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", "n")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()
	d, err := oauth2.NewDPoP()
	require.NoError(t, err)

	resp, err := d.Do(srv.Client(), "", post(srv.URL))
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.JSONEq(t, `{"error":"invalid_grant"}`, string(body))
}

func TestDPoPNoncesArePerServer(t *testing.T) {
	var calls atomic.Int32
	a := nonceServer(t, false, &calls)
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := dpoptest.Verify(r, "", "")
		require.NoError(t, err)
		require.Empty(t, p.Nonce, "a nonce of one server is not sent to another")
	}))
	defer b.Close()
	d, err := oauth2.NewDPoP()
	require.NoError(t, err)

	_, err = d.Do(a.Client(), "", post(a.URL))
	require.NoError(t, err)
	_, err = d.Do(b.Client(), "", post(b.URL))
	require.NoError(t, err)
}

func TestObserveNonceAppliesToLaterRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nonce" {
			w.Header().Set("DPoP-Nonce", "from-nonce-endpoint")
			return
		}
		_, err := dpoptest.Verify(r, "", "from-nonce-endpoint")
		require.NoError(t, err)
	}))
	defer srv.Close()
	d, err := oauth2.NewDPoP()
	require.NoError(t, err)

	resp, err := srv.Client().Post(srv.URL+"/nonce", "", nil)
	require.NoError(t, err)
	d.ObserveNonce(resp)
	_, err = d.Do(srv.Client(), "", post(srv.URL+"/credential"))
	require.NoError(t, err)
}

func TestNilDPoPSendsNoProof(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Empty(t, r.Header.Get("DPoP"))
	}))
	defer srv.Close()
	var d *oauth2.DPoP
	_, err := d.Do(srv.Client(), "", post(srv.URL))
	require.NoError(t, err)
	d.ObserveNonce(&http.Response{Request: &http.Request{URL: &url.URL{}}})
}
