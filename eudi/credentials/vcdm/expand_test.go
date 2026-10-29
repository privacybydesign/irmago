package vcdm

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const vcIri = "https://www.w3.org/2018/credentials#VerifiableCredential"

// contextServer serves a JSON-LD context at /context and counts the requests.
func contextServer(t *testing.T, body string, status int) (*httptest.Server, *int) {
	t.Helper()
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server, &requests
}

// The base context is served from memory: VerifiableCredential expands to its
// IRI, and a type no context defines stays as written (OpenID4VP B.1.1).
func TestExpandTypes_BaseContext(t *testing.T) {
	failing := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("no network in this test")
	})}
	types, err := ExpandTypes(Document{
		ContextKey: []any{ContextV2},
		TypeKey:    []any{TypeVerifiableCredential, "TestVcdmCredential"},
	}, NewContextLoader(failing))
	require.NoError(t, err)
	require.Equal(t, []string{vcIri, "TestVcdmCredential"}, types)
}

func TestExpandTypes_InlineContext(t *testing.T) {
	types, err := ExpandTypes(Document{
		ContextKey: []any{ContextV2, map[string]any{"ex": "https://example.org/vocab#", "Diploma": "ex:Diploma"}},
		TypeKey:    []any{TypeVerifiableCredential, "Diploma", "ex:Other"},
	}, NewContextLoader(http.DefaultClient))
	require.NoError(t, err)
	require.Equal(t, []string{vcIri, "https://example.org/vocab#Diploma", "https://example.org/vocab#Other"}, types)
}

func TestExpandTypes_FetchedContext(t *testing.T) {
	server, requests := contextServer(t, `{"@context": {"Diploma": "https://example.org/vocab#Diploma"}}`, http.StatusOK)
	types, err := ExpandTypes(Document{
		ContextKey: []any{ContextV2, server.URL + "/context"},
		TypeKey:    []any{TypeVerifiableCredential, "Diploma"},
	}, NewContextLoader(server.Client()))
	require.NoError(t, err)
	require.Equal(t, []string{vcIri, "https://example.org/vocab#Diploma"}, types)
	require.Equal(t, 1, *requests)
}

func TestExpandTypes_ContextThatCannotBeLoaded(t *testing.T) {
	notFound, _ := contextServer(t, "not here", http.StatusNotFound)
	tooLarge, _ := contextServer(t, `{"@context": {"x": "`+strings.Repeat("a", maxContextBytes)+`"}}`, http.StatusOK)

	for name, tc := range map[string]struct {
		context string
		client  *http.Client
		err     string
	}{
		"not https": {"http://example.org/context", http.DefaultClient, "is not an https URL"},
		"not found": {notFound.URL + "/context", notFound.Client(), "status 404"},
		"too large": {tooLarge.URL + "/context", tooLarge.Client(), "exceeds"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ExpandTypes(Document{
				ContextKey: []any{ContextV2, tc.context},
				TypeKey:    []any{TypeVerifiableCredential},
			}, NewContextLoader(tc.client))
			require.ErrorContains(t, err, tc.err)
		})
	}
}

func TestExpandTypes_TooManyContexts(t *testing.T) {
	server, _ := contextServer(t, `{"@context": {}}`, http.StatusOK)
	contexts := []any{ContextV2}
	for i := range maxContextFetches + 1 {
		contexts = append(contexts, fmt.Sprintf("%s/context/%d", server.URL, i))
	}
	_, err := ExpandTypes(Document{ContextKey: contexts, TypeKey: []any{TypeVerifiableCredential}}, NewContextLoader(server.Client()))
	require.ErrorContains(t, err, "contexts to fetch")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
