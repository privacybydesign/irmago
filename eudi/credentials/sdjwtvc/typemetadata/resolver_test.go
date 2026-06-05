package typemetadata

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolver_Resolve_RejectsHttpInProductionMode(t *testing.T) {
	r := NewResolver(nil)
	_, err := r.Resolve(context.Background(), "http://example.com/vct", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "http")
}

func TestResolver_Resolve_AllowsHttpInDevMode(t *testing.T) {
	srv := newDocServer(t, map[string]string{
		"/vct": `{"name": "Cred"}`,
	})
	defer srv.Close()

	r := NewResolver(srv.Client())
	parsed, err := r.Resolve(context.Background(), srv.URL+"/vct", true)
	require.NoError(t, err)
	require.Equal(t, "Cred", parsed.Name)
}

func TestResolver_Resolve_RejectsUnknownScheme(t *testing.T) {
	r := NewResolver(nil)
	_, err := r.Resolve(context.Background(), "file:///etc/passwd", true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported scheme")
}

func TestResolver_Resolve_SimpleSuccess(t *testing.T) {
	srv := newDocServer(t, map[string]string{
		"/vct": `{
			"name": "Email",
			"display": [{ "lang": "en", "name": "Email" }],
			"claims": [{ "path": ["email"] }]
		}`,
	})
	defer srv.Close()

	r := NewResolver(srv.Client())
	parsed, err := r.Resolve(context.Background(), srv.URL+"/vct", true)
	require.NoError(t, err)
	require.Equal(t, "Email", parsed.Name)
	require.Len(t, parsed.Display, 1)
	require.Len(t, parsed.Claims, 1)
}

func TestResolver_Resolve_RawDocumentCached(t *testing.T) {
	body := `{"name": "X"}`
	srv := newDocServer(t, map[string]string{"/vct": body})
	defer srv.Close()

	r := NewResolver(srv.Client())
	_, err := r.Resolve(context.Background(), srv.URL+"/vct", true)
	require.NoError(t, err)

	raw, ok := r.RawDocument(srv.URL + "/vct")
	require.True(t, ok)
	require.Equal(t, body, string(raw))
}

func TestResolver_Resolve_ExtendsChain_LeafOverridesParent(t *testing.T) {
	srv := newDocServer(t, map[string]string{
		"/parent": `{
			"name": "Parent Name",
			"display": [{ "lang": "en", "name": "Parent Display" }],
			"claims": [{ "path": ["parent_claim"] }]
		}`,
		"/child": `{}`,
	})
	defer srv.Close()

	// Patch the child doc to point at the parent.
	srv.docs["/child"] = `{
		"name": "Child Name",
		"display": [{ "lang": "en", "name": "Child Display" }],
		"extends": "` + srv.URL + `/parent"
	}`

	r := NewResolver(srv.Client())
	parsed, err := r.Resolve(context.Background(), srv.URL+"/child", true)
	require.NoError(t, err)

	// Child overrides parent for set fields.
	require.Equal(t, "Child Name", parsed.Name)
	require.Equal(t, "Child Display", parsed.Display[0].Name)
	// Parent fills in claims since child didn't override.
	require.Len(t, parsed.Claims, 1)
	require.Equal(t, []any{"parent_claim"}, []any(parsed.Claims[0].Path))
}

func TestResolver_Resolve_ExtendsChain_CycleDetected(t *testing.T) {
	srv := newDocServer(t, map[string]string{})
	defer srv.Close()
	srv.docs["/a"] = `{"name":"A","extends":"` + srv.URL + `/b"}`
	srv.docs["/b"] = `{"name":"B","extends":"` + srv.URL + `/a"}`

	r := NewResolver(srv.Client())
	_, err := r.Resolve(context.Background(), srv.URL+"/a", true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cycle")
}

func TestResolver_Resolve_ExtendsChain_DepthLimit(t *testing.T) {
	srv := newDocServer(t, map[string]string{})
	defer srv.Close()
	// Build a chain that's deeper than the cap.
	for i := 0; i <= DefaultMaxExtendsDepth+1; i++ {
		path := fmt.Sprintf("/d%d", i)
		next := fmt.Sprintf("%s/d%d", srv.URL, i+1)
		srv.docs[path] = fmt.Sprintf(`{"name":"d%d","extends":"%s"}`, i, next)
	}
	// Terminate the chain past the limit with a doc that has no extends.
	srv.docs[fmt.Sprintf("/d%d", DefaultMaxExtendsDepth+2)] = `{"name":"terminal"}`

	r := NewResolver(srv.Client())
	_, err := r.Resolve(context.Background(), srv.URL+"/d0", true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "depth")
}

func TestResolver_Resolve_ExtendsIntegrity_Matches(t *testing.T) {
	parentBody := `{"name":"Parent"}`
	parentHash := sha256.Sum256([]byte(parentBody))
	parentIntegrity := "sha256-" + base64.StdEncoding.EncodeToString(parentHash[:])

	srv := newDocServer(t, map[string]string{})
	defer srv.Close()
	srv.docs["/parent"] = parentBody
	srv.docs["/child"] = fmt.Sprintf(`{"name":"Child","extends":"%s/parent","extends#integrity":"%s"}`, srv.URL, parentIntegrity)

	r := NewResolver(srv.Client())
	parsed, err := r.Resolve(context.Background(), srv.URL+"/child", true)
	require.NoError(t, err)
	require.Equal(t, "Child", parsed.Name)
}

func TestResolver_Resolve_ExtendsIntegrity_Mismatch(t *testing.T) {
	srv := newDocServer(t, map[string]string{})
	defer srv.Close()
	srv.docs["/parent"] = `{"name":"Parent"}`
	srv.docs["/child"] = fmt.Sprintf(`{"name":"Child","extends":"%s/parent","extends#integrity":"sha256-aGVsbG8="}`, srv.URL)

	r := NewResolver(srv.Client())
	_, err := r.Resolve(context.Background(), srv.URL+"/child", true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "integrity")
}

func TestVerifyIntegrity_Match(t *testing.T) {
	body := []byte(`{"x":1}`)
	hash := sha256.Sum256(body)
	intg := "sha256-" + base64.StdEncoding.EncodeToString(hash[:])
	require.NoError(t, VerifyIntegrity(body, intg))
}

func TestVerifyIntegrity_Match_Sha384(t *testing.T) {
	body := []byte(`{"x":1}`)
	hash := sha512.Sum384(body)
	intg := "sha384-" + base64.StdEncoding.EncodeToString(hash[:])
	require.NoError(t, VerifyIntegrity(body, intg))
}

func TestVerifyIntegrity_Match_Sha512(t *testing.T) {
	body := []byte(`{"x":1}`)
	hash := sha512.Sum512(body)
	intg := "sha512-" + base64.StdEncoding.EncodeToString(hash[:])
	require.NoError(t, VerifyIntegrity(body, intg))
}

func TestVerifyIntegrity_Mismatch(t *testing.T) {
	require.Error(t, VerifyIntegrity([]byte(`{"x":1}`), "sha256-aGVsbG8="))
}

func TestVerifyIntegrity_UnsupportedAlgorithm(t *testing.T) {
	err := VerifyIntegrity([]byte(`{"x":1}`), "sha1-aGVsbG8=")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported")
}

func TestVerifyIntegrity_MalformedString(t *testing.T) {
	require.Error(t, VerifyIntegrity([]byte(`{}`), "no-dash-here"))
}

// --- helpers ---

type docServer struct {
	*httptest.Server
	docs map[string]string
}

func newDocServer(t *testing.T, docs map[string]string) *docServer {
	t.Helper()
	if docs == nil {
		docs = map[string]string{}
	}
	ds := &docServer{docs: docs}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, ok := ds.docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	ds.Server = httptest.NewServer(mux)
	return ds
}
