package vcdm

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/piprate/json-gold/ld"
)

// baseContext is the VCDM 2.0 base context, served from memory. Its SHA-256 is
// the digest VCDM 2.0 §B.1 publishes for it.
//
//go:embed contexts/credentials-v2.jsonld
var baseContext []byte

const (
	// maxContextBytes caps a fetched context, against a host that sends an
	// endless document.
	maxContextBytes = 1 << 20
	// maxContextFetches caps the contexts one loader fetches, since a context
	// can import others.
	maxContextFetches = 10
)

// ExpandTypes returns the credential's types as JSON-LD expands them: its
// `type` values with its `@context` applied. A DCQL query's type_values name
// types this way (OpenID4VP Appendix B.1.1). A type no context defines stays as
// written.
func ExpandTypes(document Document, loader ld.DocumentLoader) ([]string, error) {
	options := ld.NewJsonLdOptions("")
	options.DocumentLoader = loader
	// Only the types are expanded, so only what decides them is passed in.
	expanded, err := ld.NewJsonLdProcessor().Expand(map[string]any{
		ContextKey: document[ContextKey],
		TypeKey:    document[TypeKey],
	}, options)
	if err != nil {
		return nil, fmt.Errorf("failed to expand the credential's types: %w", err)
	}
	if len(expanded) != 1 {
		return nil, errors.New("failed to expand the credential's types: expected one node")
	}
	node, ok := expanded[0].(map[string]any)
	if !ok {
		return nil, errors.New("failed to expand the credential's types: node is not an object")
	}
	raw, _ := node["@type"].([]any)
	types := make([]string, 0, len(raw))
	for _, t := range raw {
		s, ok := t.(string)
		if !ok {
			return nil, fmt.Errorf("failed to expand the credential's types: %v is not a string", t)
		}
		types = append(types, s)
	}
	return types, nil
}

// NewContextLoader returns a loader for ExpandTypes that serves the VCDM 2.0
// base context from memory and fetches any other context over HTTPS with
// client, at most maxContextFetches of them.
func NewContextLoader(client *http.Client) ld.DocumentLoader {
	return &contextLoader{client: client}
}

type contextLoader struct {
	client *http.Client

	mu      sync.Mutex
	fetches int
}

func (l *contextLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	if u == ContextV2 {
		document, err := ld.DocumentFromReader(bytes.NewReader(baseContext))
		if err != nil {
			return nil, err
		}
		return &ld.RemoteDocument{DocumentURL: u, Document: document}, nil
	}

	if parsed, err := url.Parse(u); err != nil || parsed.Scheme != "https" {
		return nil, fmt.Errorf("context %q is not an https URL", u)
	}
	l.mu.Lock()
	l.fetches++
	tooMany := l.fetches > maxContextFetches
	l.mu.Unlock()
	if tooMany {
		return nil, fmt.Errorf("more than %d contexts to fetch", maxContextFetches)
	}

	request, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/ld+json, application/json")
	response, err := l.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch context %q: %w", u, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("failed to fetch context %q: status %d", u, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxContextBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch context %q: %w", u, err)
	}
	if len(body) > maxContextBytes {
		return nil, fmt.Errorf("context %q exceeds %d bytes", u, maxContextBytes)
	}
	document, err := ld.DocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("context %q is not JSON: %w", u, err)
	}
	return &ld.RemoteDocument{DocumentURL: u, Document: document}, nil
}
