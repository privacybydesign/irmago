package didweb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/privacybydesign/irmago/eudi/did"
)

const Prefix = "did:web:"

// DocumentResolver resolves did:web DIDs to DID Documents by fetching them over HTTPS.
// See: https://w3c-ccg.github.io/did-method-web/
type DocumentResolver struct {
	// HTTPClient is the HTTP client used to fetch DID documents. If nil, http.DefaultClient is used.
	HTTPClient *http.Client
	// AllowInsecure additionally allows resolving did:web DIDs over HTTP when
	// the HTTPS request fails. This should only be enabled in developer mode.
	AllowInsecure bool
}

// Resolve fetches and parses the DID Document for the given did:web DID.
func (r *DocumentResolver) Resolve(didWeb string) (*did.Document, error) {
	docURL, err := didWebToURL(didWeb)
	if err != nil {
		return nil, err
	}

	doc, err := r.fetchDocument(docURL)
	if err != nil && r.AllowInsecure {
		httpURL := strings.Replace(docURL, "https://", "http://", 1)
		doc, err = r.fetchDocument(httpURL)
	}
	if err != nil {
		return nil, err
	}

	// Verify the resolved document's ID matches the requested DID.
	if doc.ID != didWeb {
		return nil, fmt.Errorf("did:web: resolved document ID %q does not match requested DID %q", doc.ID, didWeb)
	}

	return doc, nil
}

func (r *DocumentResolver) fetchDocument(docURL string) (*did.Document, error) {
	client := r.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Get(docURL)
	if err != nil {
		return nil, fmt.Errorf("did:web: failed to fetch DID document from %s: %w", docURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("did:web: unexpected HTTP status %d fetching %s", resp.StatusCode, docURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("did:web: failed to read DID document body: %w", err)
	}

	var doc did.Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("did:web: failed to parse DID document: %w", err)
	}

	return &doc, nil
}

// didWebToURL converts a did:web DID to the HTTPS URL of its DID document.
//
// Conversion rules per the did:web spec:
//  1. Strip the "did:web:" prefix.
//  2. Percent-decode the method-specific identifier.
//  3. Replace ":" path separators with "/".
//  4. If there is no explicit path, append "/.well-known/did.json".
//  5. If there is an explicit path, append "/did.json".
//  6. Prepend "https://".
func didWebToURL(didWeb string) (string, error) {
	if !strings.HasPrefix(didWeb, Prefix) {
		return "", fmt.Errorf("did:web: invalid DID, expected prefix %q: %s", Prefix, didWeb)
	}

	methodSpecificID := strings.TrimPrefix(didWeb, Prefix)
	if methodSpecificID == "" {
		return "", fmt.Errorf("did:web: empty method-specific identifier")
	}

	// Split on literal ":" before any decoding.
	// Per the spec, ports are percent-encoded (%3A) while path separators use literal ":".
	// The first segment is the (possibly percent-encoded) host[:port]; the rest are path segments.
	parts := strings.Split(methodSpecificID, ":")

	host, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", fmt.Errorf("did:web: failed to decode host %q: %w", parts[0], err)
	}

	var rawURL string
	if len(parts) == 1 {
		// No explicit path → use well-known location.
		rawURL = "https://" + host + "/.well-known/did.json"
	} else {
		// Percent-decode each path segment and join with "/".
		pathSegments := make([]string, 0, len(parts)-1)
		for _, seg := range parts[1:] {
			decoded, err := url.PathUnescape(seg)
			if err != nil {
				return "", fmt.Errorf("did:web: failed to decode path segment %q: %w", seg, err)
			}
			pathSegments = append(pathSegments, decoded)
		}
		path := strings.Join(pathSegments, "/")
		rawURL = "https://" + host + "/" + path + "/did.json"
	}

	// Validate the resulting URL.
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		return "", fmt.Errorf("did:web: resolved URL is invalid %q: %w", rawURL, err)
	}

	return rawURL, nil
}
