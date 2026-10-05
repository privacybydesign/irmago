package scheme

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/go-errors/errors"
)

const X509SchemeExtensionOID = "2.1.123.1"

type RelyingPartyRequestor struct {
	Requestor
	RelyingParty RelyingParty `json:"rp"`
}

type AttestationProviderRequestor struct {
	Requestor
	AttestationProvider AttestationProvider `json:"ap"`
}

type Requestor struct {
	Registration string       `json:"registration"`
	Organization Organization `json:"organization"`
}

type Organization struct {
	Logo      *Logo             `json:"logo"`
	LegalName map[string]string `json:"legalName"`
}

type Logo struct {
	MimeType string `json:"mimeType"`
	Data     []byte `json:"data"`
}

type RelyingParty struct {
	// AuthorizedQueryableAttributeSets contains the sets of attributes that the relying party is allowed to query.
	AuthorizedQueryableAttributeSets []AuthorizedAttributeSet `json:"authorized"`
	RequestPurpose                   map[string]string        `json:"purpose"`
}

type AttestationProvider struct {
	// AuthorizedCredentials contains the sets of attributes that the attestation provider is allowed to issue.
	AuthorizedCredentials []AuthorizedAttributeSet `json:"authorized"`
}

type AuthorizedAttributeSet struct {
	Credential string   `json:"credential"`
	Attributes []string `json:"attributes"`
}

// CredentialQueryInfo describes the subset of a DCQL credential query
// needed for authorization validation, avoiding a direct dependency on the dcql package.
type CredentialQueryInfo struct {
	// VctValues holds the SD-JWT VC type identifiers the query accepts
	// (`vct_values`), for the dc+sd-jwt family.
	VctValues []string

	// DocTypeValue holds the ISO 18013-5 docType the query accepts
	// (`doctype_value`), for mso_mdoc. A DCQL credential query names exactly
	// one format, so a query carries either VctValues or DocTypeValue, never
	// both — read them through CredentialTypes rather than separately.
	DocTypeValue string

	// AttributeNames holds the attribute identifiers the query requests, matched
	// against AuthorizedAttributeSet.Attributes. These are names, not claim
	// paths: projecting a query's claim paths into attribute names is
	// format-specific and is the caller's job — see
	// dcql.CredentialQuery.AuthorizationAttributeNames.
	AttributeNames []string
}

// CredentialTypes returns the credential type identifiers the query accepts,
// whichever format named them. Authorization treats every format alike: the
// identifier is matched against AuthorizedAttributeSet.Credential, so the
// distinction between a vct and a docType matters only when reading the query.
func (q CredentialQueryInfo) CredentialTypes() []string {
	if q.DocTypeValue != "" {
		return []string{q.DocTypeValue}
	}
	return q.VctValues
}

// SchemeQueryValidator validates queries against the relying party's authorized attribute sets.
type SchemeQueryValidator struct {
	RelyingParty *RelyingParty
}

// ValidateCredentialQueries validates that the given credential queries are authorized
// for this relying party.
func (v *SchemeQueryValidator) ValidateCredentialQueries(queries []CredentialQueryInfo) error {
	if v.RelyingParty == nil {
		return fmt.Errorf("relying party is not set")
	}

	for _, query := range queries {
		// Fail closed on a query that names no credential type at all: with
		// nothing to match against AuthorizedAttributeSet.Credential there is
		// no way to decide whether the relying party may ask for it.
		if len(query.CredentialTypes()) == 0 {
			return errors.New("credential query identifies no credential type: neither vct_values nor doctype_value is set")
		}

		if err := isQueryAuthorized(query, v.RelyingParty.AuthorizedQueryableAttributeSets); err != nil {
			return err
		}
	}

	return nil
}

func (ap AttestationProvider) VerifySdJwtIssuance(vct string, disclosureKeys []string) error {
	return isCredentialAuthorized(vct, disclosureKeys, ap.AuthorizedCredentials)
}

func isQueryAuthorized(query CredentialQueryInfo, authorizedAttributeSets []AuthorizedAttributeSet) error {
	for _, credentialType := range query.CredentialTypes() {
		err := isCredentialAuthorized(credentialType, query.AttributeNames, authorizedAttributeSets)
		if err != nil {
			return err
		}
	}
	return nil
}

func isCredentialAuthorized(requestedCredential string, requestedAttributes []string, authorizedAttributeSets []AuthorizedAttributeSet) error {
	authorizedCredFunc := func(authorizedCredential string, requestedCredential string) bool {
		// If the requested credential is a URL, perform equality check (schemaless)
		// Make sure to check the URL scheme, as 'pbdf.abc.def' is considered a valid URL without a scheme
		parsedUrl, err := url.Parse(requestedCredential)
		if err == nil && parsedUrl.Scheme != "" {
			return authorizedCredential == requestedCredential
		} else {
			// If not, perform wildcard matching on the credential identifier parts (e.g., pbdf.issuer1.cred) to allow for more flexible authorization (Yivi scheme)
			authorizedCredentialParts := strings.Split(authorizedCredential, ".")
			requestedCredentialParts := strings.Split(requestedCredential, ".")

			for i, requestedCredentialPart := range requestedCredentialParts {
				// The requested identifier can be deeper than the authorized
				// one, and the authorized one is indexed by the requested
				// one's position — so run off its end and this panics. That
				// was reachable before only from a short scheme entry; a
				// dotted mdoc docType ("eu.europa.ec.av.1", five parts
				// against a scheme's usual three) makes it ordinary. A
				// non-wildcard authorized identifier that ran out of parts
				// never matched the longer request anyway, so this is a
				// rejection, not a new policy.
				if i >= len(authorizedCredentialParts) {
					return false
				}
				if authorizedCredentialParts[i] == "*" {
					return true
				}
				if authorizedCredentialParts[i] != requestedCredentialPart {
					return false
				}
			}
			return true
		}
	}

	authorizedCredential := false
	for _, authorizedSet := range authorizedAttributeSets {
		if authorizedCredFunc(authorizedSet.Credential, requestedCredential) {
			authorizedCredential = true

			// Credential is authorized, validate the query claims against the attributes
			if err := isSubset(requestedAttributes, authorizedSet.Attributes); err != nil {
				return fmt.Errorf("credential %v is not authorized: %v", requestedCredential, err)
			}
			break
		}
	}

	if !authorizedCredential {
		return fmt.Errorf("credential is not authorized: credential %s is not in the authorized set", requestedCredential)
	}

	return nil
}

func isSubset(subset []string, superset []string) error {
	// If the superset contains a wildcard, all subsets are authorized
	if slices.Contains(superset, "*") {
		return nil
	}

	for _, s := range subset {
		if !slices.Contains(superset, s) {
			return fmt.Errorf("requested attribute %v is not in the authorized set", s)
		}
	}
	return nil
}
