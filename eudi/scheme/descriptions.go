package scheme

import (
	"fmt"
	"slices"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
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
	Logo      Logo              `json:"logo"`
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

// SchemeQueryValidator validates queries against the relying party's authorized attribute sets.
// SchemeQueryValidator implements eudi/openid4vp/dcql/QueryValidator interface.
type SchemeQueryValidator struct {
	RelyingParty *RelyingParty
}

func (v *SchemeQueryValidator) ValidateQuery(query *dcql.DcqlQuery) error {
	if v.RelyingParty == nil {
		return fmt.Errorf("relying party is not set")
	}

	// Validate the query against the relying party's authorized attribute sets
	for _, query := range query.Credentials {
		// TODO: validate `id` is correctly formatted and is present once in the query
		// TODO: validate `format` is present and valid
		// TODO: validate `meta` is present and valid

		if len(query.Meta.VctValues) == 0 {
			return errors.New("credential query is missing vct_values")
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

func isQueryAuthorized(query dcql.CredentialQuery, authorizedAttributeSets []AuthorizedAttributeSet) error {
	allPaths := slices.Collect(query.AllClaimPaths())
	for _, vctValue := range query.Meta.VctValues {
		err := isCredentialAuthorized(vctValue, allPaths, authorizedAttributeSets)
		if err != nil {
			return err
		}
	}
	return nil
}

func isCredentialAuthorized(requestedCredential string, requestedAttributes []string, authorizedAttributeSets []AuthorizedAttributeSet) error {
	authorizedCredential := false
	for _, authorizedSet := range authorizedAttributeSets {
		if authorizedSet.Credential == requestedCredential {
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
	for _, s := range subset {
		if !slices.Contains(superset, s) {
			return fmt.Errorf("requested attribute %v is not in the authorized set", s)
		}
	}
	return nil
}
