package eudi

import (
	"fmt"
	"slices"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

type RelyingPartyRequestor struct {
	Requestor
	RelyingParty RelyingParty `json:"rp"`
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
	// AuthorizedQueryableAttributeSets contains the sets of attributes that the relying party is allowed to query. In the future, this will be checked by the app to authorize disclosure queries.
	AuthorizedQueryableAttributeSets []QueryableAttributeSet `json:"authorized"`
	RequestPurpose                   map[string]string       `json:"purpose"`
}

type QueryableAttributeSet struct {
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

func isQueryAuthorized(query dcql.CredentialQuery, authorizedAttributeSets []QueryableAttributeSet) error {
	for _, vctValue := range query.Meta.VctValues {
		authorizedCredential := false
		for _, authorizedSet := range authorizedAttributeSets {
			if authorizedSet.Credential == vctValue {
				authorizedCredential = true

				// Credential is authorized, validate the query claims against the attributes
				for _, claim := range query.Claims {
					if err := isSubset(vctValue, []string(claim.Path), &authorizedSet.Attributes); err != nil {
						return fmt.Errorf("credential query %v is not authorized: %v", query, err)
					}
				}
				break
			}
		}

		if !authorizedCredential {
			return fmt.Errorf("credential query is not authorized: credential %s is not in the authorized set", vctValue)
		}
	}

	return nil
}

func isSubset(vctValue string, subset []string, superset *[]string) error {
	for _, s := range subset {
		if !slices.Contains(*superset, s) {
			return fmt.Errorf("requested attribute %s.%v is not in the authorized set", vctValue, s)
		}
	}
	return nil
}
