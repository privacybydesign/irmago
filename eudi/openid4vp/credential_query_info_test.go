package openid4vp

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/scheme"
)

// Regression tests for the projection feeding relying-party authorization.
// This is the seam that made mso_mdoc presentation impossible: it copied only
// vct_values (which mdoc never sets) and flattened every claim-path component
// (which for mdoc includes the namespace), so ValidateCredentialQueries refused
// every mdoc query — first for a missing vct, then for an unregistered
// "attribute" that was really a namespace.

func TestDcqlQueryToCredentialQueryInfos(t *testing.T) {
	t.Run("mdoc query maps doctype and element identifiers", func(t *testing.T) {
		query := dcql.DcqlQuery{
			Credentials: []dcql.CredentialQuery{
				{
					Id:     "av",
					Format: "mso_mdoc",
					Meta:   &dcql.Meta{DocTypeValue: "eu.europa.ec.av.1"},
					Claims: []dcql.Claim{
						{Path: []any{"eu.europa.ec.av.1", "age_over_18"}},
					},
				},
			},
		}

		infos := dcqlQueryToCredentialQueryInfos(query)

		assert.Len(t, infos, 1)
		assert.Equal(t, "eu.europa.ec.av.1", infos[0].DocTypeValue)
		assert.Empty(t, infos[0].VctValues)
		assert.Equal(t, []string{"age_over_18"}, infos[0].AttributeNames)
		assert.Equal(t, []string{"eu.europa.ec.av.1"}, infos[0].CredentialTypes(),
			"authorization must see the doctype as the credential type")
	})

	t.Run("mdoc query survives scheme authorization end to end", func(t *testing.T) {
		query := dcql.DcqlQuery{
			Credentials: []dcql.CredentialQuery{
				{
					Id:     "av",
					Format: "mso_mdoc",
					Meta:   &dcql.Meta{DocTypeValue: "eu.europa.ec.av.1"},
					Claims: []dcql.Claim{
						{Path: []any{"eu.europa.ec.av.1", "age_over_18"}},
					},
				},
			},
		}

		validator := scheme.SchemeQueryValidator{
			RelyingParty: &scheme.RelyingParty{
				AuthorizedQueryableAttributeSets: []scheme.AuthorizedAttributeSet{
					{
						Credential: "eu.europa.ec.av.1",
						Attributes: []string{"age_over_18"},
					},
				},
			},
		}

		assert.NoError(t, validator.ValidateCredentialQueries(dcqlQueryToCredentialQueryInfos(query)))
	})

	t.Run("sd-jwt query mapping is unchanged", func(t *testing.T) {
		query := dcql.DcqlQuery{
			Credentials: []dcql.CredentialQuery{
				{
					Id:     "pid",
					Format: "dc+sd-jwt",
					Meta:   &dcql.Meta{VctValues: []string{"https://vct.example.com/Cred"}},
					Claims: []dcql.Claim{
						{Path: []any{"given_name"}},
						{Path: []any{"address", "street"}},
					},
				},
			},
		}

		infos := dcqlQueryToCredentialQueryInfos(query)

		assert.Len(t, infos, 1)
		assert.Empty(t, infos[0].DocTypeValue)
		assert.Equal(t, []string{"https://vct.example.com/Cred"}, infos[0].VctValues)
		assert.Equal(t, []string{"given_name", "address", "street"}, infos[0].AttributeNames)
	})

	t.Run("a query naming no credential type is still refused", func(t *testing.T) {
		query := dcql.DcqlQuery{
			Credentials: []dcql.CredentialQuery{
				{Id: "bad", Format: "mso_mdoc"}, // no meta at all
			},
		}

		validator := scheme.SchemeQueryValidator{
			RelyingParty: &scheme.RelyingParty{
				AuthorizedQueryableAttributeSets: []scheme.AuthorizedAttributeSet{
					{Credential: "*", Attributes: []string{"*"}},
				},
			},
		}

		err := validator.ValidateCredentialQueries(dcqlQueryToCredentialQueryInfos(query))
		assert.ErrorContains(t, err, "identifies no credential type")
	})
}
