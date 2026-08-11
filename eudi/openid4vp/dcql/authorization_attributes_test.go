package dcql

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Regression tests for the format-aware projection of a credential query into
// the credential type and attribute names that relying-party authorization
// consumes. Getting either wrong rejected every mso_mdoc query outright: the
// credential type came only from vct_values, which mdoc never sets, and the
// attribute names came from every string component of every claim path, which
// for mdoc includes the namespace.

func TestDocTypeValue(t *testing.T) {
	t.Run("mdoc query exposes its doctype", func(t *testing.T) {
		query := CredentialQuery{
			Format: "mso_mdoc",
			Meta:   &Meta{DocTypeValue: "eu.europa.ec.av.1"},
		}
		assert.Equal(t, "eu.europa.ec.av.1", query.DocTypeValue())
		assert.Empty(t, query.VctValues(), "an mdoc query names no vct")
	})

	t.Run("sd-jwt query exposes no doctype", func(t *testing.T) {
		query := CredentialQuery{
			Format: "dc+sd-jwt",
			Meta:   &Meta{VctValues: []string{"https://vct.example.com/Cred"}},
		}
		assert.Empty(t, query.DocTypeValue())
		assert.Equal(t, []string{"https://vct.example.com/Cred"}, query.VctValues())
	})

	t.Run("query without meta is safe to read", func(t *testing.T) {
		query := CredentialQuery{Format: "mso_mdoc"}
		assert.Empty(t, query.DocTypeValue())
		assert.Empty(t, query.VctValues())
	})
}

func TestAuthorizationAttributeNames(t *testing.T) {
	t.Run("mdoc contributes only the element identifier, never the namespace", func(t *testing.T) {
		query := CredentialQuery{
			Format: "mso_mdoc",
			Meta:   &Meta{DocTypeValue: "eu.europa.ec.av.1"},
			Claims: []Claim{
				{Path: []any{"eu.europa.ec.av.1", "age_over_18"}},
				{Path: []any{"eu.europa.ec.av.1", "age_over_21"}},
			},
		}

		names := query.AuthorizationAttributeNames()

		assert.Equal(t, []string{"age_over_18", "age_over_21"}, names)
		assert.NotContains(t, names, "eu.europa.ec.av.1",
			"the namespace is a container, not an attribute a relying party registers")
	})

	t.Run("mdoc path of the wrong shape contributes nothing", func(t *testing.T) {
		// mdoc_dcql's claim matching applies the same two-component check, so a
		// path this shape can never yield a candidate — contributing no name
		// cannot smuggle a disclosure past authorization.
		query := CredentialQuery{
			Format: "mso_mdoc",
			Meta:   &Meta{DocTypeValue: "eu.europa.ec.av.1"},
			Claims: []Claim{
				{Path: []any{"age_over_18"}},                                // too shallow
				{Path: []any{"eu.europa.ec.av.1", "nested", "age_over_18"}}, // too deep
				{Path: []any{"eu.europa.ec.av.1", 0}},                       // not a string
			},
		}

		assert.Empty(t, query.AuthorizationAttributeNames())
	})

	t.Run("sd-jwt keeps every string component", func(t *testing.T) {
		query := CredentialQuery{
			Format: "dc+sd-jwt",
			Meta:   &Meta{VctValues: []string{"https://vct.example.com/Cred"}},
			Claims: []Claim{
				{Path: []any{"given_name"}},
				{Path: []any{"address", "street"}},
			},
		}

		assert.Equal(t, []string{"given_name", "address", "street"},
			query.AuthorizationAttributeNames(),
			"non-mdoc formats must keep the pre-existing flattening behaviour")
	})
}
