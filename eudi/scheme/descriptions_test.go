package scheme

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSchemeQueryValidator(t *testing.T) {
	// Happy flow tests
	t.Run("SchemeQueryValidator authorizes query for single credential successfully", testSchemeQueryValidatorAuthorizesQueryForSingleCredentialSuccessfully)
	t.Run("SchemeQueryValidator authorizes query for multiple credential successfully", testSchemeQueryValidatorAuthorizesQueryForMultipleCredentialSuccessfully)
	t.Run("SchemeQueryValidator authorizes query against RP with attributes wildcard", testSchemeQueryValidatorAuthorizesQueryForRelyingPartyWithAttributesWildcard)
	t.Run("SchemeQueryValidator authorizes query against RP with credentials wildcard", testSchemeQueryValidatorAuthorizesQueryForRelyingPartyWithCredentialsWildcard)
	t.Run("SchemeQueryValidator authorizes query against RP with issuers wildcard", testSchemeQueryValidatorAuthorizesQueryForRelyingPartyWithIssuersWildcard)
	t.Run("SchemeQueryValidator authorizes query against RP with scheme wildcard", testSchemeQueryValidatorAuthorizesQueryForRelyingPartyWithSchemeWildcard)

	// mso_mdoc names its credential type with doctype_value, not vct_values
	t.Run("SchemeQueryValidator authorizes an mdoc query named by doctype_value", testSchemeQueryValidatorAuthorizesMdocQueryByDocType)
	t.Run("SchemeQueryValidator rejects an unauthorized mdoc attribute", testSchemeQueryValidatorFailsValidationForUnauthorizedMdocAttribute)
	t.Run("SchemeQueryValidator rejects an unauthorized mdoc doctype", testSchemeQueryValidatorFailsValidationForUnauthorizedMdocDocType)
	t.Run("SchemeQueryValidator tolerates an authorized identifier shorter than the request", testSchemeQueryValidatorHandlesShorterAuthorizedIdentifier)

	// Unhappy flow tests
	t.Run("SchemeQueryValidator fails validation for a query naming no credential type", testSchemeQueryValidatorFailsValidationForQueryWithoutCredentialType)
	t.Run("SchemeQueryValidator fails validation for unauthorized credential query", testSchemeQueryValidatorFailsValidationForUnknownCredential)
	t.Run("SchemeQueryValidator fails validation for unauthorized issuer query", testSchemeQueryValidatorFailsValidationForUnknownIssuer)
	t.Run("SchemeQueryValidator fails validation for single unauthorized credential query", testSchemeQueryValidatorFailsValidationForSingleUnknownCredential)
	t.Run("SchemeQueryValidator fails validation for unauthorized attribute", testSchemeQueryValidatorFailsValidationForUnauthorizedAttribute)
	t.Run("SchemeQueryValidator fails validation for single unauthorized attribute", testSchemeQueryValidatorFailsValidationForSingleUnauthorizedAttribute)
}

func createBasicQueryInfos() []CredentialQueryInfo {
	return []CredentialQueryInfo{
		{
			VctValues:      []string{"pbdf.issuer1.cred"},
			AttributeNames: []string{"attr"},
		},
	}
}

func testSchemeQueryValidatorAuthorizesQueryForSingleCredentialSuccessfully(t *testing.T) {
	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "pbdf.issuer1.cred",
					Attributes: []string{"attr"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(createBasicQueryInfos())
	require.NoError(t, err)
}

func testSchemeQueryValidatorAuthorizesQueryForMultipleCredentialSuccessfully(t *testing.T) {
	queryInfos := []CredentialQueryInfo{
		{
			VctValues:      []string{"pbdf.issuer1.cred", "pbdf.issuer2.cred"},
			AttributeNames: []string{"attr"},
		},
	}

	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "pbdf.issuer1.cred",
					Attributes: []string{"attr"},
				},
				{
					Credential: "pbdf.issuer2.cred",
					Attributes: []string{"attr"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(queryInfos)
	require.NoError(t, err)
}

func testSchemeQueryValidatorAuthorizesQueryForRelyingPartyWithAttributesWildcard(t *testing.T) {
	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "pbdf.issuer1.cred",
					Attributes: []string{"*"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(createBasicQueryInfos())
	require.NoError(t, err)
}

func testSchemeQueryValidatorAuthorizesQueryForRelyingPartyWithCredentialsWildcard(t *testing.T) {
	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "pbdf.issuer1.*",
					Attributes: []string{"*"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(createBasicQueryInfos())
	require.NoError(t, err)
}

func testSchemeQueryValidatorAuthorizesQueryForRelyingPartyWithIssuersWildcard(t *testing.T) {
	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "pbdf.*",
					Attributes: []string{"*"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(createBasicQueryInfos())
	require.NoError(t, err)
}

func testSchemeQueryValidatorAuthorizesQueryForRelyingPartyWithSchemeWildcard(t *testing.T) {
	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "*",
					Attributes: []string{"*"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(createBasicQueryInfos())
	require.NoError(t, err)
}

func testSchemeQueryValidatorFailsValidationForUnknownIssuer(t *testing.T) {
	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "pbdf.issuer2.cred",
					Attributes: []string{"attr"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(createBasicQueryInfos())
	require.Errorf(t, err, "credential is not authorized: credential pbdf.issuer1.cred is not in the authorized set")
}

func testSchemeQueryValidatorFailsValidationForUnknownCredential(t *testing.T) {
	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "pbdf.issuer1.test",
					Attributes: []string{"attr"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(createBasicQueryInfos())
	require.Errorf(t, err, "credential is not authorized: credential pbdf.issuer1.cred is not in the authorized set")
}

func testSchemeQueryValidatorFailsValidationForSingleUnknownCredential(t *testing.T) {
	// Test requesting `pbdf.issuer1.cred.attr` or `pbdf.issuer2.cred.attr`, where only issuer1 is authorized
	queryInfos := []CredentialQueryInfo{
		{
			VctValues:      []string{"pbdf.issuer1.cred", "pbdf.issuer2.cred"},
			AttributeNames: []string{"attr"},
		},
	}

	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "pbdf.issuer1.cred",
					Attributes: []string{"attr"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(queryInfos)
	require.Errorf(t, err, "credential is not authorized: credential pbdf.issuer2.cred is not in the authorized set")
}

func testSchemeQueryValidatorFailsValidationForUnauthorizedAttribute(t *testing.T) {
	queryInfos := []CredentialQueryInfo{
		{
			VctValues:      []string{"pbdf.issuer1.cred"},
			AttributeNames: []string{"unauthorizedAttr"},
		},
	}

	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "pbdf.issuer1.cred",
					Attributes: []string{"attr"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(queryInfos)
	require.Errorf(t, err, "credential is not authorized: requested attribute unauthorizedAttr is not in the authorized set")
}

func testSchemeQueryValidatorFailsValidationForSingleUnauthorizedAttribute(t *testing.T) {
	queryInfos := []CredentialQueryInfo{
		{
			VctValues:      []string{"pbdf.issuer1.cred"},
			AttributeNames: []string{"attr", "unauthorizedAttr"},
		},
	}

	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "pbdf.issuer1.cred",
					Attributes: []string{"attr", "attr2"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(queryInfos)
	require.Errorf(t, err, "credential is not authorized: requested attribute pbdf.issuer1.cred.unauthorizedAttr is not in the authorized set")
}

// ============================================================================
// mso_mdoc credential queries
// ============================================================================
//
// An mdoc query names its credential type with doctype_value rather than
// vct_values, and its claim paths are [namespace, elementIdentifier] with the
// namespace stripped before it reaches here (see
// dcql.CredentialQuery.AuthorizationAttributeNames). Reading only vct_values
// used to reject every mdoc query for a "missing vct_values".

func testSchemeQueryValidatorAuthorizesMdocQueryByDocType(t *testing.T) {
	queryInfos := []CredentialQueryInfo{
		{
			DocTypeValue:   "eu.europa.ec.av.1",
			AttributeNames: []string{"age_over_18"},
		},
	}

	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "eu.europa.ec.av.1",
					Attributes: []string{"age_over_18", "age_over_21"},
				},
			},
		},
	}

	require.NoError(t, validator.ValidateCredentialQueries(queryInfos))
}

func testSchemeQueryValidatorFailsValidationForUnauthorizedMdocAttribute(t *testing.T) {
	queryInfos := []CredentialQueryInfo{
		{
			DocTypeValue:   "eu.europa.ec.av.1",
			AttributeNames: []string{"age_over_18", "age_over_65"},
		},
	}

	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "eu.europa.ec.av.1",
					Attributes: []string{"age_over_18"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(queryInfos)
	require.ErrorContains(t, err, "age_over_65")
}

func testSchemeQueryValidatorFailsValidationForUnauthorizedMdocDocType(t *testing.T) {
	queryInfos := []CredentialQueryInfo{
		{
			DocTypeValue:   "org.iso.18013.5.1.mDL",
			AttributeNames: []string{"age_over_18"},
		},
	}

	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					Credential: "eu.europa.ec.av.1",
					Attributes: []string{"age_over_18"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(queryInfos)
	require.ErrorContains(t, err, "org.iso.18013.5.1.mDL")
}

// testSchemeQueryValidatorHandlesShorterAuthorizedIdentifier pins the bounds
// guard in the dotted wildcard matcher: the authorized identifier is indexed by
// the requested identifier's position, so an authorized identifier with fewer
// parts than the request used to read past its end and panic. A dotted mdoc
// docType (five parts against a scheme's usual three) makes that ordinary.
func testSchemeQueryValidatorHandlesShorterAuthorizedIdentifier(t *testing.T) {
	queryInfos := []CredentialQueryInfo{
		{
			DocTypeValue:   "eu.europa.ec.av.1",
			AttributeNames: []string{"age_over_18"},
		},
	}

	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{
					// Every part matches, then runs out — must reject, not panic.
					Credential: "eu.europa",
					Attributes: []string{"age_over_18"},
				},
			},
		},
	}

	err := validator.ValidateCredentialQueries(queryInfos)
	require.ErrorContains(t, err, "not in the authorized set")
}

func testSchemeQueryValidatorFailsValidationForQueryWithoutCredentialType(t *testing.T) {
	queryInfos := []CredentialQueryInfo{
		{AttributeNames: []string{"attr"}},
	}

	validator := SchemeQueryValidator{
		RelyingParty: &RelyingParty{
			AuthorizedQueryableAttributeSets: []AuthorizedAttributeSet{
				{Credential: "*", Attributes: []string{"*"}},
			},
		},
	}

	err := validator.ValidateCredentialQueries(queryInfos)
	require.ErrorContains(t, err, "identifies no credential type")
}
