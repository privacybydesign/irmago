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

	// Unhappy flow tests
	t.Run("SchemeQueryValidator fails validation for unauthorized credential query", testSchemeQueryValidatorFailsValidationForUnknownCredential)
	t.Run("SchemeQueryValidator fails validation for unauthorized issuer query", testSchemeQueryValidatorFailsValidationForUnknownIssuer)
	t.Run("SchemeQueryValidator fails validation for single unauthorized credential query", testSchemeQueryValidatorFailsValidationForSingleUnknownCredential)
	t.Run("SchemeQueryValidator fails validation for unauthorized attribute", testSchemeQueryValidatorFailsValidationForUnauthorizedAttribute)
	t.Run("SchemeQueryValidator fails validation for single unauthorized attribute", testSchemeQueryValidatorFailsValidationForSingleUnauthorizedAttribute)
}

func createBasicQueryInfos() []CredentialQueryInfo {
	return []CredentialQueryInfo{
		{
			VctValues:  []string{"pbdf.issuer1.cred"},
			ClaimPaths: []string{"attr"},
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
			VctValues:  []string{"pbdf.issuer1.cred", "pbdf.issuer2.cred"},
			ClaimPaths: []string{"attr"},
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
			VctValues:  []string{"pbdf.issuer1.cred", "pbdf.issuer2.cred"},
			ClaimPaths: []string{"attr"},
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
			VctValues:  []string{"pbdf.issuer1.cred"},
			ClaimPaths: []string{"unauthorizedAttr"},
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
			VctValues:  []string{"pbdf.issuer1.cred"},
			ClaimPaths: []string{"attr", "unauthorizedAttr"},
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
