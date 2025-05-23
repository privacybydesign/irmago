package sdjwtvc

import "testing"

func Test_BuildSdJwtVc_BareMinimum_Success(t *testing.T) {
	builder := NewSdJwtVcBuilder().
		WithVerifiableCredentialType(DefaultVerifiableCredentialType)
	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_ValidIssuerUrl_Success(t *testing.T) {
	builder := NewSdJwtVcBuilder().
		WithVerifiableCredentialType(DefaultVerifiableCredentialType).
		WithIssuerUrl("https://openid4vc.staging.yivi.app", false)

	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_InvalidIssuerUrl_BuildFailure(t *testing.T) {
	builder := NewSdJwtVcBuilder().
		WithVerifiableCredentialType(DefaultVerifiableCredentialType).
		WithIssuerUrl("http://openid4vc.staging.yivi.app", false)

	requireBuildFailure(t, builder)
}

func Test_BuildSdJwtVc_WithDisclosures_Success(t *testing.T) {
	disclosures, err := MultipleNewDisclosureContents(map[string]any{
		"name":     "Yivi",
		"location": "Utrecht",
	})
	requireNoErr(t, err)

	builder := NewSdJwtVcBuilder().
		WithHashingAlgorithm(HashAlg_Sha256).
		WithVerifiableCredentialType(DefaultVerifiableCredentialType).
		WithDisclosures(disclosures)

	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_DisclosuresWithoutHashingAlg_Failure(t *testing.T) {
	disclosures, err := MultipleNewDisclosureContents(map[string]any{
		"name":     "Yivi",
		"location": "Utrecht",
	})
	requireNoErr(t, err)

	builder := NewSdJwtVcBuilder().
		WithVerifiableCredentialType(DefaultVerifiableCredentialType).
		WithDisclosures(disclosures)

	requireBuildFailure(t, builder)
}

func Test_BuildSdJwtVc_NoVct_BuildFailure(t *testing.T) {
	builder := NewSdJwtVcBuilder()
	requireBuildFailure(t, builder)
}

func requireBuildFailure(t *testing.T, builder *SdJwtVcBuilder) {
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	_, err := builder.Build(jwtCreator)
	requireErr(t, err)
}

func requireValidSdJwtVc(t *testing.T, builder *SdJwtVcBuilder) {
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	sdjwtvc, err := builder.Build(jwtCreator)
	requireNoErr(t, err)
	context := createTestVerificationContext()
	_, err = ParseAndVerifySdJwtVc(context, sdjwtvc)
	requireNoErr(t, err)
}
