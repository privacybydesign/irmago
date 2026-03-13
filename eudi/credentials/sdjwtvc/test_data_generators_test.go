package sdjwtvc

import (
	"testing"
	"time"

	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// These tests generate the SD-JWT VCs used in test_data.go

func Test_GenerateSdjwt_ValidSdJwtVc_NoDisclosuresNoKbjwt(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcTestConfig().
		withDisclosures([]DisclosureContent{}).
		withoutSdClaims()

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now - 60},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_GenerateSdjwt_ValidSdJwtVc_DcTypHeader_WithKbJwt(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcKbTestConfig()

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now - 60},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVcKb(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.Error(t, err)
}

func Test_GenerateSdjwt_ValidSdJwtVc_DcTypHeader_WithoutKbJwt(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcTestConfig().
		withCnf(createHolderCnfField())

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now - 60},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_GenerateSdjwt_WrongIssuerSignedJwtTypHeader(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcKbTestConfig()
	config.withTypHeader("jwt") // wrong typ header

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now - 60},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVcKb(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.Error(t, err)
}

func Test_GenerateSdjwt_ValidSdJwtVc_VcTypHeader_WithKbJwt(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcKbTestConfig()
	config.withTypHeader(SdJwtVcTyp_Legacy)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now - 60},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVcKb(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.Error(t, err)
}

func Test_GenerateSdjwt_ValidSdJwtVc_VcTypHeader_WithoutKbJwt(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcTestConfig().
		withCnf(createHolderCnfField()).
		withTypHeader(SdJwtVcTyp_Legacy)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now - 60},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_GenerateSdjwt_InvalidSdJwtVC_WrongKbTypHeader(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcKbTestConfig().withKbTypHeader("invalid")

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now - 60},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVcKb(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.Error(t, err)
}
