package sdjwtvc

import (
	"encoding/json"
	"testing"
	"time"

	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// fails for:
// - [x] invalid jwt as the issuer signed jwt
// - [x] sdjwtvc doesn't end with ~ and doesn't have a kbjwt
// - [x] typ in issuer signed jwt is not vc+sd-jwt or dc+sd-jwt
// - [x] empty (not missing) sd field in issuer signed jwt
// - [x] disclosures that are not in the sd field
// - [x] missing iss link
// - [x] iss link that can't be fetched
// - [x] iss link with wrong key in metadata
// - [x] iss link with wrong issuer url in metadata
// - [x] iss link is non-https, when it should be
// - [x] clock.now + skew is before iat
// - [x] clock.now + skew is before nbf
// - [x] clock.now - skew is after exp
// - [x] cnf missing while there is a kbjwt
// - [x] cnf contains wrong key to verify kbjwt
// - [x] mismatch for sd_hash field in kbjwt
// - [x] unsupported _sd_alg
// - [x] kbjwt doesn't contain the kb+jwt typ in header
// - [x] failing to get issuer metadata fails the verification
// - [x] no iss value provided
// - [x] valid self-signed x509 certificate that doesn't match a trusted certificate
//
// success for
// - [x] both vc+sd-jwt and dc+sd-jwt in typ header of issuer signed jwt
// - [x] no disclosures but with a kbjwt
// - [x] issuer signed jwt doesn't contain any sd's
// - [x] multiple keys in issuer metadata, of which the second is correct
// - [x] different orders for disclosures
// - [x] less disclosures than are in the _sd field
// - [x] no kbjwt for otherwise valid sdjwtvc with disclosures
// - [x] no kbjwt for otherwise valid sdjwtvc without disclosures
// - [x] no kbjwt and no cnf field
// - [x] iss link is non-https, but is accepted (for testing purposes)
// - [x] valid self-signed x509 certificate with DNS/URI value that matches `iss` value
// - [x] valid x509 certificate chain with DNS/URI value that matches `iss` value
// - [x] clock.now - 1 minute is before iat (valid because of skew)
// - [x] clock.now - 1 minute is before nbf (valid because of skew)
// - [x] clock.now + 1 minute is after exp (valid because of skew)

// =======================================================================

type x509TestConfig struct {
	IssuerCert                     []byte
	VerifierTrustedIssuerCertChain []byte
	IssUrl                         string
	ShouldFail                     bool
}

func runCertChainTest(t *testing.T, config x509TestConfig) {
	chain, err := utils.ParsePemCertificateChainToX5cFormat(config.IssuerCert)
	require.NoError(t, err)

	disclosures, err := MultipleNewDisclosureContents(map[string]string{
		"email": "test@gmail.com",
	})
	require.NoError(t, err)

	creator := NewEcdsaJwtCreatorWithIssuerTestkey()
	sdjwt, err := NewSdJwtVcBuilder().
		WithExpiresAt(time.Now().Unix()).
		WithIssuerCertificateChain(chain).
		WithIssuerUrl(config.IssUrl).
		WithVerifiableCredentialType("test.test.email").
		WithDisclosures(disclosures).
		WithHashingAlgorithm(HashAlg_Sha256).
		Build(creator)
	require.NoError(t, err)

	verifyOpts, err := utils.CreateX509VerifyOptionsFromCertChain(config.VerifierTrustedIssuerCertChain)
	require.NoError(t, err)

	context := SdJwtVcVerificationContext{
		VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: *verifyOpts,
		},
		Clock:       NewSystemClock(),
		JwtVerifier: NewJwxJwtVerifier(),
	}

	_, err = ParseAndVerifySdJwtVc(context, sdjwt)
	if config.ShouldFail {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}
}

func Test_ValidLeafCertOnly_Success(t *testing.T) {
	runCertChainTest(t, x509TestConfig{
		IssuerCert:                     testdata.IssuerCert_irma_app_Bytes,
		VerifierTrustedIssuerCertChain: testdata.IssuerCert_irma_app_Bytes,
		IssUrl:                         "https://irma.app",
		ShouldFail:                     false,
	})
}

func Test_Valid_X509Chain_Success(t *testing.T) {
	runCertChainTest(t, x509TestConfig{
		IssuerCert:                     testdata.IssuerCert_irma_app_Bytes,
		VerifierTrustedIssuerCertChain: testdata.IssuerCertChain_irma_app_Bytes,
		IssUrl:                         "https://irma.app",
		ShouldFail:                     false,
	})
}

func Test_ValidButUntrusted_SelfSigned_X509Cert_Fails(t *testing.T) {
	runCertChainTest(t, x509TestConfig{
		IssuerCert: testdata.IssuerCert_irma_app_Bytes,
		IssUrl:     "https://irma.app",
		ShouldFail: true,
	})
}

func Test_InvalidJwtForIssuerSignedJwt_Fails(t *testing.T) {
	sdJwt := SdJwtVc("slkjfaslkgdjaglj")
	context := CreateTestVerificationContext()

	_, err := ParseAndVerifySdJwtVc(context, sdJwt)
	require.Error(t, err)
}

func TestDecodingDisclosure(t *testing.T) {
	content, err := NewDisclosureContent("name", "Yivi")
	require.NoError(t, err)
	d, err := EncodeDisclosure(content)
	require.NoError(t, err)

	decoded, err := DecodeDisclosure(d)
	require.NoError(t, err)

	require.Equal(t, "name", decoded.Key)
	require.Equal(t, "Yivi", decoded.Value)
}

func Test_IssuerSignedJwt_WithInvalidTypHeader_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	_, err := ParseAndVerifySdJwtVc(context, SdJwtVc(wrongIssuerSignedJwtTypHeader))
	require.Error(t, err, "failed to parse JWT: jwt.Parse: failed to parse token: jws.Verify: key provider 0 failed: invalid 'typ' header: jwt")
}

func Test_ValidSdJwtVc_NoDisclosures_NoKbJwt(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	verifiedSdJwtVc, err := ParseAndVerifySdJwtVc(context, validSdJwtVc_NoDisclosuresNoKbjwt)
	require.NoError(t, err)

	require.Len(t, verifiedSdJwtVc.Disclosures, 0)
	require.Nil(t, verifiedSdJwtVc.KeyBindingJwt)
}

func Test_ValidSdJwt_MismatchingHashInKbJwt_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	_, err := ParseAndVerifySdJwtVc(context, validSdJwtVc_MismatchingHashInKbJwt)
	require.Error(t, err)
}

func Test_ValidSdJwt_WithDcTypHeader_WithDisclosures_WithKbJwt_Succeeds(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	verifiedSdJwtVc, err := ParseAndVerifySdJwtVc(context, validSdJwtVc_DcTypHeader)
	require.NoError(t, err)

	require.Len(t, verifiedSdJwtVc.Disclosures, 2)
	require.NotNil(t, verifiedSdJwtVc.KeyBindingJwt)
}

func Test_ValidSdJwtVc_WithKbJwt_WithLegacyVcHeader_Succeeds(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	verifiedSdJwtVc, err := ParseAndVerifySdJwtVc(context, validSdJwtVc_VcTypHeader)
	require.NoError(t, err)

	require.Len(t, verifiedSdJwtVc.Disclosures, 2)
	require.NotNil(t, verifiedSdJwtVc.KeyBindingJwt)
}

func Test_ValidSdJwt_WithDisclosures_NoKbJwt_Succeeds(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	verifiedSdJwtVc, err := ParseAndVerifySdJwtVc(context, validSdJwtVc_NoKbJwt)
	require.NoError(t, err)

	require.Len(t, verifiedSdJwtVc.Disclosures, 2)
	require.Nil(t, verifiedSdJwtVc.KeyBindingJwt)
}

func Test_InvalidSdJwtVc_MissingTrailingTilde_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	_, err := ParseAndVerifySdJwtVc(context, invalidSdJwtVc_MissingTrailingTilde)
	require.Error(t, err)
}

func Test_InvalidSdJwtVc_WrongKbJwtTypHeader_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	_, err := ParseAndVerifySdJwtVc(context, invalidSdJwtVC_WrongKbTypHeader)
	require.Error(t, err)
}

// ==============================================================================

func Test_MismatchingSdHash_Fails(t *testing.T) {
	mismatchingSdHashConfig := newWorkingSdJwtTestConfig().
		withSdHash("lkasjgdlksajglskjg")
	errorTestCase(t, mismatchingSdHashConfig, "mismatching sd hash should fail")
}

func Test_NoSdHash_Fails(t *testing.T) {
	noHashConfig := newWorkingSdJwtTestConfig().withoutAnySdHash()
	errorTestCase(t, noHashConfig, "no sd_hash in kbjwt should fail")
}

func Test_MissingIssuerUrl_Fails(t *testing.T) {
	missingIssuerUrl := newWorkingSdJwtTestConfig()
	missingIssuerUrl.issuerUrl = nil
	errorTestCase(t, missingIssuerUrl, "missing issuer url is valid")
}

func Test_InvalidIssuerUrl_Fails(t *testing.T) {
	invalidIssuerUrl := newWorkingSdJwtTestConfig().withIssuerUrl("http://openid4vc.staging.yivi.app/", false)
	errorTestCase(t, invalidIssuerUrl, "invalid issuer url should fail (no https)")
}

func Test_InvalidIssuerUrl_Succeeds(t *testing.T) {
	invalidIssuerUrl := newWorkingSdJwtTestConfig().withIssuerUrl("http://openid4vc.staging.yivi.app/", true)
	errorTestCase(t, invalidIssuerUrl, "invalid issuer url should fail (no https)")
}

func Test_MissingVct_Fails(t *testing.T) {
	missingVct := newWorkingSdJwtTestConfig()
	missingVct.vct = nil
	errorTestCase(t, missingVct, "missing vct should fail")
}

func Test_EmptyButNotMissingSdField_Fails(t *testing.T) {
	emptyNotMissingSdField := newWorkingSdJwtTestConfig().
		withSdClaims([]DisclosureContent{}).
		withDisclosures([]DisclosureContent{})
	errorTestCase(t, emptyNotMissingSdField, "sd_hash may not be empty")
}

func Test_NoCnfFieldButWithKbJwt_Fails(t *testing.T) {
	noCnfFieldWithKbJwt := newWorkingSdJwtTestConfig()
	noCnfFieldWithKbJwt.cnfPubKey = nil
	errorTestCase(t, noCnfFieldWithKbJwt, "no cnf field with kbjwt present should fail")
}

func Test_WrongCnfKey_Fails(t *testing.T) {
	wrongCnfKey := newWorkingSdJwtTestConfig().withCnf(createIssuerCnfField())
	errorTestCase(t, wrongCnfKey, "wrong pub key in cnf field should fail")
}

func Test_MissingSdAlg_Fails(t *testing.T) {
	missingSdAlgField := newWorkingSdJwtTestConfig()
	missingSdAlgField.sdAlg = nil
	errorTestCase(t, missingSdAlgField, "missing _sd_alg field should fail")
}

func Test_UnsupportedSdAlg_Fails(t *testing.T) {
	wrongSdAlgField := newWorkingSdJwtTestConfig().withSdAlg("SHA-null")
	errorTestCase(t, wrongSdAlgField, "wrong _sd_alg field should fail")
}

func Test_DisclosuresThatAreNotInSdField_Fails(t *testing.T) {
	otherDisclosures, err := MultipleNewDisclosureContents(map[string]string{
		"name":     "IRMA",
		"location": "Nijmegen",
	})
	require.NoError(t, err)
	config := newWorkingSdJwtTestConfig().withDisclosures(otherDisclosures)
	errorTestCase(t, config, "different disclosures than are in the _sd field should fail")
}

func Test_BaselineGeneratedSdJwtVc_Succeeds(t *testing.T) {
	config := newWorkingSdJwtTestConfig().
		withIssuerCertificateChainBytes(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	noErrorTestCase(t, config, "default working test sdjwtvc creator is valid")
}

func Test_FewerDisclosuresThanSdHashes_Succeeds(t *testing.T) {
	config := newWorkingSdJwtTestConfig().
		withIssuerCertificateChainBytes(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	config.disclosures = []DisclosureContent{
		config.disclosures[1],
	}
	noErrorTestCase(t, config, "fewer disclosures than _sd field hashes is valid")
}

func Test_DifferentOrderDisclosures_Succeeds(t *testing.T) {
	config := newWorkingSdJwtTestConfig().
		withIssuerCertificateChainBytes(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	config.disclosures = []DisclosureContent{
		config.disclosures[1],
		config.disclosures[0],
	}
	noErrorTestCase(t, config, "different order disclosures than _sd field hashes is valid")
}

func Test_NoCnfFieldAndNoKbJwt_Succeeds(t *testing.T) {
	config := newWorkingSdJwtTestConfig().
		withIssuerCertificateChainBytes(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes).
		withoutKbJwt()
	config.cnfPubKey = nil
	noErrorTestCase(t, config, "no cnf pub key and no kbjwt is valid")
}

func Test_NoDisclosuresWithKbJwt_Succeeds(t *testing.T) {
	config := newWorkingSdJwtTestConfig().
		withIssuerCertificateChainBytes(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes).
		withDisclosures([]DisclosureContent{}).withKbJwt()
	noErrorTestCase(t, config, "no disclosures but with a kbjwt is valid")
}

func Test_NoSdsAtAll_Succeeds(t *testing.T) {
	config := newWorkingSdJwtTestConfig().
		withIssuerCertificateChainBytes(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)

	config.sdClaims = nil
	config.disclosures = []DisclosureContent{}

	noErrorTestCase(t, config, "no _sd claims at all is valid (if no disclosures either)")
}

func Test_IatIsAfterVerification_Fails(t *testing.T) {
	now := time.Now().Unix()
	iat := now + ClockSkewInSeconds + 100
	kbIat := now

	config := newWorkingSdJwtTestConfig().
		withIssuerCertificateChainBytes(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes).
		withIssuedAt(iat).
		withKbIssuedAt(kbIat)

	context := SdJwtVcVerificationContext{
		Clock:       &testClock{time: now},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.Error(t, err)
}

func Test_VerificationIsAfterExp_Fails(t *testing.T) {
	now := time.Now().Unix()
	exp := now - ClockSkewInSeconds - 100

	config := newWorkingSdJwtTestConfig().
		withIssuerCertificateChainBytes(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes).
		withIssuedAt(now).
		withKbIssuedAt(now).
		withExpiryTime(exp)

	context := SdJwtVcVerificationContext{
		Clock:       &testClock{time: now},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.Error(t, err)
}

func Test_VerificationIsBeforeNotBefore_Fails(t *testing.T) {
	now := time.Now().Unix()
	nbf := now + ClockSkewInSeconds + 50

	config := newWorkingSdJwtTestConfig().
		withIssuerCertificateChainBytes(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes).
		withIssuedAt(now).
		withKbIssuedAt(now).
		withExpiryTime(100).
		withNotBefore(nbf)

	context := SdJwtVcVerificationContext{
		VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(),
		},
		Clock:       &testClock{time: now},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.Error(t, err)
}

func Test_VerificationMinusOneMinuteIsBeforeIat_GivenClockSkew_Success(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtTestConfig().
		withIssuerCertificateChainBytes(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes).
		withIssuedAt(now).
		withKbIssuedAt(now)

	context := SdJwtVcVerificationContext{
		VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now - 60},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.NoError(t, err)
}

func Test_VerificationPlusOneMinuteIsAfterExp_GivenClockSkew_Success(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtTestConfig().
		withIssuerCertificateChainBytes(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes).
		withIssuedAt(now).
		withKbIssuedAt(now).
		withExpiryTime(now)

	context := SdJwtVcVerificationContext{
		VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now + 60},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.NoError(t, err)
}

func Test_VerificationMinusOneMinuteIsBeforeNotBefore_GivenClockSkew_Success(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtTestConfig().
		withIssuerCertificateChainBytes(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes).
		withIssuedAt(now).
		withKbIssuedAt(now).
		withNotBefore(now)

	context := SdJwtVcVerificationContext{
		VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now - 60},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.NoError(t, err)
}

func Test_VerifyAndProcessPayloadDisclosures_FlatSdJwt_EmptySdField_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{}
	issuerSignedJwtPayload := map[string]any{
		"_sd": []any{},
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "when the _sd field is present it may not be empty")
}

func Test_VerifyAndProcessPayloadDisclosures_FlatSdJwt_SdFieldIsNotAnArray_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{}
	issuerSignedJwtPayload := map[string]any{
		"_sd": 42,
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "failed to convert _sd field to []any")
}

func Test_VerifyAndProcessPayloadDisclosures_FlatSdJwt_NonStringSdField_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{}
	issuerSignedJwtPayload := map[string]any{
		"_sd": []any{42},
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "failed to convert value in _sd array to string")
}

func Test_VerifyAndProcessPayloadDisclosures_FlatSdJwt_DisclosureContainsSdField_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// disclosure: ["_3JoPNqbcqtsdax9J0xMvA","_sd","test"]
		"WyJfM0pvUE5xYmNxdHNkYXg5SjB4TXZBIiwiX3NkIiwidGVzdCJd",
	}

	issuerSignedJwtPayload := map[string]any{
		"_sd": []any{
			"uaqRlJ33nALYusFITW0nuk67ZynCsLdwTI4EymZB5Rw",
		},
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "has an `_sd` field, which is not allowed")
}

func Test_VerifyAndProcessPayloadDisclosures_FlatSdJwt_DisclosureContainsEllipsisField_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// disclosure: ["_3JoPNqbcqtsdax9J0xMvA","...","test"]
		"WyJfM0pvUE5xYmNxdHNkYXg5SjB4TXZBIiwiLi4uIiwidGVzdCJd",
	}

	issuerSignedJwtPayload := map[string]any{
		"_sd": []any{
			"YRYvIY_GmMyi58Byf6JCg3CZvC7D6MGmKOaEx2plM1k",
		},
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "has an `...` field, which is not allowed")
}

func Test_VerifyAndProcessPayloadDisclosures_FlatSdJwt_AlreadyContainsFieldnameAtSameLevel_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// disclosure: ["_3JoPNqbcqtsdax9J0xMvA","name","Alpha"]
		"WyJfM0pvUE5xYmNxdHNkYXg5SjB4TXZBIiwibmFtZSIsIkFscGhhIl0",
	}

	issuerSignedJwtPayload := map[string]any{
		"_sd": []any{
			"c3DYrtRZ3zLEKH2fcTrkRymiT4T5ZkwQuFfj3TlnRQQ",
		},
		"name": "Bravo",
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "embedded disclosure key \"name\" already exists at this level")
}

func Test_VerifyAndProcessPayloadDisclosures_FlatSdJwt_ContainsNoArrays_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// disclosure: ["_3JoPNqbcqtsdax9J0xMvA","family_name","T"]
		"WyJfM0pvUE5xYmNxdHNkYXg5SjB4TXZBIiwiZmFtaWx5X25hbWUiLCJUIl0",
		// disclosure: ["OKyl8ky692IYD_W9OPP8xg","given_name","T"]
		"WyJPS3lsOGt5NjkySVlEX1c5T1BQOHhnIiwiZ2l2ZW5fbmFtZSIsIlQiXQ",
	}

	issuerSignedJwtPayload := map[string]any{
		"_sd": []any{
			"dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU",
			"K4oRic8I4m2y8lMUAN7MttLYrynKgocsENANMvPoHYQ",
		},
	}

	// Act
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 2)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload["_sd"]
	require.False(t, ok)

	// Check the claims are present/replaced correctly
	_, ok = issuerSignedJwtPayload["family_name"]
	require.True(t, ok)
	_, ok = issuerSignedJwtPayload["given_name"]
	require.True(t, ok)
}

func Test_VerifyAndProcessPayloadDisclosures_FlatSdJwt_ContainsAnArray_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// array element: ["dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJkSXZmcGFpb2lUZXA1b3J6NmVFWnh3IiwiTkwiXQ",
		// array: ["PW8uSwHPfOh3fENJGCeEBQ","nationalities",[{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"}]]
		"WyJQVzh1U3dIUGZPaDNmRU5KR0NlRUJRIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiYjdNVFhSWm1NeUUyMl9aeWlOdkFwNmh5Z0k1WThFeTZLTnVLVWFINmxpbyJ9XV0",
	}

	issuerSignedJwtPayload := map[string]any{
		"_sd": []any{
			// Hash for array (NOT the array element)
			"3KpnrnSJV9ING3MqFexvxLLkAEQDs4suq3MgG0RnE54",
		},
	}

	// Act
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 2)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload["_sd"]
	require.False(t, ok)

	arrVal, ok := issuerSignedJwtPayload["nationalities"]
	require.True(t, ok)
	require.NotNil(t, arrVal)

	// The array should now contain 1 element
	arr, ok := arrVal.([]any)
	require.True(t, ok)
	require.Len(t, arr, 1)
}

func Test_VerifyAndProcessPayloadDisclosures_FlatSdJwt_WithPermanentDisclosure_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// flat object: ["2GLC42sKQveCfGfryNRN9w", "street_address", "Schulstr. 12"]
		"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd",
	}

	issuerSignedJwtPayload := map[string]any{
		"_sd": []any{
			"9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM",
		},
		"country": "DE",
	}

	// Act
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 1)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload["_sd"]
	require.False(t, ok)

	// Map should now contain the permanently disclosed value + the selectively disclosed value
	require.Len(t, issuerSignedJwtPayload, 2)

	arrVal, ok := issuerSignedJwtPayload["street_address"]
	require.True(t, ok)
	require.Equal(t, arrVal, "Schulstr. 12")

	// The array should now contain 1 element
	arrVal, ok = issuerSignedJwtPayload["country"]
	require.True(t, ok)
	require.Equal(t, arrVal, "DE")
}

func Test_VerifyAndProcessPayloadDisclosures_FlatSdJwt_ContainsAnArray_WithPermanentlyDisclosedValues_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// array element: ["dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJkSXZmcGFpb2lUZXA1b3J6NmVFWnh3IiwiTkwiXQ",
		// array: ["PW8uSwHPfOh3fENJGCeEBQ","nationalities",["DE","FR",{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"}]]
		"WyJQVzh1U3dIUGZPaDNmRU5KR0NlRUJRIiwibmF0aW9uYWxpdGllcyIsWyJERSIsIkZSIix7Ii4uLiI6ImI3TVRYUlptTXlFMjJfWnlpTnZBcDZoeWdJNVk4RXk2S051S1VhSDZsaW8ifV1d",
	}

	issuerSignedJwtPayload := map[string]any{
		"_sd": []any{
			// Hash for array
			"bH_IUnOFqaa2MAX1YNxrSyYv4OzPFC9cWwEMI3gn72w",
		},
	}

	// Act
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 2)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload["_sd"]
	require.False(t, ok)

	arrVal, ok := issuerSignedJwtPayload["nationalities"]
	require.True(t, ok)
	require.NotNil(t, arrVal)

	// The array should now contain 3 elements: "DE", "FR", and the disclosed object
	arr, ok := arrVal.([]any)
	require.True(t, ok)
	require.Len(t, arr, 3)
}

func Test_VerifyAndProcessPayloadDisclosures_FlatSdJwt_ContainsAnArray_GivenInvalidDigestElement_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// valid array element: ["dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJkSXZmcGFpb2lUZXA1b3J6NmVFWnh3IiwiTkwiXQ",
		// invalid array element digest (extra field): ["invalid_extra_element_in_digest_element", "dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJpbnZhbGlkX2V4dHJhX2VsZW1lbnRfaW5fZGlnZXN0X2VsZW1lbnQiLCAiZEl2ZnBhaW9pVGVwNW9yejZlRVp4dyIsIk5MIl0",
		// array: ["PW8uSwHPfOh3fENJGCeEBQ","nationalities",[{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"},{"...":"h-CQlbsh70pquZdVagjwYSojWUT41ZzXfvr3FLCo4Ks"}]]
		"WyJQVzh1U3dIUGZPaDNmRU5KR0NlRUJRIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiYjdNVFhSWm1NeUUyMl9aeWlOdkFwNmh5Z0k1WThFeTZLTnVLVWFINmxpbyJ9LHsiLi4uIjoiaC1DUWxic2g3MHBxdVpkVmFnandZU29qV1VUNDFaelhmdnIzRkxDbzRLcyJ9XV0",
	}
	payload := IssuerSignedJwtPayload{
		SdAlg: "sha-256",
	}

	issuerSignedJwtPayload := map[string]any{
		"_sd": []any{
			// Hash for array (NOT the array element)
			"3mhS5a0J_TxEK5ZHlES0_MRx7qV7FERCHbX2lSEz94Q",
		},
	}

	// Act
	_, disclosures, err := verifyAndProcessDisclosures(payload.SdAlg, &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.Error(t, err)
	require.ErrorContains(t, err, "is expected to be an array element, but is not")
	require.Nil(t, disclosures)
}

func Test_VerifyAndProcessPayloadDisclosures_FlatSdJwt_ContainsAnArray_WithDecoyDigests_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// array element: ["dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJkSXZmcGFpb2lUZXA1b3J6NmVFWnh3IiwiTkwiXQ",
		// array with valid element (element 0) and one decoy digest (element 1, which is a hash over a 'secure random' value)
		// array: ["PW8uSwHPfOh3fENJGCeEBQ","nationalities",[{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"},{"...":"wBIalkzxNqdBbT-eotJFegKmirdUPyyXLxIbtFugdsI"}]]
		"WyJQVzh1U3dIUGZPaDNmRU5KR0NlRUJRIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiYjdNVFhSWm1NeUUyMl9aeWlOdkFwNmh5Z0k1WThFeTZLTnVLVWFINmxpbyJ9LHsiLi4uIjoid0JJYWxrenhOcWRCYlQtZW90SkZlZ0ttaXJkVVB5eVhMeElidEZ1Z2RzSSJ9XV0",
	}

	issuerSignedJwtPayload := map[string]any{
		"_sd": []any{
			// Hash for array (NOT the array element)
			"FxetI8EvzLU8v49U8JdbN0FsQs4UtwudaT7xdPLYU3g",
		},
	}

	// Act
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 2)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload["_sd"]
	require.False(t, ok)

	arrVal, ok := issuerSignedJwtPayload["nationalities"]
	require.True(t, ok)
	require.NotNil(t, arrVal)

	// The array should only contain the valid element, the decoy digest should be ignored
	arr, ok := arrVal.([]any)
	require.True(t, ok)
	require.Len(t, arr, 1)
}

func Test_VerifyAndProcessPayloadDisclosures_StructuredSdJwt_ContainsNoArrays_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd",
		"WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0",
		"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd",
		"WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ",
	}

	issuerSignedJwtPayload := `{
		"address": {
			"_sd": [
				"6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0",
				"9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM",
				"KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88",
				"WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM"
			]
		}
	}`

	var issuerSignedJwtPayloadFromJson map[string]any
	err := json.Unmarshal([]byte(issuerSignedJwtPayload), &issuerSignedJwtPayloadFromJson)
	require.NoError(t, err)

	// Act
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayloadFromJson, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 4)

	addr, ok := issuerSignedJwtPayloadFromJson["address"]
	require.True(t, ok)
	require.NotNil(t, addr)

	addrMap, ok := addr.(map[string]any)
	require.True(t, ok)

	// Check that _sd field is removed from `address` field in the issuer signed jwt payload
	_, ok = addrMap["_sd"]
	require.False(t, ok)

	// The object should contain 4 fields now: street_address, locality, region, country
	require.Len(t, addrMap, 4)
	require.Contains(t, addrMap["street_address"], "Schulstr. 12")
	require.Contains(t, addrMap["locality"], "Schulpforta")
	require.Contains(t, addrMap["region"], "Sachsen-Anhalt")
	require.Contains(t, addrMap["country"], "DE")
}

func Test_VerifyAndProcessPayloadDisclosures_StructuredSdJwt_ContainsArraysWithDecoyDigest_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd",
		"WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0",
		"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd",
		"WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ",
		// array element: ["dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJkSXZmcGFpb2lUZXA1b3J6NmVFWnh3IiwiTkwiXQ",
		// array with valid element (element 0) and one decoy digest (element 1, which is a hash over a 'secure random' value)
		// array: ["PW8uSwHPfOh3fENJGCeEBQ","nationalities",[{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"},{"...":"wBIalkzxNqdBbT-eotJFegKmirdUPyyXLxIbtFugdsI"}]]
		"WyJQVzh1U3dIUGZPaDNmRU5KR0NlRUJRIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiYjdNVFhSWm1NeUUyMl9aeWlOdkFwNmh5Z0k1WThFeTZLTnVLVWFINmxpbyJ9LHsiLi4uIjoid0JJYWxrenhOcWRCYlQtZW90SkZlZ0ttaXJkVVB5eVhMeElidEZ1Z2RzSSJ9XV0",
	}

	issuerSignedJwtPayload := `{
		"address": {
			"_sd": [
				"6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0",
				"9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM",
				"KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88",
				"WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM",
				"FxetI8EvzLU8v49U8JdbN0FsQs4UtwudaT7xdPLYU3g"
			]
		}
	}`

	var issuerSignedJwtPayloadFromJson map[string]any
	err := json.Unmarshal([]byte(issuerSignedJwtPayload), &issuerSignedJwtPayloadFromJson)
	require.NoError(t, err)

	// Act
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayloadFromJson, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 6)

	addr, ok := issuerSignedJwtPayloadFromJson["address"]
	require.True(t, ok)
	require.NotNil(t, addr)

	addrMap, ok := addr.(map[string]any)
	require.True(t, ok)

	// Check that _sd field is removed from `address` field in the issuer signed jwt payload
	_, ok = addrMap["_sd"]
	require.False(t, ok)

	// The object should contain 5 fields now: street_address, locality, region, country, nationalities
	require.Len(t, addrMap, 5)
	require.Contains(t, addrMap["street_address"], "Schulstr. 12")
	require.Contains(t, addrMap["locality"], "Schulpforta")
	require.Contains(t, addrMap["region"], "Sachsen-Anhalt")
	require.Contains(t, addrMap["country"], "DE")

	natVal, ok := addrMap["nationalities"]
	require.True(t, ok)
	require.NotNil(t, natVal)

	// The array should only contain the valid element, the decoy digest should be ignored
	natArr, ok := natVal.([]any)
	require.True(t, ok)
	require.Len(t, natArr, 1)
}

func Test_VerifyAndProcessPayloadDisclosures_RecursiveDisclosures_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		"WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImV4dGVuc2lvbiIsICJiaXMiXQ", // extension disclosure
		"WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgIm51bWJlciIsICIxMiJd",       // number disclosure
		"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImhvdXNlbnVtYmVyIiwgeyJfc2QiOlsiMW9mOW82ZXRjNWdTWkpXQmVERHl3eGI1RVcwbE14Z2diWUdHQ1RiWG9VNCIsIjExZEZzM0ZVWTdUa0hDdmIwZDU2T2p6bU5yZVJWMl9pdDVwNXZtS0FXY0UiXX1d", // housenumber disclosure
		"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInN0cmVldCIsICJTY2h1bHN0ci4iXQ", // street disclosure
		"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInN0cmVldF9hZGRyZXNzIiwgeyJfc2QiOlsic1BTT1VmTkVJSW5FUE14cTlrVC1YU0ptT0tyRkpVTC0yZElQektPcmNhVSIsIndQNG9kbFJDUzlybmlZZjJ6UTNjNEVrU2JySUpKTHdTR21MY0ZrWDVKNVkiXX1d", // street_address disclosure
	}

	// Format:
	// {
	//   "address": {
	//     "street_address": {
	//       "street": "Schulstr."
	//     	 "housenumber": {
	//			"number": "12"
	//		    "extension": "bis"
	//		 }
	//     }
	// 	 }
	// }
	// Where the address only contains a pointer to the street_address disclosure, which will need to (recursively) build the full structure
	issuerSignedJwtPayload := `{
		"address": {
			"_sd": [
				"2c7XHh7XAUa0NknanfXW1vTWsJ7tqgOnDzsnZGEFtl4"
			]
		}
	}`

	var issuerSignedJwtPayloadFromJson map[string]any
	err := json.Unmarshal([]byte(issuerSignedJwtPayload), &issuerSignedJwtPayloadFromJson)
	require.NoError(t, err)

	// Act
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayloadFromJson, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 5)

	addr, ok := issuerSignedJwtPayloadFromJson["address"]
	require.True(t, ok)
	require.NotNil(t, addr)

	addrMap, ok := addr.(map[string]any)
	require.True(t, ok)

	// Check that _sd field is removed from `address` field in the issuer signed jwt payload
	_, ok = addrMap["_sd"]
	require.False(t, ok)

	// The object should contain 1 field now: street_address
	require.Len(t, addrMap, 1)

	streetAddrVal, ok := addrMap["street_address"]
	require.True(t, ok)
	require.NotNil(t, streetAddrVal)

	streetAddrMap, ok := streetAddrVal.(map[string]any)
	require.True(t, ok)

	// The street_address object should contain 2 fields now: street, housenumber
	require.Len(t, streetAddrMap, 2)
	require.Contains(t, streetAddrMap["street"], "Schulstr.")

	housenumberVal, ok := streetAddrMap["housenumber"]
	require.True(t, ok)
	require.NotNil(t, housenumberVal)

	housenumberMap, ok := housenumberVal.(map[string]any)
	require.True(t, ok)

	// The housenumber object should contain 2 fields now: number, extension
	require.Len(t, housenumberMap, 2)
	require.Contains(t, housenumberMap["number"], "12")
	require.Contains(t, housenumberMap["extension"], "bis")
}

// ==============================================================================

func errorTestCase(t *testing.T, config testSdJwtVcConfig, message string) {
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.Error(t, err, message)
}

func noErrorTestCase(t *testing.T, config testSdJwtVcConfig, message string) {
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.NoError(t, err, message)
}
