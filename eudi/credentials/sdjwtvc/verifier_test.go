package sdjwtvc

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi"
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
// - [x] clock.now is before nbf
// - [x] clock.now is after exp
// - [x] cnf missing while there is a kbjwt
// - [x] cnf contains wrong key to verify kbjwt
// - [x] mismatch for sd_hash field in kbjwt
// - [x] unsupported _sd_alg
// - [x] kbjwt doesn't contain the kb+jwt typ in header
// - [x] failing to get issuer metadata fails the verifiction
// - [x] no iss value provided
// - [x] valid self-signed x509 certificate with DNS/URI value that doesn't match `iss` value
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

// =======================================================================

type x509TestConfig struct {
	IssuerCertChain   []byte
	VerifierCertChain []byte
	IssUrl            string
	ShouldFail        bool
}

func runCertChainTest(t *testing.T, config x509TestConfig) {
	chain, err := eudi.ParsePemCertificateChainToX5cFormat(config.IssuerCertChain)
	require.NoError(t, err)

	disclosures, err := MultipleNewDisclosureContents(map[string]string{
		"email": "test@mail.com",
	})
	require.NoError(t, err)

	creator := NewEcdsaJwtCreatorWithIssuerTestkey()
	sdjwt, err := NewSdJwtVcBuilder().
		WithIssuerCertificateChain(chain).
		WithIssuerUrl(config.IssUrl).
		WithVerifiableCredentialType("pbdf.sidn-pbdf.email").
		WithDisclosures(disclosures).
		WithHashingAlgorithm(HashAlg_Sha256).
		Build(creator)
	require.NoError(t, err)

	verifyOpts, err := CreateX509VerifyOptionsFromCertChain(config.VerifierCertChain)
	require.NoError(t, err)

	context := VerificationContext{
		Clock:                   NewSystemClock(),
		JwtVerifier:             NewJwxJwtVerifier(),
		X509VerificationOptions: verifyOpts,
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
		IssuerCertChain:   testdata.IssuerCert_irma_app_Bytes,
		VerifierCertChain: testdata.IssuerCertChain_irma_app_Bytes,
		IssUrl:            "https://irma.app",
		ShouldFail:        false,
	})
}

func Test_Valid_X509Chain_WrongISS_Failure(t *testing.T) {
	runCertChainTest(t, x509TestConfig{
		IssuerCertChain:   testdata.IssuerCertChain_irma_app_Bytes,
		VerifierCertChain: testdata.IssuerCertChain_irma_app_Bytes,
		IssUrl:            "https://openid4vc.staging.yivi.app",
		ShouldFail:        true,
	})
}

func Test_Valid_X509Chain_Success(t *testing.T) {
	runCertChainTest(t, x509TestConfig{
		IssuerCertChain:   testdata.IssuerCertChain_irma_app_Bytes,
		VerifierCertChain: testdata.IssuerCertChain_irma_app_Bytes,
		IssUrl:            "https://irma.app",
		ShouldFail:        false,
	})
}

func Test_Valid_SelfSigned_X509Cert_Success(t *testing.T) {
	runCertChainTest(t, x509TestConfig{
		IssuerCertChain:   testdata.IssuerCert_irma_app_Bytes,
		VerifierCertChain: testdata.IssuerCert_irma_app_Bytes,
		IssUrl:            "https://irma.app",
		ShouldFail:        false,
	})
}

func Test_X509_MismatchWithISS_Fails(t *testing.T) {
	runCertChainTest(t, x509TestConfig{
		IssuerCertChain:   testdata.IssuerCert_irma_app_Bytes,
		VerifierCertChain: testdata.IssuerCert_irma_app_Bytes,
		IssUrl:            "https://openid4vc.staging.yivi.app",
		ShouldFail:        true,
	})
}

func Test_ValidButUntrusted_SelfSigned_X509Cert_Fails(t *testing.T) {
	runCertChainTest(t, x509TestConfig{
		IssuerCertChain:   testdata.IssuerCert_irma_app_Bytes,
		VerifierCertChain: testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes,
		IssUrl:            "https://irma.app",
		ShouldFail:        true,
	})
}

func Test_InvalidJwtForIssuerSignedJwt_Fails(t *testing.T) {
	sdJwt := SdJwtVc("slkjfaslkgdjaglj")
	context := CreateTestVerificationContext(false)

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

func Test_FailingToFetchIssuerMetadata_Fails(t *testing.T) {
	context := VerificationContext{
		IssuerMetadataFetcher: &failingMetadataFetcherNetworkError{},
		Clock:                 NewSystemClock(),
		JwtVerifier:           NewJwxJwtVerifier(),
	}
	_, err := ParseAndVerifySdJwtVc(context, validSdJwtVc_DcTypHeader)
	require.Error(t, err)
}

func Test_IssuerSignedJwt_WithInvalidTypHeader_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext()
	_, err := ParseAndVerifySdJwtVc(context, SdJwtVc(wrongIssuerSignedJwtTypHeader))
	require.Error(t, err)
}

func Test_ValidSdJwtVc_NoDisclosures_NoKbJwt(t *testing.T) {
	context := CreateDefaultVerificationContext()
	verifiedSdJwtVc, err := ParseAndVerifySdJwtVc(context, validSdJwtVc_NoDisclosuresNoKbjwt)
	require.NoError(t, err)

	require.Len(t, verifiedSdJwtVc.Disclosures, 0)
	require.Nil(t, verifiedSdJwtVc.KeyBindingJwt)
}

func Test_ValidSdJwt_MismatchingHashInKbJwt_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext()
	_, err := ParseAndVerifySdJwtVc(context, validSdJwtVc_MismatchingHashInKbJwt)
	require.Error(t, err)
}

func Test_ValidSdJwt_WithDcTypHeader_WithDisclosures_WithKbJwt_Succeeds(t *testing.T) {
	context := CreateDefaultVerificationContext()
	verifiedSdJwtVc, err := ParseAndVerifySdJwtVc(context, validSdJwtVc_DcTypHeader)
	require.NoError(t, err)

	require.Len(t, verifiedSdJwtVc.Disclosures, 2)
	require.NotNil(t, verifiedSdJwtVc.KeyBindingJwt)
}

func Test_ValidSdJwtVc_WithKbJwt_WithLegacyVcHeader_Succeeds(t *testing.T) {
	context := CreateDefaultVerificationContext()
	verifiedSdJwtVc, err := ParseAndVerifySdJwtVc(context, validSdJwtVc_VcTypHeader)
	require.NoError(t, err)

	require.Len(t, verifiedSdJwtVc.Disclosures, 2)
	require.NotNil(t, verifiedSdJwtVc.KeyBindingJwt)
}

func Test_ValidSdJwt_WithDisclosures_NoKbJwt_Succeeds(t *testing.T) {
	context := CreateDefaultVerificationContext()
	verifiedSdJwtVc, err := ParseAndVerifySdJwtVc(context, validSdJwtVc_NoKbJwt)
	require.NoError(t, err)

	require.Len(t, verifiedSdJwtVc.Disclosures, 2)
	require.Nil(t, verifiedSdJwtVc.KeyBindingJwt)
}

func Test_InvalidSdJwtVc_MissingTrailingTilde_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext()
	_, err := ParseAndVerifySdJwtVc(context, invalidSdJwtVc_MissingTrailingTilde)
	require.Error(t, err)
}

func Test_InvalidSdJwtVc_WrongKbJwtTypHeader_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext()
	_, err := ParseAndVerifySdJwtVc(context, invalidSdJwtVC_WrongKbTypHeader)
	require.Error(t, err)
}

// ==============================================================================

func Test_MismatchingSdHash_Fails(t *testing.T) {
	mismatchingSdHashConfig := newWorkingSdJwtTestConfig().withSdHash("lkasjgdlksajglskjg")
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
	noErrorTestCase(t, newWorkingSdJwtTestConfig(), "default working test sdjwtvc creator is valid")
}

func Test_FewerDisclosuresThanSdHashes_Succeeds(t *testing.T) {
	config := newWorkingSdJwtTestConfig()
	config.disclosures = []DisclosureContent{
		config.disclosures[1],
	}
	noErrorTestCase(t, config, "fewer disclosures than _sd field hashes is valid")
}

func Test_DifferentOrderDisclosures_Succeeds(t *testing.T) {
	config := newWorkingSdJwtTestConfig()
	config.disclosures = []DisclosureContent{
		config.disclosures[1],
		config.disclosures[0],
	}
	noErrorTestCase(t, config, "different order disclosures than _sd field hashes is valid")
}

func Test_NoCnfFieldAndNoKbJwt_Succeeds(t *testing.T) {
	config := newWorkingSdJwtTestConfig().withoutKbJwt()
	config.cnfPubKey = nil
	noErrorTestCase(t, config, "no cnf pub key and no kbjwt is valid")
}

func Test_NoDisclosuresWithKbJwt_Succeeds(t *testing.T) {
	config := newWorkingSdJwtTestConfig().withDisclosures([]DisclosureContent{}).withKbJwt()
	noErrorTestCase(t, config, "no disclosures but with a kbjwt is valid")
}

func Test_IssMetadataCantBeFetched_Fails(t *testing.T) {
	config := newWorkingSdJwtTestConfig()
	context := VerificationContext{
		IssuerMetadataFetcher: &failingMetadataFetcherNetworkError{},
		Clock:                 NewSystemClock(),
		JwtVerifier:           NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.Error(t, err)
}

func Test_IssLinkNotHttps_Fails(t *testing.T) {
	url := "http://openid4vc.staging.yivi.app"
	config := newWorkingSdJwtTestConfig().withIssuerUrl(url, false)
	context := VerificationContext{
		IssuerMetadataFetcher: &validTestMetadataFetcher{},
		Clock:                 NewSystemClock(),
		JwtVerifier:           NewJwxJwtVerifier(),
	}
	sdjwtvc := createTestSdJwtVc(t, config)
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.Error(t, err)
}

func Test_IssLinkNotSameAsInMetadata_Fails(t *testing.T) {
	url := "http://openid4vc.staging.yivi.app"
	config := newWorkingSdJwtTestConfig().withIssuerUrl(url, false)
	sdjwtvc := createTestSdJwtVc(t, config)
	context := VerificationContext{
		IssuerMetadataFetcher: &validTestMetadataFetcher{},
		Clock:                 NewSystemClock(),
		JwtVerifier:           NewJwxJwtVerifier(),
	}
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.Error(t, err)
}

func Test_MultipleJwksInMetadata_SecondCorrect_Succeeds(t *testing.T) {
	context := VerificationContext{
		IssuerMetadataFetcher: &validTestMetadataFetcherMultipleKeys{},
		Clock:                 NewSystemClock(),
		JwtVerifier:           NewJwxJwtVerifier(),
	}
	sdjwtvc := createTestSdJwtVc(t, newWorkingSdJwtTestConfig())
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.NoError(t, err)
}

func Test_NoSdsAtAll_Succeeds(t *testing.T) {
	config := newWorkingSdJwtTestConfig()
	config.sdClaims = nil
	config.disclosures = []DisclosureContent{}

	noErrorTestCase(t, config, "no _sd claims at all is valid (if no disclosures either)")
}

func Test_WrongKeyInIssuerMetadata_Fails(t *testing.T) {
	sdjwtvc := createTestSdJwtVc(t, newWorkingSdJwtTestConfig())
	context := VerificationContext{
		IssuerMetadataFetcher: &failingMetadataFetcherWrongIssuerKeys{},
		Clock:                 NewSystemClock(),
		JwtVerifier:           NewJwxJwtVerifier(),
	}
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.Error(t, err)
}

func Test_IatIsAfterVerification_Fails(t *testing.T) {
	config := newWorkingSdJwtTestConfig().withIssuedAt(100).withKbIssuedAt(101)
	context := VerificationContext{
		IssuerMetadataFetcher: NewHttpIssuerMetadataFetcher(),
		Clock:                 &testClock{time: 90},
		JwtVerifier:           NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.Error(t, err)
}

func Test_VerificationIsAfterExp_Fails(t *testing.T) {
	config := newWorkingSdJwtTestConfig().withIssuedAt(50).withKbIssuedAt(70).withExpiryTime(100)
	context := VerificationContext{
		IssuerMetadataFetcher: NewHttpIssuerMetadataFetcher(),
		Clock:                 &testClock{time: 200},
		JwtVerifier:           NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.Error(t, err)
}

func Test_VerificationIsBeforeNotBefore_Fails(t *testing.T) {
	config := newWorkingSdJwtTestConfig().withIssuedAt(40).withKbIssuedAt(40).withExpiryTime(100).withNotBefore(50)
	context := VerificationContext{
		IssuerMetadataFetcher: NewHttpIssuerMetadataFetcher(),
		Clock:                 &testClock{time: 45},
		JwtVerifier:           NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.Error(t, err)
}

// ==============================================================================

func errorTestCase(t *testing.T, config testSdJwtVcConfig, message string) {
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext()
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.Error(t, err, message)
}

func noErrorTestCase(t *testing.T, config testSdJwtVcConfig, message string) {
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext()
	_, err := ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.NoError(t, err, message)
}
