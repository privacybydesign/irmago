package sdjwtvc

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/didjwk"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt/sdjwttest"
	"github.com/privacybydesign/irmago/eudi/utils"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// ======================= Holder verification tests ==============================
// fails for:
// - [x] invalid jwt as the issuer signed jwt
// - [x] issuer signed jwt with key binding jwt
// - [x] typ in issuer signed jwt is not vc+sd-jwt or dc+sd-jwt
// - [x] invalid sd-jwt (missing trailing ~)
// - [x] valid self-signed x509 certificate that doesn't match a trusted certificate
// - [x] missing vct link
// - [x] clock.now + skew is before iat
// - [x] clock.now + skew is before nbf
// - [x] clock.now - skew is after exp
// - [x] empty but not missing _sd field
// - [x] unsupported _sd_alg
// - [x] failing to get issuer metadata fails the verification
// - [x] invalid disclosures (different than in _sd field)
// - [x] iss claim that is not a URI SAN of the x5c end-entity certificate
// - [x] iss claim missing and an x5c end-entity certificate without a URI SAN
// - [x] iss claim missing on the kid path, where no certificate can supply the issuer

// success for
// - [x] iss link is non-https, but is accepted (for testing purposes)
// - [x] iss claim missing entirely (OPTIONAL claim; Issuer stays nil)
// - [x] sub claim missing entirely (OPTIONAL claim; Subject stays nil)
// - [x] missing _sd_alg claim, falls back to sha-256
// - [x] valid SD-JWT, no disclosures, no KB-JWT
// - [x] valid SD-JWT, with disclosures, no KB-JWT
// - [x] baseline generated valid sd-jwt vc with disclosures, issuer signed jwt and x5c
// - [x] less disclosures than are in the _sd field
// - [x] different orders for disclosures
// - [x] issuer signed jwt doesn't contain any sd's
// - [x] valid self-signed x509 certificate with DNS/URI value that matches `iss` value
// - [x] valid x509 certificate chain with DNS/URI value that matches `iss` value
// - [x] clock.now - 1 minute is before iat (valid because of skew)
// - [x] clock.now - 1 minute is before nbf (valid because of skew)
// - [x] clock.now + 1 minute is after exp (valid because of skew)
// - [x] iss claim present: it is the resolved issuer identifier
// - [x] iss claim missing: the certificate's URI SAN is the resolved issuer identifier
// - [x] kid path with a did:jwk iss: the DID is the resolved issuer identifier

func Test_HolderVerificationProcessor_InvalidJwtForIssuerSignedJwt_Fails(t *testing.T) {
	sdJwt := SdJwtVc("slkjfaslkgdjaglj")
	context := CreateTestVerificationContext()

	holderVerifier := NewHolderVerificationProcessor(context)
	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdJwt))

	require.Error(t, err)
}

func Test_HolderVerificationProcessor_MissingSdAlg_FallbackToSha256_Succeeds(t *testing.T) {
	missingSdAlgField := newWorkingSdJwtVcTestConfig()
	missingSdAlgField.sdAlg = nil
	noErrorTestCaseHolder(t, missingSdAlgField, "missing _sd_alg field falls back to sha-256")
}

func Test_HolderVerificationProcessor_IssuerSignedJwt_WithKeyBindingJwt_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	holderVerifier := NewHolderVerificationProcessor(context)
	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(validSdJwtVc_VcTypHeader_WithKbJwt))

	require.Error(t, err, "failed to parse JWT: jwt.Parse: failed to parse token: jws.Verify: key provider 0 failed: invalid 'typ' header: jwt")
}

func Test_HolderVerificationProcessor_IssuerSignedJwt_WithInvalidTypHeader_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	holderVerifier := NewHolderVerificationProcessor(context)
	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(wrongIssuerSignedJwtTypHeader))

	require.Error(t, err, "failed to parse JWT: jwt.Parse: failed to parse token: jws.Verify: key provider 0 failed: invalid 'typ' header: jwt")
}

func Test_HolderVerificationProcessor_BothX5cAndKidHeaders_Fails(t *testing.T) {
	// A JWT carrying both x5c and kid must be rejected: if both were accepted the kid
	// branch would overwrite the x5c key provider and the X.509 trust/CRL check would be
	// silently skipped, allowing a forged credential to verify against the kid-resolved key.
	bothKeyReferences := newWorkingSdJwtVcTestConfig().
		withKidHeader("did:jwk:attacker#0")
	errorTestCaseHolder(t, bothKeyReferences, "both 'x5c' and 'kid' headers are present")
}

func Test_HolderVerificationProcessor_InvalidSdJwtVc_MissingTrailingTilde_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(invalidSdJwtVc_MissingTrailingTilde))
	require.Error(t, err)
}

// ─── optional iss / sub ──────────────────────────────────────────────────────
// draft-ietf-oauth-sd-jwt-vc makes both `iss` and `sub` OPTIONAL: `iss` may be
// conveyed by other means (here: the x5c end-entity certificate), and `sub` is
// only a hint. Both are therefore modelled as pointers, and absence must be
// preserved as nil rather than collapsed into "".

func Test_HolderVerificationProcessor_MissingIssuerUrl_Succeeds_IssuerIsNil(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig()
	config.issuerUrl = nil

	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	verified, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err, "iss is optional when the issuer is conveyed by the x5c certificate")
	require.Nil(t, verified.IssuerSignedJwtPayload.Issuer, "an absent iss must stay absent, not become an empty string")
}

func Test_HolderVerificationProcessor_IssuerUrlPresent_IssuerIsSet(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig()

	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	verified, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
	require.NotNil(t, verified.IssuerSignedJwtPayload.Issuer)
	require.Equal(t, "https://openid4vc.staging.yivi.app", *verified.IssuerSignedJwtPayload.Issuer)
}

// ─── issuer identifier resolution ────────────────────────────────────────────
// Whoever consumes a verified credential needs an issuer to attribute it to, even
// though `iss` is OPTIONAL. VerifiedSdJwtVc.IssuerIdentifier carries that identity,
// resolved per draft-ietf-oauth-sd-jwt-vc §2.5: `iss` when present, otherwise the
// subject of the x5c end-entity certificate. Verification fails when neither is
// available, so the identifier is never empty on success.

func Test_HolderVerificationProcessor_IssPresent_IssuerIdentifierIsIss(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig() // iss == the certificate's URI SAN

	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	verified, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
	require.Equal(t, "https://openid4vc.staging.yivi.app", verified.IssuerIdentifier)
}

func Test_HolderVerificationProcessor_MissingIss_IssuerIdentifierFromCertificateUriSan(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig()
	config.issuerUrl = nil

	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	verified, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err, "iss is optional when the issuer is conveyed by the x5c certificate")
	require.Equal(t, "https://openid4vc.staging.yivi.app", verified.IssuerIdentifier,
		"an absent iss falls back to the URI SAN of the end-entity certificate")
	require.Nil(t, verified.IssuerSignedJwtPayload.Issuer,
		"the resolved identifier must not be written back into the claim set")
}

func Test_HolderVerificationProcessor_IssNotInCertificateSans_Fails(t *testing.T) {
	// An issuer holding a certificate trusted for one identity must not be able to
	// issue credentials in the name of another.
	config := newWorkingSdJwtVcTestConfig().
		withIssuerUrl("https://attacker.example.com", false)

	errorTestCaseHolder(t, config, "is not a SAN of the issuer certificate")
}

func Test_HolderVerificationProcessor_MissingIss_CertificateWithoutUriSan_Fails(t *testing.T) {
	// Neither source of identity is available: no iss claim, and an end-entity
	// certificate that carries no URI SAN to fall back to.
	config, context := newGeneratedIssuerConfig(t, "issuer.example.com", testdata.PkiOption_MissingUriSan|testdata.PkiOption_MissingDnsSan)

	sdjwtvc := createTestSdJwtVc(t, config)

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.ErrorContains(t, err, "failed to obtain issuer URL from certificate")
}

func Test_HolderVerificationProcessor_GeneratedCertificateWithUriSan_ResolvesIssuerIdentifier(t *testing.T) {
	// Control for the test above: the same generated PKI, but with the URI SAN in
	// place, resolves the issuer identifier instead of failing.
	config, context := newGeneratedIssuerConfig(t, "issuer.example.com", testdata.PkiOption_None)

	sdjwtvc := createTestSdJwtVc(t, config)

	verified, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example.com", verified.IssuerIdentifier)
}

func Test_HolderVerificationProcessor_KidHeader_IssuerIdentifierIsIss(t *testing.T) {
	// On the kid path there is no certificate, so iss is the only source of identity —
	// here a did:jwk, which is also what the signing key is resolved from.
	config, context, did := newDidJwkIssuerConfig(t)

	sdjwtvc := createTestSdJwtVc(t, config)

	verified, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
	require.Equal(t, did, verified.IssuerIdentifier)
}

func Test_HolderVerificationProcessor_KidHeaderWithoutIss_Fails(t *testing.T) {
	// Same credential as the test above with only the iss claim dropped. Without a
	// certificate to fall back to there is no identity left, and the credential is in
	// fact already rejected during signature verification, because DidKeyProvider
	// resolves the signing key from iss too — the explicit check in
	// parseAndVerifyIssuerSignedJwt guards the case defensively.
	config, context, _ := newDidJwkIssuerConfig(t)
	config.issuerUrl = nil

	sdjwtvc := createTestSdJwtVc(t, config)

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.Error(t, err)
}

// newDidJwkIssuerConfig builds a working SD-JWT VC config signed on the kid path: no
// x5c header, and an iss claim holding the did:jwk that the issuer test key derives to.
// It returns the config, a verification context for it, and that DID. The context
// carries no trust anchors, because on the kid path the signing key comes from the DID
// itself and the X.509 material is never consulted.
func newDidJwkIssuerConfig(t *testing.T) (*testSdJwtVcConfig, SdJwtVcVerificationContext, string) {
	issuerKey, err := readTestIssuerPrivateKey()
	require.NoError(t, err)

	pubJwk, err := jwk.Import(issuerKey.Public())
	require.NoError(t, err)
	doc, err := (&didjwk.DocumentBuilder{}).FromJwk(pubJwk)
	require.NoError(t, err)

	config := newWorkingSdJwtVcTestConfig().
		withIssuerUrl(doc.ID, false).
		withKidHeader(doc.ID + "#0")
	config.x5cHeader = nil

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{},
		Clock:                   eudi_jwt.NewSystemClock(),
		JwtVerifier:             sdjwt.NewJwxJwtVerifier(),
	}

	return config, context, doc.ID
}

// newGeneratedIssuerConfig builds a working SD-JWT VC config signed by a freshly
// generated end-entity certificate for hostname, together with a verification context
// that trusts that certificate's chain. opts is forwarded to the certificate
// generation, so a test can ask for an issuer certificate that deliberately lacks a
// URI SAN. The `iss` claim is left out, since a generated certificate never matches
// the shared test fixture's iss; a caller that wants one sets it to a URI SAN of the
// generated certificate.
func newGeneratedIssuerConfig(t *testing.T, hostname string, opts testdata.PkiGenerationOptions) (*testSdJwtVcConfig, SdJwtVcVerificationContext) {
	_, rootCert, caKeys, caCerts, _ := testdata.CreateTestPkiHierarchy(
		t, testdata.CreateDistinguishedName("ROOT CERT"), 1, testdata.PkiOption_None, nil)
	issuerKey, issuerCert, _ := testdata.CreateEndEntityCertificate(
		t, testdata.CreateDistinguishedName(hostname), hostname, caCerts[0], caKeys[0], "", opts)

	x5c, err := utils.ConvertPemCertificateChainToX5cFormat([]*x509.Certificate{issuerCert})
	require.NoError(t, err)

	config := newWorkingSdJwtVcTestConfig().withIssuerPrivateKey(issuerKey)
	config.x5cHeader = x5c
	config.issuerUrl = nil

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(caCerts[0])

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
		Clock:       eudi_jwt.NewSystemClock(),
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
	}

	return config, context
}

func Test_HolderVerificationProcessor_MissingSubject_SubjectIsNil(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig() // no sub claim

	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	verified, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
	require.Nil(t, verified.IssuerSignedJwtPayload.Subject)
}

func Test_HolderVerificationProcessor_SubjectPresent_SubjectIsSet(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig().withSubject("urn:example:holder-42")

	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	verified, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
	require.NotNil(t, verified.IssuerSignedJwtPayload.Subject)
	require.Equal(t, "urn:example:holder-42", *verified.IssuerSignedJwtPayload.Subject)
}

func Test_HolderVerificationProcessor_ValidButUntrusted_SelfSigned_X509Cert_Fails(t *testing.T) {
	runCertChainTestCase(t, x509TestConfig{
		IssuerCert: testdata.IssuerCert_irma_app_Bytes,
		IssUrl:     "https://irma.app",
		ShouldFail: true,
	})
}

func Test_HolderVerificationProcessor_MissingVct_Fails(t *testing.T) {
	missingVct := newWorkingSdJwtVcTestConfig()
	missingVct.vct = nil
	errorTestCaseHolder(t, missingVct, "missing vct field")
}

func Test_HolderVerificationProcessor_IatIsAfterVerification_Fails(t *testing.T) {
	now := time.Now().Unix()
	iat := now + ClockSkewInSeconds + 100

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(&iat)

	context := SdJwtVcVerificationContext{
		Clock:       &testClock{time: now},
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.Error(t, err)
}

func Test_HolderVerificationProcessor_VerificationIsAfterExp_Fails(t *testing.T) {
	now := time.Now().Unix()
	exp := now - ClockSkewInSeconds - 100

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(&now).
		withExpiryTime(&exp)

	context := SdJwtVcVerificationContext{
		Clock:       &testClock{time: now},
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.Error(t, err)
}

func Test_HolderVerificationProcessor_VerificationIsBeforeNotBefore_Fails(t *testing.T) {
	now := time.Now().Unix()
	nbf := now + ClockSkewInSeconds + 50
	exp := int64(100)

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(&now).
		withExpiryTime(&exp).
		withNotBefore(&nbf)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(),
		},
		Clock:       &testClock{time: now},
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.Error(t, err)
}

func Test_HolderVerificationProcessor_EmptyButNotMissingSdField_Fails(t *testing.T) {
	emptyNotMissingSdField := newWorkingSdJwtVcTestConfig().
		withSdClaims([]sdjwt.DisclosureContent{}, iana.SHA256).
		withDisclosures([]sdjwt.DisclosureContent{})
	errorTestCaseHolder(t, emptyNotMissingSdField, "failed to parse sd field: when the _sd field is present it may not be empty")
}

func Test_HolderVerificationProcessor_UnsupportedSdAlg_Fails(t *testing.T) {
	wrongSdAlgField := newWorkingSdJwtVcTestConfig().withSdAlg("SHA-null")
	errorTestCaseHolder(t, wrongSdAlgField, "unsupported _sd_alg: SHA-null")
}

func Test_HolderVerificationProcessor_ValidSdJwtVc_NoDisclosures_NoKbJwt_Succeeds(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	holderVerifier := NewHolderVerificationProcessor(context)

	verifiedSdJwtVc, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(validSdJwtVc_NoDisclosuresNoKbjwt))
	require.NoError(t, err)

	require.Len(t, verifiedSdJwtVc.Disclosures, 0)
	require.Nil(t, verifiedSdJwtVc.KeyBindingJwt)
}

func Test_HolderVerificationProcessor_BaselineGeneratedSdJwtVc_Succeeds(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig()
	noErrorTestCaseHolder(t, config, "default working test sdjwtvc creator is valid")
}

func Test_HolderVerificationProcessor_StatusClaim_RoundtripsThroughPayload(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig().
		withStatusListReference("https://issuer.example/sl/1", 42)
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	verified, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
	require.NotNil(t, verified.IssuerSignedJwtPayload.Status)
	require.NotNil(t, verified.IssuerSignedJwtPayload.Status.StatusList)
	require.Equal(t, "https://issuer.example/sl/1", verified.IssuerSignedJwtPayload.Status.StatusList.URI)
	require.Equal(t, uint64(42), verified.IssuerSignedJwtPayload.Status.StatusList.Index)
}

func Test_HolderVerificationProcessor_StatusClaim_AbsentLeavesPayloadStatusNil(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig() // no status reference
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	verified, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
	require.Nil(t, verified.IssuerSignedJwtPayload.Status)
}

func Test_HolderVerificationProcessor_StatusCheck_ValidList_Accepts(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://openid4vc.staging.yivi.app",
		Bits:     1,
		Statuses: map[uint64]uint8{7: 0}, // Valid at idx 7
	})

	config := newWorkingSdJwtVcTestConfig().withStatusListReference(srv.URL(), 7)
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.StatusChecker = statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_HolderVerificationProcessor_StatusCheck_InvalidList_Rejects(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://openid4vc.staging.yivi.app",
		Bits:     1,
		Statuses: map[uint64]uint8{7: 1}, // Invalid at idx 7
	})

	config := newWorkingSdJwtVcTestConfig().withStatusListReference(srv.URL(), 7)
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.StatusChecker = statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.ErrorContains(t, err, "credential status is invalid")
}

// Holder verification is the exact code path OpenID4VCI issuance runs, so this
// asserts that a credential whose status is non-VALID at issuance time is
// rejected — not only the revoked (Invalid, 0x01) case above but also
// Suspended (0x02), which requires bits >= 2. The gate is fail-closed: only
// StatusValid is accepted, every other value aborts the issuance.
func Test_HolderVerificationProcessor_StatusCheck_SuspendedList_RejectsAtIssuance(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://openid4vc.staging.yivi.app",
		Bits:     2,
		Statuses: map[uint64]uint8{7: 2}, // Suspended at idx 7
	})

	config := newWorkingSdJwtVcTestConfig().withStatusListReference(srv.URL(), 7)
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.StatusChecker = statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.ErrorContains(t, err, "credential status is suspended")
}

func Test_HolderVerificationProcessor_StatusCheck_UnreachableURI_FailsClosed(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	config := newWorkingSdJwtVcTestConfig().withStatusListReference("http://127.0.0.1:0/nope", 0)
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.StatusChecker = statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.ErrorContains(t, err, "status list check failed")
}

func Test_HolderVerificationProcessor_StatusCheck_NilCheckerLeavesClaimUnverified(t *testing.T) {
	// Even with a status reference present, a nil StatusChecker
	// must not reject the credential — this is the back-compat path
	// for callers that haven't opted into status checks.
	config := newWorkingSdJwtVcTestConfig().withStatusListReference("https://issuer.example/sl/1", 0)
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	// context.StatusChecker is nil.

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_HolderVerificationProcessor_StatusCheck_NoStatusClaim_PassesWithCheckerConfigured(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	config := newWorkingSdJwtVcTestConfig() // no status reference
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.StatusChecker = statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_HolderVerificationProcessor_FewerDisclosuresThanSdHashes_Succeeds(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig()
	config.disclosures = []sdjwt.DisclosureContent{
		config.disclosures[1],
	}
	noErrorTestCaseHolder(t, config, "fewer disclosures than _sd field hashes is valid")
}

func Test_HolderVerificationProcessor_DifferentOrderDisclosures_Succeeds(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig()
	config.disclosures = []sdjwt.DisclosureContent{
		config.disclosures[1],
		config.disclosures[0],
	}
	noErrorTestCaseHolder(t, config, "different order disclosures than _sd field hashes is valid")
}

func Test_HolderVerificationProcessor_NoSdsAtAll_Succeeds(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig()

	config.sdClaims = nil
	config.disclosures = []sdjwt.DisclosureContent{}

	noErrorTestCaseHolder(t, config, "no _sd claims at all is valid (if no disclosures either)")
}

func Test_HolderVerificationProcessor_ValidLeafCertOnly_Succeeds(t *testing.T) {
	runCertChainTestCase(t, x509TestConfig{
		IssuerCert:                     testdata.IssuerCert_irma_app_Bytes,
		VerifierTrustedIssuerCertChain: testdata.IssuerCert_irma_app_Bytes,
		IssUrl:                         "https://irma.app",
		ShouldFail:                     false,
	})
}

func Test_HolderVerificationProcessor_Valid_X509Chain_Succeeds(t *testing.T) {
	runCertChainTestCase(t, x509TestConfig{
		IssuerCert:                     testdata.IssuerCert_irma_app_Bytes,
		VerifierTrustedIssuerCertChain: testdata.IssuerCertChain_irma_app_Bytes,
		IssUrl:                         "https://irma.app",
		ShouldFail:                     false,
	})
}

func Test_HolderVerificationProcessor_VerificationMinusOneMinuteIsBeforeIat_GivenClockSkew_Success(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcTestConfig().withIssuedAt(&now)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now - 60},
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_HolderVerificationProcessor_VerificationPlusOneMinuteIsAfterExp_GivenClockSkew_Success(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(&now).
		withExpiryTime(&now)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now + 60},
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_HolderVerificationProcessor_VerificationMinusOneMinuteIsBeforeNotBefore_GivenClockSkew_Success(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(&now).
		withNotBefore(&now)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now - 60},
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_HolderVerificationProcessor_TimeFieldsAreParsedCorrectly(t *testing.T) {
	now := time.Now().Unix()
	exp := now + 86400 // 1 day from now
	nbf := now - 60

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(&now).
		withExpiryTime(&exp).
		withNotBefore(&nbf)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now},
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	result, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)

	require.Equal(t, now, *result.IssuerSignedJwtPayload.IssuedAt, "IssuedAt should match the iat claim")
	require.Equal(t, exp, *result.IssuerSignedJwtPayload.Expiry, "Expiry should match the exp claim")
	require.Equal(t, nbf, *result.IssuerSignedJwtPayload.NotBefore, "NotBefore should match the nbf claim")
}

func Test_HolderVerificationProcessor_MissingTimeFieldsAreParsedCorrectly(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(nil).
		withExpiryTime(nil).
		withNotBefore(nil)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now},
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	result, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)

	require.Nil(t, result.IssuerSignedJwtPayload.IssuedAt, "IssuedAt should be nil")
	require.Nil(t, result.IssuerSignedJwtPayload.Expiry, "Expiry should be nil")
	require.Nil(t, result.IssuerSignedJwtPayload.NotBefore, "NotBefore should be nil")
}

func Test_HolderVerificationProcessor_ProcessedSdJwtPayload_ContainsDisclosedClaims(t *testing.T) {
	// Arrange: build a credential with two selective-disclosure claims (email + domain),
	// matching what an OpenID4VCI issuer would produce.
	now := time.Now().Unix()
	exp := now + 86400

	disclosures, err := sdjwt.MultipleNewDisclosureContents(map[string]string{
		"email":  "holder@example.com",
		"domain": "example.com",
	})
	require.NoError(t, err)

	config := newWorkingSdJwtVcTestConfig().
		withVct("test.test.email").
		withIssuedAt(&now).
		withExpiryTime(&exp).
		withSdClaims(disclosures, iana.SHA256).
		withDisclosures(disclosures)

	sdjwtvc := createTestSdJwtVc(t, config)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now},
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
	}
	holderVerifier := NewHolderVerificationProcessor(context)

	// Act
	result, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))

	// Assert
	require.NoError(t, err)

	payload := result.ProcessedSdJwtPayload

	// Standard JWT claims must be present
	require.Equal(t, "https://openid4vc.staging.yivi.app", payload[jwt.IssuerKey], "iss claim should be present in processed payload")
	require.Equal(t, "test.test.email", payload[VerifiableCredentialTypeKey], "vct claim should be present in processed payload")

	// Selectively-disclosed claims must be embedded directly in the processed payload
	require.Equal(t, "holder@example.com", payload["email"], "email disclosure should be embedded in processed payload")
	require.Equal(t, "example.com", payload["domain"], "domain disclosure should be embedded in processed payload")

	// _sd and _sd_alg must be stripped from the processed payload
	_, hasSd := payload[sdjwt.SdKey]
	require.False(t, hasSd, "_sd field should be removed from processed payload")
	_, hasSdAlg := payload[sdjwt.SdAlgKey]
	require.False(t, hasSdAlg, "_sd_alg field should be removed from processed payload")
}

// ======================= Verifier verification tests ==============================
// fails for:
// - [x] required kb-jwt, but missing
// - [x] invalid kb-jwt typ header
// - [x] missing sd_hash in kb-jwt
// - [x] sd_hash in KB-JWT does not match calculated hash
// - [x] missing cnf field in issuer signed JWT, but kb-jwt present
// - [x] kb-jwt nonce does not match expected nonce
// - [x] kb-jwt aud does not match expected audience (client_id)
//
// succeeds for:
// - [x] required kb-jwt, valid sd-jwt, matching hash in kb-jwt
// - [x] non-required kb-jwt, no KB-JWT present
// - [x] kb-jwt nonce matches expected nonce
// - [x] kb-jwt aud matches expected audience (client_id)

func Test_VerifierVerificationProcessor_RequiredKbJwt_NoKbJwtInSdJwt_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "nonce"
	verifierVerificationProcessor := NewVerifierVerificationProcessor(true, context)
	_, err := verifierVerificationProcessor.ParseAndVerifySdJwtVc(SdJwtVcKb(validSdJwtVc_DcTypHeader_WithoutKbJwt))
	require.ErrorContains(t, err, "key binding jwt is required, but not present in sdjwtvc")
}

func Test_VerifierVerificationProcessor_InvalidSdJwtVc_WrongKbJwtTypHeader_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "nonce"
	holderVerifier := NewVerifierVerificationProcessor(true, context)
	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(invalidSdJwtVC_WrongKbTypHeader))
	require.Error(t, err)
}

func Test_VerifierVerificationProcessor_NoSdHash_Fails(t *testing.T) {
	noHashConfig := newWorkingSdJwtVcKbTestConfig().withoutAnySdHash()
	errorTestCaseVerifier(t, noHashConfig, "issuer signed jwt hash missing in kbjwt")
}

func Test_VerifierVerificationProcessor_RequiredKbJwt_ValidSdJwt_MismatchingHashInKbJwt_Fails(t *testing.T) {
	sdHashMismatchInKb := newWorkingSdJwtVcKbTestConfig().withSdHash("12356")
	errorTestCaseVerifier(t, sdHashMismatchInKb, "issuer signed jwt hash doesn't equal sd_hash found in kbjwt")
}

func Test_VerifierVerificationProcessor_NoCnfFieldInIssuerSignedJwt_WithKbJwt_Fails(t *testing.T) {
	noCnfFieldWithKbJwt := newWorkingSdJwtVcKbTestConfig()
	noCnfFieldWithKbJwt.cnfPubKey = nil
	errorTestCaseVerifier(t, noCnfFieldWithKbJwt, "issuer signed jwt is missing holder key (cnf) required to verify kbjwt signature")
}

func Test_VerifierVerificationProcessor_RequiredKbJwt_WithKbJwtInSdJwt_Succeeds(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "nonce"
	context.ExpectedAudience = "Verifier" // The testdata contains a KB-JWT with aud "Verifier", which would usually be something like "<client_id_prefix>:<orig_client_id>"
	verifierVerificationProcessor := NewVerifierVerificationProcessor(true, context)
	_, err := verifierVerificationProcessor.ParseAndVerifySdJwtVc(SdJwtVcKb(validSdJwtVc_DcTypHeader_WithKbJwt))
	require.NoError(t, err)
}

func Test_VerifierVerificationProcessor_KbJwtNonce_MatchesExpectedNonce_Succeeds(t *testing.T) {
	realNonce := "abc123-real-nonce"

	config := newWorkingSdJwtVcKbTestConfig()
	config.withKbNonce(realNonce)

	sdjwtvc := createTestSdJwtVcKb(t, config)

	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = realNonce
	context.ExpectedAudience = "Verifier" // The testdata contains a KB-JWT with aud "Verifier", which would usually be something like "<client_id_prefix>:<orig_client_id>"

	verifier := NewVerifierVerificationProcessor(true, context)
	_, err := verifier.ParseAndVerifySdJwtVc(sdjwtvc)
	require.NoError(t, err)
}

func Test_VerifierVerificationProcessor_KbJwtNonce_DoesNotMatchExpectedNonce_Fails(t *testing.T) {
	config := newWorkingSdJwtVcKbTestConfig()
	config.withKbNonce("nonce-in-kbjwt")

	sdjwtvc := createTestSdJwtVcKb(t, config)

	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "different-expected-nonce"

	verifier := NewVerifierVerificationProcessor(true, context)
	_, err := verifier.ParseAndVerifySdJwtVc(sdjwtvc)
	require.ErrorContains(t, err, "nonce")
}

func Test_VerifierVerificationProcessor_KbJwtAudience_MatchesExpectedAudience_Succeeds(t *testing.T) {
	// The KB-JWT `aud` must equal the `client_id` from the OpenID4VP authorization request.
	clientID := "x509_san_dns:client.example.org"

	config := newWorkingSdJwtVcKbTestConfig()
	config.withAudience(clientID)

	sdjwtvc := createTestSdJwtVcKb(t, config)

	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "nonce"
	context.ExpectedAudience = clientID

	verifier := NewVerifierVerificationProcessor(true, context)
	_, err := verifier.ParseAndVerifySdJwtVc(sdjwtvc)
	require.NoError(t, err)
}

func Test_VerifierVerificationProcessor_KbJwtAudience_DoesNotMatchExpectedAudience_Fails(t *testing.T) {
	// The KB-JWT `aud` must equal the `client_id` from the OpenID4VP authorization request.
	config := newWorkingSdJwtVcKbTestConfig()
	config.withAudience("x509_san_dns:client.example.org")

	sdjwtvc := createTestSdJwtVcKb(t, config)

	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "nonce"
	context.ExpectedAudience = "x509_san_dns:different-client.example.org"

	verifier := NewVerifierVerificationProcessor(true, context)
	_, err := verifier.ParseAndVerifySdJwtVc(sdjwtvc)
	require.ErrorContains(t, err, "aud")
}

func Test_VerifierVerificationProcessor_NonRequiredKbJwt_NoKbJwtInSdJwt_Succeeds(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	verifierVerificationProcessor := NewVerifierVerificationProcessor(false, context)
	_, err := verifierVerificationProcessor.ParseAndVerifySdJwtVc(SdJwtVcKb(validSdJwtVc_DcTypHeader_WithoutKbJwt))
	require.NoError(t, err)
}

// ================================= Helpers ===================================

func errorTestCaseHolder(t *testing.T, config *testSdJwtVcConfig, message string) {
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	holderVerifier := NewHolderVerificationProcessor(context)
	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.ErrorContains(t, err, message)
}

func noErrorTestCaseHolder(t *testing.T, config *testSdJwtVcConfig, message string) {
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	holderVerifier := NewHolderVerificationProcessor(context)
	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err, message)
}

func errorTestCaseVerifier(t *testing.T, config *testSdJwtVcKbConfig, message string) {
	sdjwtvc := createTestSdJwtVcKb(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "nonce"
	verifierVerificationProcessor := NewVerifierVerificationProcessor(true, context)
	_, err := verifierVerificationProcessor.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.ErrorContains(t, err, message)
}

func runCertChainTestCase(t *testing.T, config x509TestConfig) {
	chain, err := utils.ParsePemCertificateChainToX5cFormat(config.IssuerCert)
	require.NoError(t, err)

	creator := sdjwttest.NewEcdsaJwtCreatorWithIssuerTestKey()

	builtSdJwtVc, err := NewSdJwtVcBuilder().
		WithPayload(
			sdjwt.Claim(jwt.IssuerKey, config.IssUrl),
			sdjwt.Claim(jwt.ExpirationKey, time.Now().Unix()),
			sdjwt.Claim(sdjwt.SdAlgKey, iana.SHA256),
			sdjwt.Claim(VerifiableCredentialTypeKey, "test.test.email"),
			sdjwt.SdClaim("email", "test@gmail.com"),
		).
		WithIssuerCertificateChain(chain).Build(creator)

	require.NoError(t, err)

	verifyOpts, err := utils.CreateX509VerifyOptionsFromCertChain(config.VerifierTrustedIssuerCertChain)
	require.NoError(t, err)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: *verifyOpts,
		},
		Clock:       eudi_jwt.NewSystemClock(),
		JwtVerifier: sdjwt.NewJwxJwtVerifier(),
	}

	holderVerifier := NewHolderVerificationProcessor(context)
	_, err = holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(builtSdJwtVc))

	if config.ShouldFail {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}
}
