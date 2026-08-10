package openid4vp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	mathBig "math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

const EndEntityCN = "END ENTITY CERT"

// The gate is internal validity: signature against the certificate the
// client_id binds the request to, presented within its own validity window.
// Anchoring is not the gate's question — a chain to a root the wallet does not
// anchor passes, with the certificate's contents demoted to the verifier's own
// word — so the failure tests split in two: broken requests still fail, while
// legitimate-looking strangers now pass unattested.
func TestVerifierValidator(t *testing.T) {
	// Happy flow tests
	t.Run("ParseAndVerifyAuthorizationRequest validates a JWT successfully", testParseAndVerifyAuthorizationRequestSuccess)
	t.Run("ParseAndVerifyAuthorizationRequest attests certificate CN when missing scheme data in x5c", testParseAndVerifyAuthorizationRequestMissingSchemeData_AssumesThirdPartyCertificate_AttestsCertificateCommonName)
	t.Run("ParseAndVerifyAuthorizationRequest attests certificate CN when invalid ASN scheme data in x5c", testParseAndVerifyAuthorizationRequestInvalidAsnSchemeData_AssumesThirdPartyCertificate_AttestsCertificateCommonName)
	t.Run("ParseAndVerifyAuthorizationRequest attests certificate CN when invalid JSON scheme data in x5c", testParseAndVerifyAuthorizationRequestInvalidJsonSchemeData_AssumesThirdPartyCertificate_AttestsCertificateCommonName)

	// Unhappy flow tests
	t.Run("ParseAndVerifyAuthorizationRequest fails with invalid client_id", testParseAndVerifyAuthorizationRequestFailureForInvalidClientID)
	t.Run("ParseAndVerifyAuthorizationRequest fails when the client_id hostname is not in the certificate", testParseAndVerifyAuthorizationRequestFailureHostnameMismatch)

	// Unhappy flow tests for x5c related errors
	t.Run("ParseAndVerifyAuthorizationRequest fails with missing x5c header", testParseAndVerifyAuthorizationRequestFailureMissingX5C)
	t.Run("ParseAndVerifyAuthorizationRequest fails with empty x5c array", testParseAndVerifyAuthorizationRequestFailureEmptyX5cArray)
	t.Run("ParseAndVerifyAuthorizationRequest fails with expired x5c certificate", testParseAndVerifyAuthorizationRequestFailureExpiredX5C)

	// The certificate channel demotes rather than blocks: a certificate no
	// anchor stands behind — revoked, unknown root, broken chain — passes the
	// gate with its contents counted as self-asserted.
	t.Run("ParseAndVerifyAuthorizationRequest demotes a revoked x5c certificate to self-asserted", testParseAndVerifyAuthorizationRequestRevokedX5C_DemotesToSelfAsserted)
	t.Run("ParseAndVerifyAuthorizationRequest demotes an unknown root to self-asserted", testParseAndVerifyAuthorizationRequestMissingRoot_DemotesToSelfAsserted)
	t.Run("ParseAndVerifyAuthorizationRequest demotes an expired root to self-asserted", testParseAndVerifyAuthorizationRequestExpiredRoot_DemotesToSelfAsserted)
	t.Run("ParseAndVerifyAuthorizationRequest demotes a missing intermediate to self-asserted", testParseAndVerifyAuthorizationRequestMissingIntermediate_DemotesToSelfAsserted)
	t.Run("ParseAndVerifyAuthorizationRequest demotes an expired intermediate to self-asserted", testParseAndVerifyAuthorizationRequestExpiredIntermediate_DemotesToSelfAsserted)

	// x509_hash scheme tests
	t.Run("ParseAndVerifyAuthorizationRequest validates an x509_hash JWT successfully", testParseAndVerifyAuthorizationRequestSuccessX509Hash)
	t.Run("ParseAndVerifyAuthorizationRequest fails when x509_hash doesn't match the leaf certificate", testParseAndVerifyAuthorizationRequestFailureX509HashMismatch)

	// client_metadata tests: the request's own account of the verifier is kept
	// apart from what the certificate attests.
	t.Run("ParseAndVerifyAuthorizationRequest keeps certificate scheme data attested when client_metadata is absent", testParseAndVerifyAuthorizationRequestNilClientMetadata_AttestsCertificateSchemeData)
	t.Run("ParseAndVerifyAuthorizationRequest keeps certificate scheme data attested when client_metadata has no client_name", testParseAndVerifyAuthorizationRequestClientMetadataWithoutClientName_AttestsCertificateSchemeData)
	t.Run("ParseAndVerifyAuthorizationRequest surfaces client_metadata client_name as self-asserted", testParseAndVerifyAuthorizationRequestClientMetadataWithClientName_IsSelfAsserted)
	t.Run("ParseAndVerifyAuthorizationRequest never takes a client_metadata logo", testParseAndVerifyAuthorizationRequestClientMetadataLogo_IsIgnored)

	// The one hard rule: an anchored certificate's authorization is enforced
	// whatever else the request carries; an unanchored certificate carries no
	// authorization worth enforcing.
	t.Run("ParseAndVerifyAuthorizationRequest enforces the certificate's authorization even with client_metadata present", testParseAndVerifyAuthorizationRequestQueryValidation_EnforcedWithClientMetadata)
	t.Run("ParseAndVerifyAuthorizationRequest does not enforce authorization from an unanchored certificate", testParseAndVerifyAuthorizationRequestQueryValidation_SkippedWhenUnanchored)
}

func testParseAndVerifyAuthorizationRequestFailureEmptyX5cArray(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Header["x5c"] = []string{}
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to get end-entity certificate from x5c header: auth request token contains empty x5c array in the header")
}

func testParseAndVerifyAuthorizationRequestSuccess(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_None)

	// Parse and verify the authorization request
	claims, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, claims)
	require.NotNil(t, requestor)
	require.NotNil(t, requestor.Certificate)
	require.NotNil(t, requestor.Attested, "an anchored certificate's account of the party is attested")
	require.Nil(t, requestor.SelfAsserted, "the request asserted nothing of its own")

	// Assert requestor data
	attested := requestor.Attested
	require.Equal(t, "https://portal.yivi.app/organizations/yivi", attested.Registration)

	require.NotEmpty(t, attested.Organization.LegalName)
	require.Equal(t, "Yivi B.V.", attested.Organization.LegalName["en"])
	require.Equal(t, "Yivi B.V.", attested.Organization.LegalName["nl"])

	require.Equal(t, "image/png", attested.Organization.Logo.MimeType)
	require.NotEmpty(t, attested.Organization.Logo.Data)

	require.NotEmpty(t, attested.RelyingParty.AuthorizedQueryableAttributeSets)
	require.Equal(t, "test.test.email", attested.RelyingParty.AuthorizedQueryableAttributeSets[0].Credential)
	require.NotEmpty(t, attested.RelyingParty.AuthorizedQueryableAttributeSets[0].Attributes)
	require.Equal(t, "email", attested.RelyingParty.AuthorizedQueryableAttributeSets[0].Attributes[0])
	require.Equal(t, "domain", attested.RelyingParty.AuthorizedQueryableAttributeSets[0].Attributes[1])

	require.NotEmpty(t, attested.RelyingParty.RequestPurpose)
	require.Equal(t, "Unit testing", attested.RelyingParty.RequestPurpose["en"])
	require.Equal(t, "Unit testen", attested.RelyingParty.RequestPurpose["nl"])
}

func testParseAndVerifyAuthorizationRequestMissingSchemeData_AssumesThirdPartyCertificate_AttestsCertificateCommonName(t *testing.T) {
	// An anchored certificate without the Yivi scheme extension is the
	// third-party-CA shape: the CA attested the subject, so its common name is
	// attested — the blog's medium display, "the organisation name attested by
	// its CA".
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_MissingSchemeData)

	_, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, requestor.Attested)
	require.Equal(t, EndEntityCN, requestor.Attested.Organization.LegalName["en"])
}

func testParseAndVerifyAuthorizationRequestInvalidAsnSchemeData_AssumesThirdPartyCertificate_AttestsCertificateCommonName(t *testing.T) {
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_InvalidAsnSchemeData)

	_, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, requestor.Attested)
	require.Equal(t, EndEntityCN, requestor.Attested.Organization.LegalName["en"])
}

func testParseAndVerifyAuthorizationRequestInvalidJsonSchemeData_AssumesThirdPartyCertificate_AttestsCertificateCommonName(t *testing.T) {
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_InvalidJsonSchemeData)

	_, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, requestor.Attested)
	require.Equal(t, EndEntityCN, requestor.Attested.Organization.LegalName["en"])
}

func testParseAndVerifyAuthorizationRequestFailureForInvalidClientID(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		// Modify the client_id to an invalid value
		token.Claims.(jwt.MapClaims)["client_id"] = "invalid_client_id"
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: client_id expected to start with 'x509_san_dns:' or 'x509_hash:' but doesn't (invalid_client_id)")
}

func testParseAndVerifyAuthorizationRequestFailureHostnameMismatch(t *testing.T) {
	// A request whose certificate does not cover its own client_id hostname is
	// internally incoherent, however the chain ends: the binding stays in the
	// gate.
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_id"] = "x509_san_dns:somebody-else.example.com"
	}, testdata.PkiOption_None)

	_, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match the leaf certificate")
}

func testParseAndVerifyAuthorizationRequestFailureMissingX5C(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Header["x5c"] = nil // Remove x5c header
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to get end-entity certificate from x5c header: auth request token doesn't contain valid x5c field in the header")
}

func testParseAndVerifyAuthorizationRequestFailureExpiredX5C(t *testing.T) {
	// A certificate presented outside its own validity window is a broken
	// artifact, like an expired JWT: the gate rejects it. This is deliberately
	// different from an expired *chain* (see the demotion tests): the party
	// itself presented stale material.
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_ExpiredEndEntity)

	_, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "relying party certificate is not valid at the current time")
}

func testParseAndVerifyAuthorizationRequestRevokedX5C_DemotesToSelfAsserted(t *testing.T) {
	// Revocation withdraws the anchor's word, it does not break the request:
	// the signature still verifies, so the session may proceed with nobody
	// vouching — the certificate's contents are the party's own word now, and
	// the trust ladder will rank it low.
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_RevokedEndEntity)

	_, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, requestor.Certificate)
	require.Nil(t, requestor.Attested, "a revoked certificate attests nothing")
	require.NotNil(t, requestor.SelfAsserted)
	require.Equal(t, EndEntityCN, requestor.SelfAsserted.Organization.LegalName["en"])
}

func testParseAndVerifyAuthorizationRequestMissingRoot_DemotesToSelfAsserted(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_None)

	// Remove the root certificate from the trusted roots: the chain now ends
	// nowhere the wallet knows, which is evidentially a self-signed key.
	verifierValidator.(*RequestorCertificateStoreVerifierValidator).
		verificationContext.(*eudi.TrustModel).
		ClearTrustedRootCertificates()

	// Parse and verify the authorization request
	_, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err, "a legitimate-looking stranger passes the gate")
	require.Nil(t, requestor.Attested)
	require.Equal(t, EndEntityCN, requestor.SelfAsserted.Organization.LegalName["en"])
}

func testParseAndVerifyAuthorizationRequestExpiredRoot_DemotesToSelfAsserted(t *testing.T) {
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_ExpiredRoot)

	_, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Nil(t, requestor.Attested, "an expired root is not an anchor anymore")
	require.Equal(t, EndEntityCN, requestor.SelfAsserted.Organization.LegalName["en"])
}

// This function implicitly also tests the case where an intermediate certificate is revoked, because it will be 'missing'
// from the chain if it is revoked (not added by the configuration).
func testParseAndVerifyAuthorizationRequestMissingIntermediate_DemotesToSelfAsserted(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_None)

	// Remove the intermediate certificate from the trusted intermediates: the
	// chain cannot be built, so no anchor stands behind the leaf.
	verifierValidator.(*RequestorCertificateStoreVerifierValidator).
		verificationContext.(*eudi.TrustModel).
		ClearTrustedIntermediateCertificates()

	// Parse and verify the authorization request
	_, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Nil(t, requestor.Attested)
	require.Equal(t, EndEntityCN, requestor.SelfAsserted.Organization.LegalName["en"])
}

func testParseAndVerifyAuthorizationRequestExpiredIntermediate_DemotesToSelfAsserted(t *testing.T) {
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_ExpiredIntermediate)

	_, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Nil(t, requestor.Attested)
	require.Equal(t, EndEntityCN, requestor.SelfAsserted.Organization.LegalName["en"])
}

func testParseAndVerifyAuthorizationRequestSuccessX509Hash(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupHashTest(t, nil, testdata.PkiOption_None)

	// Parse and verify the authorization request
	claims, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, claims)
	require.NotNil(t, requestor.Certificate)
	require.NotNil(t, requestor.Attested)
}

func testParseAndVerifyAuthorizationRequestFailureX509HashMismatch(t *testing.T) {
	// Setup test data with a client_id hash that doesn't match the leaf certificate
	authRequestJwt, verifierValidator := setupHashTest(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_id"] = "x509_hash:" + base64.RawURLEncoding.EncodeToString(sha256.New().Sum(nil))
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match leaf certificate hash")
}

func testParseAndVerifyAuthorizationRequestNilClientMetadata_AttestsCertificateSchemeData(t *testing.T) {
	// Setup test data. By default the test JWT doesn't set client_metadata at all, so
	// AuthorizationRequest.ClientMetadata (a pointer) is nil.
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_None)

	// Parse and verify the authorization request
	claims, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Nil(t, claims.ClientMetadata)
	require.Equal(t, "Yivi B.V.", requestor.Attested.Organization.LegalName["en"])
	require.Nil(t, requestor.SelfAsserted)
}

func testParseAndVerifyAuthorizationRequestClientMetadataWithoutClientName_AttestsCertificateSchemeData(t *testing.T) {
	// Setup test data with a client_metadata object present, but without a client_name.
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_metadata"] = map[string]any{
			"client_uri": "https://verifier.example.com",
		}
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	claims, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, claims.ClientMetadata)
	require.Nil(t, claims.ClientMetadata.ClientName)
	require.Equal(t, "Yivi B.V.", requestor.Attested.Organization.LegalName["en"])
	require.Nil(t, requestor.SelfAsserted)
}

func testParseAndVerifyAuthorizationRequestClientMetadataWithClientName_IsSelfAsserted(t *testing.T) {
	// client_metadata is the verifier's own word about itself, whoever signed
	// its certificate: it travels in the self-asserted account and never
	// displaces what the certificate attests.
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_metadata"] = map[string]any{
			"client_name": "Acme Verifier",
		}
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Equal(t, "Yivi B.V.", requestor.Attested.Organization.LegalName["en"],
		"the certificate's account stays attested")
	require.Equal(t, "Acme Verifier", requestor.SelfAsserted.Organization.LegalName["en"],
		"the request's account stays the verifier's own word")
}

func testParseAndVerifyAuthorizationRequestClientMetadataLogo_IsIgnored(t *testing.T) {
	// A logo is believed rather than judged, so nothing self-asserted may
	// supply one: the logo_uri is not even downloaded.
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_metadata"] = map[string]any{
			"client_name": "Acme Verifier",
			"logo_uri":    "data:image/png;base64,aGVsbG8=",
		}
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Equal(t, "Acme Verifier", requestor.SelfAsserted.Organization.LegalName["en"])
	require.Nil(t, requestor.SelfAsserted.Organization.Logo)
}

func testParseAndVerifyAuthorizationRequestQueryValidation_EnforcedWithClientMetadata(t *testing.T) {
	// Grant violation always blocks — and the check must not be skippable by
	// dressing the request up with client_metadata, which is how it used to be
	// bypassed.
	authRequestJwt, verifierValidator := setupTestWithFactory(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_metadata"] = map[string]any{
			"client_name": "Acme Verifier",
		}
	}, testdata.PkiOption_None, &MockQueryValidatorFactory{failsQueryValidation: true})

	_, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to verify queried credentials")
}

func testParseAndVerifyAuthorizationRequestQueryValidation_SkippedWhenUnanchored(t *testing.T) {
	// An unanchored certificate's contents are the party's own word, its
	// authorization data included: there is nothing trustworthy to enforce,
	// exactly as for a DID verifier that carries no authorization artifact.
	authRequestJwt, verifierValidator := setupTestWithFactory(t, nil,
		testdata.PkiOption_None, &MockQueryValidatorFactory{failsQueryValidation: true})

	verifierValidator.(*RequestorCertificateStoreVerifierValidator).
		verificationContext.(*eudi.TrustModel).
		ClearTrustedRootCertificates()

	_, requestor, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Nil(t, requestor.Attested)
}

func setupTest(t *testing.T, tokenModifier func(token *jwt.Token), opts testdata.PkiGenerationOptions) (authRequestJwt string, verifierValidator VerifierValidator) {
	return setupTestWithFactory(t, tokenModifier, opts, &MockQueryValidatorFactory{})
}

func setupTestWithFactory(t *testing.T, tokenModifier func(token *jwt.Token), opts testdata.PkiGenerationOptions, factory QueryValidatorFactory) (authRequestJwt string, verifierValidator VerifierValidator) {
	tempDir := t.TempDir()

	// Setup PKI
	hostname := "example.com"
	crlDistPoint := "https://yivi.app/crl.crl"
	_, rootCert, caKeys, caCerts, _ := testdata.CreateTestPkiHierarchy(t, testdata.CreateDistinguishedName("ROOT CERT 1"), 1, opts, &crlDistPoint)
	verifierKey, verifierCert, _ := testdata.CreateEndEntityCertificate(t, testdata.CreateDistinguishedName(EndEntityCN), hostname, caCerts[0], caKeys[0], testdata.VerifierCertSchemeData, opts)

	// Setup VerifierValidator with PKI
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(caCerts[0])

	revocationLists := revocationListsFor(t, opts, verifierCert, caCerts[0], caKeys[0])

	// Create the TrustModel with the PKI
	trustModel := eudi.NewTestTrustModel(tempDir, rootPool, intermediatePool, revocationLists)

	verifierValidator = NewRequestorCertificateStoreVerifierValidator(trustModel, factory)

	// Create an authorization request JWT
	authRequestJwt = testdata.CreateTestAuthorizationRequestJWT(hostname, verifierKey, verifierCert, tokenModifier)
	return
}

// setupHashTest mirrors setupTest, but builds an x509_hash: client_id from the leaf
// certificate's hash instead of an x509_san_dns: client_id built from its hostname.
func setupHashTest(t *testing.T, tokenModifier func(token *jwt.Token), opts testdata.PkiGenerationOptions) (authRequestJwt string, verifierValidator VerifierValidator) {
	tempDir := t.TempDir()

	// Setup PKI
	hostname := "example.com"
	crlDistPoint := "https://yivi.app/crl.crl"
	_, rootCert, caKeys, caCerts, _ := testdata.CreateTestPkiHierarchy(t, testdata.CreateDistinguishedName("ROOT CERT 1"), 1, opts, &crlDistPoint)
	verifierKey, verifierCert, certDerBytes := testdata.CreateEndEntityCertificate(t, testdata.CreateDistinguishedName("END ENTITY CERT"), hostname, caCerts[0], caKeys[0], testdata.VerifierCertSchemeData, opts)

	// Setup VerifierValidator with PKI
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(caCerts[0])

	revocationLists := revocationListsFor(t, opts, verifierCert, caCerts[0], caKeys[0])

	// Create the TrustModel with the PKI
	trustModel := eudi.NewTestTrustModel(tempDir, rootPool, intermediatePool, revocationLists)

	verifierValidator = NewRequestorCertificateStoreVerifierValidator(trustModel, &MockQueryValidatorFactory{})

	// Create an authorization request JWT with an x509_hash: client_id matching the leaf certificate
	hash := sha256.Sum256(certDerBytes)
	clientId := "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])
	authRequestJwt = testdata.CreateTestAuthorizationRequestJWTWithClientId(clientId, verifierKey, verifierCert, tokenModifier)
	return
}

// revocationListsFor builds the CRL revoking the verifier certificate when the
// options ask for a revoked end entity, and nothing otherwise.
func revocationListsFor(t *testing.T, opts testdata.PkiGenerationOptions, verifierCert, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) []*x509.RevocationList {
	t.Helper()

	if opts&testdata.PkiOption_RevokedEndEntity == 0 {
		return nil
	}

	crlTemplate := &x509.RevocationList{
		Number:     mathBig.NewInt(1),
		ThisUpdate: time.Now().Add(time.Duration(-1 * time.Hour)),
		NextUpdate: time.Now().Add(time.Duration(1 * time.Hour)),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   verifierCert.SerialNumber,
				RevocationTime: time.Now().Add(time.Duration(-1 * time.Hour)),
				ReasonCode:     0, // Unspecified reason
			},
		},
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)
	crl, err := x509.ParseRevocationList(crlBytes)
	require.NoError(t, err)
	return []*x509.RevocationList{crl}
}
