package openid4vp

import (
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

func TestVerifierValidator(t *testing.T) {
	// Happy flow tests
	t.Run("ParseAndVerifyAuthorizationRequest validates a JWT successfully", testParseAndVerifyAuthorizationRequestSuccess)
	t.Run("ParseAndVerifyAuthorizationRequest returns certificate CN as requestorInfo when missing scheme data in x5c", testParseAndVerifyAuthorizationRequestMissingSchemeData_AssumesThirdPartyCertificate_ReturnsCertificateCommonName)
	t.Run("ParseAndVerifyAuthorizationRequest returns certificate CN as requestorInfo when invalid ASN scheme data in x5c", testParseAndVerifyAuthorizationRequestInvalidAsnSchemeData_AssumesThirdPartyCertificate_ReturnsCertificateCommonName)
	t.Run("ParseAndVerifyAuthorizationRequest returns certificate CN as requestorInfo when invalid JSON scheme data in x5c", testParseAndVerifyAuthorizationRequestInvalidJsonSchemeData_AssumesThirdPartyCertificate_ReturnsCertificateCommonName)

	// Unhappy flow tests
	t.Run("ParseAndVerifyAuthorizationRequest fails with invalid client_id", testParseAndVerifyAuthorizationRequestFailureForInvalidClientID)

	// Unhappy flow tests for x5c related errors
	t.Run("ParseAndVerifyAuthorizationRequest fails with missing x5c header", testParseAndVerifyAuthorizationRequestFailureMissingX5C)
	t.Run("ParseAndVerifyAuthorizationRequest fails with empty x5c array", testParseAndVerifyAuthorizationRequestFailureEmptyX5cArray)
	t.Run("ParseAndVerifyAuthorizationRequest fails with expired x5c certificate", testParseAndVerifyAuthorizationRequestFailureExpiredX5C)
	t.Run("ParseAndVerifyAuthorizationRequest fails with revoked x5c certificate", testParseAndVerifyAuthorizationRequestFailureRevokedX5C)

	// Unhappy flow tests for x5c related CHAIN errors
	t.Run("ParseAndVerifyAuthorizationRequest fails with valid cert but missing root certificate", testParseAndVerifyAuthorizationRequestFailureMissingRoot)
	t.Run("ParseAndVerifyAuthorizationRequest fails with valid cert but expired root certificate", testParseAndVerifyAuthorizationRequestFailureExpiredRoot)

	t.Run("ParseAndVerifyAuthorizationRequest fails with valid cert but missing intermediate certificate", testParseAndVerifyAuthorizationRequestFailureMissingIntermediate)
	t.Run("ParseAndVerifyAuthorizationRequest fails with valid cert but expired intermediate certificate", testParseAndVerifyAuthorizationRequestFailureExpiredIntermediate)

	// x509_hash scheme tests
	t.Run("ParseAndVerifyAuthorizationRequest validates an x509_hash JWT successfully", testParseAndVerifyAuthorizationRequestSuccessX509Hash)
	t.Run("ParseAndVerifyAuthorizationRequest fails when x509_hash doesn't match the leaf certificate", testParseAndVerifyAuthorizationRequestFailureX509HashMismatch)

	// client_metadata (nil-pointer) tests
	t.Run("ParseAndVerifyAuthorizationRequest falls back to certificate scheme data when client_metadata is absent", testParseAndVerifyAuthorizationRequestNilClientMetadata_FallsBackToCertificateSchemeData)
	t.Run("ParseAndVerifyAuthorizationRequest falls back to certificate scheme data when client_metadata has no client_name", testParseAndVerifyAuthorizationRequestClientMetadataWithoutClientName_FallsBackToCertificateSchemeData)
	t.Run("ParseAndVerifyAuthorizationRequest uses client_metadata client_name when present", testParseAndVerifyAuthorizationRequestClientMetadataWithClientName_UsesClientMetadataName)
	t.Run("ParseAndVerifyAuthorizationRequest downloads the logo referenced in client_metadata", testParseAndVerifyAuthorizationRequestClientMetadataWithLogoUri_DownloadsLogo)
	t.Run("ParseAndVerifyAuthorizationRequest continues without a logo when it fails to download", testParseAndVerifyAuthorizationRequestClientMetadataWithInvalidLogoUri_ContinuesWithoutLogo)
}

func testParseAndVerifyAuthorizationRequestFailureEmptyX5cArray(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Header["x5c"] = []string{}
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to get end-entity certificate from x5c header: auth request token contains empty x5c array in the header")
}

func testParseAndVerifyAuthorizationRequestSuccess(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_None)

	// Parse and verify the authorization request
	claims, endEntityCert, requestorSchemeData, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, claims)
	require.NotNil(t, endEntityCert)
	require.NotNil(t, requestorSchemeData)

	// Assert requestor data
	require.Equal(t, "https://portal.yivi.app/organizations/yivi", requestorSchemeData.Registration)

	require.NotEmpty(t, requestorSchemeData.Organization.LegalName)
	require.Equal(t, "Yivi B.V.", requestorSchemeData.Organization.LegalName["en"])
	require.Equal(t, "Yivi B.V.", requestorSchemeData.Organization.LegalName["nl"])

	require.Equal(t, "image/png", requestorSchemeData.Organization.Logo.MimeType)
	require.NotEmpty(t, requestorSchemeData.Organization.Logo.Data)

	require.NotEmpty(t, requestorSchemeData.RelyingParty.AuthorizedQueryableAttributeSets)
	require.Equal(t, "test.test.email", requestorSchemeData.RelyingParty.AuthorizedQueryableAttributeSets[0].Credential)
	require.NotEmpty(t, requestorSchemeData.RelyingParty.AuthorizedQueryableAttributeSets[0].Attributes)
	require.Equal(t, "email", requestorSchemeData.RelyingParty.AuthorizedQueryableAttributeSets[0].Attributes[0])
	require.Equal(t, "domain", requestorSchemeData.RelyingParty.AuthorizedQueryableAttributeSets[0].Attributes[1])

	require.NotEmpty(t, requestorSchemeData.RelyingParty.RequestPurpose)
	require.Equal(t, "Unit testing", requestorSchemeData.RelyingParty.RequestPurpose["en"])
	require.Equal(t, "Unit testen", requestorSchemeData.RelyingParty.RequestPurpose["nl"])
}

func testParseAndVerifyAuthorizationRequestFailureForInvalidClientID(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		// Modify the client_id to an invalid value
		token.Claims.(jwt.MapClaims)["client_id"] = "invalid_client_id"
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: client_id expected to start with 'x509_san_dns:' or 'x509_hash:' but doesn't (invalid_client_id)")
}

func testParseAndVerifyAuthorizationRequestFailureMissingX5C(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Header["x5c"] = nil // Remove x5c header
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to get end-entity certificate from x5c header: auth request token doesn't contain valid x5c field in the header")
}

func testParseAndVerifyAuthorizationRequestFailureExpiredX5C(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Header["x5c"] = nil // Remove x5c header
	}, testdata.PkiOption_ExpiredEndEntity)

	// Parse and verify the authorization request
	_, _, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to get end-entity certificate from x5c header: auth request token doesn't contain valid x5c field in the header")
}

func testParseAndVerifyAuthorizationRequestFailureRevokedX5C(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_RevokedEndEntity)

	// Parse and verify the authorization request
	_, _, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to verify relying party certificate: failed to verify x5c end-entity certificate against revocation lists: certificate is revoked by issuer CN=CA CERT 0,OU=Test Unit,O=Test Organization,C=NL in revocation list with number 1")
}

func testParseAndVerifyAuthorizationRequestMissingSchemeData_AssumesThirdPartyCertificate_ReturnsCertificateCommonName(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_MissingSchemeData)

	// Parse and verify the authorization request
	_, _, requestorInfo, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Equal(t, EndEntityCN, requestorInfo.Organization.LegalName["en"])
}

func testParseAndVerifyAuthorizationRequestInvalidAsnSchemeData_AssumesThirdPartyCertificate_ReturnsCertificateCommonName(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_InvalidAsnSchemeData)

	// Parse and verify the authorization request
	_, _, requestorInfo, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Equal(t, EndEntityCN, requestorInfo.Organization.LegalName["en"])
}

func testParseAndVerifyAuthorizationRequestInvalidJsonSchemeData_AssumesThirdPartyCertificate_ReturnsCertificateCommonName(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_InvalidJsonSchemeData)

	// Parse and verify the authorization request
	_, _, requestorInfo, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Equal(t, EndEntityCN, requestorInfo.Organization.LegalName["en"])
}

func testParseAndVerifyAuthorizationRequestFailureMissingRoot(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_None)

	// Remove the root certificate from the trusted roots, to simulate a missing cert
	verifierValidator.(*RequestorCertificateStoreVerifierValidator).
		verificationContext.(*eudi.TrustModel).
		ClearTrustedRootCertificates()

	// Parse and verify the authorization request
	_, _, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to verify relying party certificate: failed to verify x5c end-entity certificate: x509: certificate signed by unknown authority")
}

func testParseAndVerifyAuthorizationRequestFailureExpiredRoot(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_ExpiredRoot)

	// Parse and verify the authorization request
	_, _, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to verify relying party certificate: failed to verify x5c end-entity certificate: x509: certificate has expired or is not yet valid: current time ")
}

// This function implicitly also tests the case where an intermediate certificate is revoked, because it will be 'missing'
// from the chain if it is revoked (not added by the configuration).
func testParseAndVerifyAuthorizationRequestFailureMissingIntermediate(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_None)

	// Remove the intermediate certificate from the trusted intermediates, to simulate a missing cert
	verifierValidator.(*RequestorCertificateStoreVerifierValidator).
		verificationContext.(*eudi.TrustModel).
		ClearTrustedIntermediateCertificates()

	// Parse and verify the authorization request
	_, _, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to verify relying party certificate: failed to verify x5c end-entity certificate: x509: certificate signed by unknown authority")
}

func testParseAndVerifyAuthorizationRequestFailureExpiredIntermediate(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_ExpiredIntermediate)

	// Parse and verify the authorization request
	_, _, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to verify relying party certificate: failed to verify x5c end-entity certificate: x509: certificate has expired or is not yet valid: ")
}

func testParseAndVerifyAuthorizationRequestSuccessX509Hash(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupHashTest(t, nil, testdata.PkiOption_None)

	// Parse and verify the authorization request
	claims, endEntityCert, requestorSchemeData, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, claims)
	require.NotNil(t, endEntityCert)
	require.NotNil(t, requestorSchemeData)
}

func testParseAndVerifyAuthorizationRequestFailureX509HashMismatch(t *testing.T) {
	// Setup test data with a client_id hash that doesn't match the leaf certificate
	authRequestJwt, verifierValidator := setupHashTest(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_id"] = "x509_hash:" + base64.RawURLEncoding.EncodeToString(sha256.New().Sum(nil))
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match leaf certificate hash")
}

func testParseAndVerifyAuthorizationRequestNilClientMetadata_FallsBackToCertificateSchemeData(t *testing.T) {
	// Setup test data. By default the test JWT doesn't set client_metadata at all, so
	// AuthorizationRequest.ClientMetadata (a pointer) is nil.
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_None)

	// Parse and verify the authorization request
	claims, _, requestorInfo, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Nil(t, claims.ClientMetadata)
	require.Equal(t, "Yivi B.V.", requestorInfo.Organization.LegalName["en"])
}

func testParseAndVerifyAuthorizationRequestClientMetadataWithoutClientName_FallsBackToCertificateSchemeData(t *testing.T) {
	// Setup test data with a client_metadata object present, but without a client_name.
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_metadata"] = map[string]any{
			"client_uri": "https://verifier.example.com",
		}
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	claims, _, requestorInfo, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, claims.ClientMetadata)
	require.Nil(t, claims.ClientMetadata.ClientName)
	require.Equal(t, "Yivi B.V.", requestorInfo.Organization.LegalName["en"])
}

func testParseAndVerifyAuthorizationRequestClientMetadataWithClientName_UsesClientMetadataName(t *testing.T) {
	// Setup test data with client_metadata.client_name set, and no logo_uri.
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_metadata"] = map[string]any{
			"client_name": "Acme Verifier",
		}
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, requestorInfo, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Equal(t, "Acme Verifier", requestorInfo.Organization.LegalName["en"])
	require.Nil(t, requestorInfo.Organization.Logo)
}

func testParseAndVerifyAuthorizationRequestClientMetadataWithLogoUri_DownloadsLogo(t *testing.T) {
	// Setup test data with client_metadata.client_name and a data-uri logo_uri, so the
	// logo can be "downloaded" without a real network call.
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_metadata"] = map[string]any{
			"client_name": "Acme Verifier",
			"logo_uri":    "data:image/png;base64,aGVsbG8=",
		}
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, requestorInfo, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Equal(t, "Acme Verifier", requestorInfo.Organization.LegalName["en"])
	require.NotNil(t, requestorInfo.Organization.Logo)
	require.Equal(t, "image/png", requestorInfo.Organization.Logo.MimeType)
	require.Equal(t, []byte("hello"), requestorInfo.Organization.Logo.Data)
}

func testParseAndVerifyAuthorizationRequestClientMetadataWithInvalidLogoUri_ContinuesWithoutLogo(t *testing.T) {
	// Setup test data with client_metadata.client_name and a malformed logo_uri (missing
	// the comma separator), so downloading the logo fails.
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_metadata"] = map[string]any{
			"client_name": "Acme Verifier",
			"logo_uri":    "data:image/png;base64",
		}
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, requestorInfo, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Equal(t, "Acme Verifier", requestorInfo.Organization.LegalName["en"])
	require.Nil(t, requestorInfo.Organization.Logo)
}

func setupTest(t *testing.T, tokenModifier func(token *jwt.Token), opts testdata.PkiGenerationOptions) (authRequestJwt string, verifierValidator VerifierValidator) {
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

	var revocationLists []*x509.RevocationList
	if opts&testdata.PkiOption_RevokedEndEntity != 0 {
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
		crlBytes, _ := x509.CreateRevocationList(rand.Reader, crlTemplate, caCerts[0], caKeys[0])
		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			t.Fatalf("failed to parse revocation list: %v", err)
		}
		revocationLists = append(revocationLists, crl)
	}

	// Create the TrustModel with the PKI
	trustModel := eudi.NewTestTrustModel(tempDir, rootPool, intermediatePool, revocationLists)

	verifierValidator = NewRequestorCertificateStoreVerifierValidator(trustModel, &MockQueryValidatorFactory{})

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

	var revocationLists []*x509.RevocationList
	if opts&testdata.PkiOption_RevokedEndEntity != 0 {
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
		crlBytes, _ := x509.CreateRevocationList(rand.Reader, crlTemplate, caCerts[0], caKeys[0])
		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			t.Fatalf("failed to parse revocation list: %v", err)
		}
		revocationLists = append(revocationLists, crl)
	}

	// Create the TrustModel with the PKI
	trustModel := eudi.NewTestTrustModel(tempDir, rootPool, intermediatePool, revocationLists)

	verifierValidator = NewRequestorCertificateStoreVerifierValidator(trustModel, &MockQueryValidatorFactory{})

	// Create an authorization request JWT with an x509_hash: client_id matching the leaf certificate
	hash := sha256.Sum256(certDerBytes)
	clientId := "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])
	authRequestJwt = testdata.CreateTestAuthorizationRequestJWTWithClientId(clientId, verifierKey, verifierCert, tokenModifier)
	return
}
