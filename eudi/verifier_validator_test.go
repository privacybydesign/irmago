package eudi

import (
	"crypto/rand"
	"crypto/x509"
	mathBig "math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func TestVerifierValidator(t *testing.T) {
	// Happy flow tests
	t.Run("ParseAndVerifyAuthorizationRequest validates a JWT successfully", testParseAndVerifyAuthorizationRequestSuccess)

	// Unhappy flow tests
	t.Run("ParseAndVerifyAuthorizationRequest fails with invalid client_id", testParseAndVerifyAuthorizationRequestFailureForInvalidClientID)

	// Unhappy flow tests for x5c related errors
	t.Run("ParseAndVerifyAuthorizationRequest fails with missing x5c header", testParseAndVerifyAuthorizationRequestFailureMissingX5C)
	t.Run("ParseAndVerifyAuthorizationRequest fails with empty x5c array", testParseAndVerifyAuthorizationRequestFailureEmptyX5cArray)
	t.Run("ParseAndVerifyAuthorizationRequest fails with expired x5c certificate", testParseAndVerifyAuthorizationRequestFailureExpiredX5C)
	t.Run("ParseAndVerifyAuthorizationRequest fails with revoked x5c certificate", testParseAndVerifyAuthorizationRequestFailureRevokedX5C)
	t.Run("ParseAndVerifyAuthorizationRequest fails for missing scheme data in x5c certificate", testParseAndVerifyAuthorizationRequestFailureMissingSchemeData)
	t.Run("ParseAndVerifyAuthorizationRequest fails for invalid ASN scheme data in x5c certificate", testParseAndVerifyAuthorizationRequestFailureInvalidAsnSchemeData)
	t.Run("ParseAndVerifyAuthorizationRequest fails for invalid JSON scheme data in x5c certificate", testParseAndVerifyAuthorizationRequestFailureInvalidJsonSchemeData)

	// Unhappy flow tests for x5c related CHAIN errors
	t.Run("ParseAndVerifyAuthorizationRequest fails with valid cert but missing root certificate", testParseAndVerifyAuthorizationRequestFailureMissingRoot)
	t.Run("ParseAndVerifyAuthorizationRequest fails with valid cert but expired root certificate", testParseAndVerifyAuthorizationRequestFailureExpiredRoot)

	t.Run("ParseAndVerifyAuthorizationRequest fails with valid cert but missing intermediate certificate", testParseAndVerifyAuthorizationRequestFailureMissingIntermediate)
	t.Run("ParseAndVerifyAuthorizationRequest fails with valid cert but expired intermediate certificate", testParseAndVerifyAuthorizationRequestFailureExpiredIntermediate)
}

func testParseAndVerifyAuthorizationRequestFailureEmptyX5cArray(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Header["x5c"] = []string{}
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to get end-entity certificate from x5c header: auth request token contains empty x5c array in the header")
}

func testParseAndVerifyAuthorizationRequestSuccess(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_None)

	// Parse and verify the authorization request
	claims, endEntityCert, requestorSchemeData, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

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
	require.Equal(t, "pbdf.gemeente.personalData", requestorSchemeData.RelyingParty.AuthorizedQueryableAttributeSets[0].Credential)
	require.NotEmpty(t, requestorSchemeData.RelyingParty.AuthorizedQueryableAttributeSets[0].Attributes)
	require.Equal(t, "over18", requestorSchemeData.RelyingParty.AuthorizedQueryableAttributeSets[0].Attributes[0])

	require.NotEmpty(t, requestorSchemeData.RelyingParty.RequestPurpose)
	require.Equal(t, "Age verification", requestorSchemeData.RelyingParty.RequestPurpose["en"])
	require.Equal(t, "Leeftijdsverificatie", requestorSchemeData.RelyingParty.RequestPurpose["nl"])
}

func testParseAndVerifyAuthorizationRequestFailureForInvalidClientID(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		// Modify the client_id to an invalid value
		token.Claims.(jwt.MapClaims)["client_id"] = "invalid_client_id"
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: client_id expected to start with 'x509_san_dns:' but doesn't (invalid_client_id)")
}

func testParseAndVerifyAuthorizationRequestFailureMissingX5C(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Header["x5c"] = nil // Remove x5c header
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to get end-entity certificate from x5c header: auth request token doesn't contain valid x5c field in the header")
}

func testParseAndVerifyAuthorizationRequestFailureExpiredX5C(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Header["x5c"] = nil // Remove x5c header
	}, testdata.PkiOption_ExpiredEndEntity)

	// Parse and verify the authorization request
	_, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to get end-entity certificate from x5c header: auth request token doesn't contain valid x5c field in the header")
}

func testParseAndVerifyAuthorizationRequestFailureRevokedX5C(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_RevokedEndEntity)

	// Parse and verify the authorization request
	_, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to verify relying party certificate: failed to verify x5c end-entity certificate against revocation lists: certificate is revoked by issuer CN=CA CERT 0,OU=Test Unit,O=Test Organization,C=NL in revocation list with number 1")
}

func testParseAndVerifyAuthorizationRequestFailureMissingSchemeData(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_MissingSchemeData)

	// Parse and verify the authorization request
	_, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to verify end-entity certificate: it does not contain the required custom certificate extension with OID 2.1.123.1")
}

func testParseAndVerifyAuthorizationRequestFailureInvalidAsnSchemeData(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_InvalidAsnSchemeData)

	// Parse and verify the authorization request
	_, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to verify end-entity certificate: failed to unmarshal scheme extension data:")
}

func testParseAndVerifyAuthorizationRequestFailureInvalidJsonSchemeData(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_InvalidJsonSchemeData)

	// Parse and verify the authorization request
	_, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to verify end-entity certificate: failed to unmarshal scheme data to requestor object:")
}

func testParseAndVerifyAuthorizationRequestFailureMissingRoot(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_None)

	// Remove the root certificate from the trusted roots, to simulate a missing cert
	verifierValidator.(*RequestorCertificateStoreVerifierValidator).
		verificationContext.(*TrustModel).
		trustedRootCertificates = x509.NewCertPool()

	// Parse and verify the authorization request
	_, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to verify relying party certificate: failed to verify x5c end-entity certificate: x509: certificate signed by unknown authority")
}

func testParseAndVerifyAuthorizationRequestFailureExpiredRoot(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_ExpiredRoot)

	// Parse and verify the authorization request
	_, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

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
		verificationContext.(*TrustModel).
		trustedIntermediateCertificates = x509.NewCertPool()

	// Parse and verify the authorization request
	_, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to verify relying party certificate: failed to verify x5c end-entity certificate: x509: certificate signed by unknown authority")
}

func testParseAndVerifyAuthorizationRequestFailureExpiredIntermediate(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_ExpiredIntermediate)

	// Parse and verify the authorization request
	_, _, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to verify relying party certificate: failed to verify x5c end-entity certificate: x509: certificate has expired or is not yet valid: ")
}

func setupTest(t *testing.T, tokenModifier func(token *jwt.Token), opts testdata.PkiGenerationOptions) (authRequestJwt string, verifierValidator VerifierValidator) {
	// Setup PKI
	hostname := "example.com"
	crlDistPoint := "https://yivi.app/crl.crl"
	_, rootCert, caKeys, caCerts, _ := testdata.CreateTestPkiHierarchy(t, testdata.CreateDistinguishedName("ROOT CERT 1"), 1, opts, &crlDistPoint)
	verifierKey, verifierCert, _ := testdata.CreateEndEntityCertificate(t, testdata.CreateDistinguishedName("END ENTITY CERT"), hostname, caCerts[0], caKeys[0], testdata.VerifierCertSchemeData, opts)

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
	trustModel := &TrustModel{
		basePath:                        "testdata",
		trustedRootCertificates:         rootPool,
		trustedIntermediateCertificates: intermediatePool,
		revocationLists:                 revocationLists,
	}

	verifierValidator = NewRequestorCertificateStoreVerifierValidator(trustModel, &MockQueryValidatorFactory{})

	// Create an authorization request JWT
	authRequestJwt = testdata.CreateTestAuthorizationRequestJWT(hostname, verifierKey, verifierCert, tokenModifier)
	return
}
