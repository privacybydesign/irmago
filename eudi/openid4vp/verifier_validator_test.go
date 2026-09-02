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

	// Chain errors are not the gate's: the gate passes and the chain does not anchor
	t.Run("ParseAndVerifyAuthorizationRequest passes a valid cert with a missing root certificate, which does not anchor", testParseAndVerifyAuthorizationRequestFailureMissingRoot)
	t.Run("ParseAndVerifyAuthorizationRequest passes a valid cert with an expired root certificate, which does not anchor", testParseAndVerifyAuthorizationRequestFailureExpiredRoot)

	t.Run("ParseAndVerifyAuthorizationRequest passes a valid cert with a missing intermediate certificate, which does not anchor", testParseAndVerifyAuthorizationRequestFailureMissingIntermediate)
	t.Run("ParseAndVerifyAuthorizationRequest passes a valid cert with an expired intermediate certificate, which does not anchor", testParseAndVerifyAuthorizationRequestFailureExpiredIntermediate)

	// x509_hash scheme tests
	t.Run("ParseAndVerifyAuthorizationRequest validates an x509_hash JWT successfully", testParseAndVerifyAuthorizationRequestSuccessX509Hash)
	t.Run("ParseAndVerifyAuthorizationRequest fails when x509_hash doesn't match the leaf certificate", testParseAndVerifyAuthorizationRequestFailureX509HashMismatch)

	// client_metadata (nil-pointer) tests
	t.Run("ParseAndVerifyAuthorizationRequest falls back to certificate scheme data when client_metadata is absent", testParseAndVerifyAuthorizationRequestNilClientMetadata_FallsBackToCertificateSchemeData)
	t.Run("ParseAndVerifyAuthorizationRequest falls back to certificate scheme data when client_metadata has no client_name", testParseAndVerifyAuthorizationRequestClientMetadataWithoutClientName_FallsBackToCertificateSchemeData)
	t.Run("ParseAndVerifyAuthorizationRequest uses client_metadata client_name when present", testParseAndVerifyAuthorizationRequestClientMetadataWithClientName_UsesClientMetadataName)
	t.Run("ParseAndVerifyAuthorizationRequest ignores the logo referenced in client_metadata", testParseAndVerifyAuthorizationRequestClientMetadataWithLogoUri_IgnoresLogo)
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
	claims, verified, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, claims)
	require.NotNil(t, verified.Certificate)
	require.Empty(t, verified.DID)
	require.NotNil(t, verified.SchemeData)
	requestorSchemeData := verified.SchemeData

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
	_, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: client_id expected to start with 'x509_san_dns:' or 'x509_hash:' but doesn't (invalid_client_id)")
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
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Header["x5c"] = nil // Remove x5c header
	}, testdata.PkiOption_ExpiredEndEntity)

	// Parse and verify the authorization request
	_, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse auth request jwt: token is unverifiable: error while executing keyfunc: failed to get end-entity certificate from x5c header: auth request token doesn't contain valid x5c field in the header")
}

func testParseAndVerifyAuthorizationRequestFailureRevokedX5C(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_RevokedEndEntity)

	// Parse and verify the authorization request
	_, _, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.Error(t, err)
	require.Contains(t, err.Error(), "relying party certificate is refused: certificate is revoked: certificate is revoked by issuer CN=CA CERT 0,OU=Test Unit,O=Test Organization,C=NL in revocation list with number 1")
}

func testParseAndVerifyAuthorizationRequestMissingSchemeData_AssumesThirdPartyCertificate_ReturnsCertificateCommonName(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_MissingSchemeData)

	// Parse and verify the authorization request
	_, verified, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Nil(t, verified.SchemeData)
	require.Equal(t, EndEntityCN, verified.SelfAssertedName)
}

func testParseAndVerifyAuthorizationRequestInvalidAsnSchemeData_AssumesThirdPartyCertificate_ReturnsCertificateCommonName(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_InvalidAsnSchemeData)

	// Parse and verify the authorization request
	_, verified, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Nil(t, verified.SchemeData)
	require.Equal(t, EndEntityCN, verified.SelfAssertedName)
}

func testParseAndVerifyAuthorizationRequestInvalidJsonSchemeData_AssumesThirdPartyCertificate_ReturnsCertificateCommonName(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_InvalidJsonSchemeData)

	// Parse and verify the authorization request
	_, verified, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Nil(t, verified.SchemeData)
	require.Equal(t, EndEntityCN, verified.SelfAssertedName)
}

func testParseAndVerifyAuthorizationRequestFailureMissingRoot(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_None)

	// Remove the root certificate from the trusted roots, to simulate a missing cert
	trustModel := verifierValidator.(*RequestorCertificateStoreVerifierValidator).verificationContext.(*eudi.TrustModel)
	trustModel.ClearTrustedRootCertificates()

	// The gate passes: the certificate is valid on its own terms and matches its
	// client_id. Anchoring is the trust ladder's question, and the chain does not
	// anchor, so the verifier ranks low rather than being refused.
	_, verified, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)
	require.NoError(t, err)
	require.NotNil(t, verified.Certificate)

	_, err = trustModel.ValidateChain(verified.Certificate)
	require.ErrorContains(t, err, "x509: certificate signed by unknown authority")
}

func testParseAndVerifyAuthorizationRequestFailureExpiredRoot(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_ExpiredRoot)

	// The leaf itself is valid, so the gate passes; the chain to the expired root
	// does not validate, so the verifier is unanchored and ranks low.
	_, verified, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)
	require.NoError(t, err)

	trustModel := verifierValidator.(*RequestorCertificateStoreVerifierValidator).verificationContext.(*eudi.TrustModel)
	_, err = trustModel.ValidateChain(verified.Certificate)
	require.ErrorContains(t, err, "x509: certificate has expired or is not yet valid")
}

// This function implicitly also tests the case where an intermediate certificate is revoked, because it will be 'missing'
// from the chain if it is revoked (not added by the configuration).
func testParseAndVerifyAuthorizationRequestFailureMissingIntermediate(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_None)

	// Remove the intermediate certificate from the trusted intermediates, to simulate a missing cert
	trustModel := verifierValidator.(*RequestorCertificateStoreVerifierValidator).verificationContext.(*eudi.TrustModel)
	trustModel.ClearTrustedIntermediateCertificates()

	// The gate passes; without the intermediate the chain does not anchor, which
	// the trust ladder reads as absent evidence.
	_, verified, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)
	require.NoError(t, err)

	_, err = trustModel.ValidateChain(verified.Certificate)
	require.ErrorContains(t, err, "x509: certificate signed by unknown authority")
}

func testParseAndVerifyAuthorizationRequestFailureExpiredIntermediate(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_ExpiredIntermediate)

	// As with an expired root: the gate passes and the chain does not anchor.
	_, verified, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)
	require.NoError(t, err)

	trustModel := verifierValidator.(*RequestorCertificateStoreVerifierValidator).verificationContext.(*eudi.TrustModel)
	_, err = trustModel.ValidateChain(verified.Certificate)
	require.ErrorContains(t, err, "x509: certificate has expired or is not yet valid")
}

func testParseAndVerifyAuthorizationRequestSuccessX509Hash(t *testing.T) {
	// Setup test data
	authRequestJwt, verifierValidator := setupHashTest(t, nil, testdata.PkiOption_None)

	// Parse and verify the authorization request
	claims, verified, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, claims)
	require.NotNil(t, verified.Certificate)
	require.NotNil(t, verified.SchemeData)
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

func testParseAndVerifyAuthorizationRequestNilClientMetadata_FallsBackToCertificateSchemeData(t *testing.T) {
	// Setup test data. By default the test JWT doesn't set client_metadata at all, so
	// AuthorizationRequest.ClientMetadata (a pointer) is nil.
	authRequestJwt, verifierValidator := setupTest(t, nil, testdata.PkiOption_None)

	// Parse and verify the authorization request
	claims, verified, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Nil(t, claims.ClientMetadata)
	require.Equal(t, "Yivi B.V.", verified.SchemeData.Organization.LegalName["en"])
	require.Equal(t, EndEntityCN, verified.SelfAssertedName, "without client_metadata the verifier's own name is its certificate's common name")
}

func testParseAndVerifyAuthorizationRequestClientMetadataWithoutClientName_FallsBackToCertificateSchemeData(t *testing.T) {
	// Setup test data with a client_metadata object present, but without a client_name.
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_metadata"] = map[string]any{
			"client_uri": "https://verifier.example.com",
		}
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	claims, verified, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.NotNil(t, claims.ClientMetadata)
	require.Nil(t, claims.ClientMetadata.ClientName)
	require.Equal(t, "Yivi B.V.", verified.SchemeData.Organization.LegalName["en"])
	require.Equal(t, EndEntityCN, verified.SelfAssertedName)
}

func testParseAndVerifyAuthorizationRequestClientMetadataWithClientName_UsesClientMetadataName(t *testing.T) {
	// Setup test data with client_metadata.client_name set, and no logo_uri.
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_metadata"] = map[string]any{
			"client_name": "Acme Verifier",
		}
	}, testdata.PkiOption_None)

	// Parse and verify the authorization request
	_, verified, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Equal(t, "Acme Verifier", verified.SelfAssertedName)
	// What the certificate says is reported alongside; which of the two the
	// wallet shows depends on whether the certificate anchors.
	require.Equal(t, "Yivi B.V.", verified.SchemeData.Organization.LegalName["en"])
}

// A logo the verifier names for itself in client_metadata is never fetched or
// shown: a logo is believed rather than judged, so it only ever comes from a
// source beyond the verifier — an anchored certificate or the wallet config.
func testParseAndVerifyAuthorizationRequestClientMetadataWithLogoUri_IgnoresLogo(t *testing.T) {
	authRequestJwt, verifierValidator := setupTest(t, func(token *jwt.Token) {
		token.Claims.(jwt.MapClaims)["client_metadata"] = map[string]any{
			"client_name": "Acme Verifier",
			"logo_uri":    "data:image/png;base64,aGVsbG8=",
		}
	}, testdata.PkiOption_None)

	_, verified, err := verifierValidator.ParseAndVerifyAuthorizationRequest(authRequestJwt)

	require.NoError(t, err)
	require.Equal(t, "Acme Verifier", verified.SelfAssertedName)
	require.NotEqual(t, []byte("hello"), verified.SchemeData.Organization.Logo.Data,
		"the only logo reported is the certificate's, not client_metadata's")
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

	verifierValidator = NewRequestorCertificateStoreVerifierValidator(trustModel)

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

	verifierValidator = NewRequestorCertificateStoreVerifierValidator(trustModel)

	// Create an authorization request JWT with an x509_hash: client_id matching the leaf certificate
	hash := sha256.Sum256(certDerBytes)
	clientId := "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])
	authRequestJwt = testdata.CreateTestAuthorizationRequestJWTWithClientId(clientId, verifierKey, verifierCert, tokenModifier)
	return
}
