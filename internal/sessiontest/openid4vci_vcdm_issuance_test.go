package sessiontest

import (
	"fmt"
	"strings"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// SD-JWT-secured W3C VCDM 2.0 (vc+sd-jwt) issuance by the veramo issuer. Veramo
// builds the VCDM document from the TestCredentialVcdm configuration: the second
// type comes from the configuration's scope, @context is only the VCDM 2.0 base
// context, and the offer data becomes credentialSubject. Veramo issues every
// claim of a vc+sd-jwt credential in the clear, because it takes selective
// disclosure only from VCT metadata, which VCDM has none of.

const (
	vcdmCredentialConfigId = "TestCredentialVcdm"
	vcdmCredentialName     = "Test Credential (VCDM)"
	vcdmCredentialType     = "TestVcdmCredential"

	// vcdmCredentialId is the @context+type identity the wallet stores the
	// credential under.
	vcdmCredentialId = "https://www.w3.org/ns/credentials/v2 VerifiableCredential " + vcdmCredentialType

	vcdmTestClaims = `{
		"given_name": "Vera",
		"family_name": "Modell",
		"email": "vera@example.com"
	}`
)

func testSessionHandlerForOpenID4VCIVcdm(t *testing.T) {
	t.Run("issues VCDM credential via pre-authorized code", testOpenID4VCIVcdmPreAuthFlow)
	t.Run("stores VCDM credential under its type identity", testOpenID4VCIVcdmStoredUnderTypeIdentity)
	t.Run("reissuing VCDM credential stores a second credential", testOpenID4VCIVcdmReissueStoresSecondCredential)
	t.Run("different claims give a second VCDM credential", testOpenID4VCIVcdmDifferentClaimsAddSecond)
	t.Run("deleting VCDM credential removes it", testOpenID4VCIVcdmDeletion)
	t.Run("denying VCDM issuance stores nothing", testOpenID4VCIVcdmDenyStoresNothing)
	t.Run("VCDM batch with differing subject ids is rejected", testOpenID4VCIVcdmBatchWithDifferingSubjectIdsRejected)
}

// testOpenID4VCIVcdmBatchWithDifferingSubjectIdsRejected checks that the wallet
// refuses a batch whose instances differ in a value it would show. Veramo writes
// each instance's own holder key into credentialSubject.id, so the two instances from
// the batch2 issuer differ there. The wallet shows a batch as one credential,
// so accepting it would mean showing the user one id and sending another.
func testOpenID4VCIVcdmBatchWithDifferingSubjectIdsRejected(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := postOffer(t, batch2IssuerURL, batch2AdminToken, fmt.Sprintf(`{
		"credentials": [%q],
		"grants": {
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
				"pre-authorized_code": "generate"
			}
		},
		"credentialDataSupplierInput": %s
	}`, vcdmCredentialConfigId, vcdmTestClaims))
	startOpenID4VCISession(t, c, 1, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	// The batch is checked when the credentials arrive, before the user is
	// asked to accept them.
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Error, session.Status)
	require.NotNil(t, session.Error)
	require.Contains(t, session.Error.WrappedError, "differs from credential 0 in credentialSubject")
	require.Empty(t, session.OfferedCredentials)
}

func testOpenID4VCIVcdmPreAuthFlow(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createVcdmPreAuthOffer(t, vcdmTestClaims)
	startOpenID4VCISession(t, c, 1, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)

	offered := session.OfferedCredentials[0]
	require.Equal(t, vcdmCredentialName, offered.Name)
	require.Equal(t, "Test Issuer", offered.Issuer.Name)
	requireVcdmTestAttrs(t, offered.Attributes, "Vera", "Modell", "vera@example.com")

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)
	require.Equal(t, "CREDENTIAL_ISSUED", checkOfferStatus(t, preAuthIssuerURL, preAuthAdminToken, offer.ID))

	cred := requireSingleVcdmCredential(t, c)
	require.Equal(t, vcdmCredentialName, cred.Name)
	requireVcdmTestAttrs(t, cred.Attributes, "Vera", "Modell", "vera@example.com")
}

func testOpenID4VCIVcdmStoredUnderTypeIdentity(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)

	cred := requireSingleVcdmCredential(t, c)
	require.Equal(t, vcdmCredentialId, cred.CredentialId)
	require.Equal(t, map[clientmodels.CredentialFormat]string{clientmodels.Format_SdJwtVcdm: cred.Hash}, cred.CredentialInstanceIds)

	// The issuer signs over did:web, which the wallet resolves and trusts.
	require.True(t, cred.Issuer.Verified)
	require.NotNil(t, cred.IssuanceDate, "validFrom is the issuance date")

	// The credential carries no status list (VCDM status is not checked yet).
	require.False(t, cred.RevocationSupported)
	require.False(t, cred.Revoked)

	// Only credentialSubject is user data. The VCDM envelope (@context, type,
	// issuer, validFrom, termsOfUse) and the JWT claims are not attributes.
	for _, attr := range cred.Attributes {
		require.Equal(t, "credentialSubject", attr.ClaimPath[0],
			"attribute %v is not under credentialSubject", attr.ClaimPath)
	}
}

// testOpenID4VCIVcdmReissueStoresSecondCredential checks that credentialSubject.id
// counts as content. Veramo sets it to the holder key's did:key, and every
// issuance uses a fresh holder key. The dedupe hash leaves the envelope out but
// keeps all of credentialSubject, so a renewal with the same claims is stored
// next to the first credential instead of replacing it. That is intended: a
// subject id can also be a stable identifier of the person, so the wallet does
// not guess when it is only a key.
func testOpenID4VCIVcdmReissueStoresSecondCredential(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)
	issueCredentialViaOpenID4VCI(t, c, 2, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)

	creds := vcdmCredentials(t, c)
	require.Len(t, creds, 2)
	require.NotEqual(t, creds[0].Hash, creds[1].Hash)

	// The two credentials differ only in credentialSubject.id.
	firstDid, secondDid := vcdmHolderDid(t, creds[0].Attributes), vcdmHolderDid(t, creds[1].Attributes)
	require.NotEqual(t, firstDid, secondDid)
	requireVcdmTestAttrs(t, creds[0].Attributes, "Vera", "Modell", "vera@example.com")
	requireVcdmTestAttrs(t, creds[1].Attributes, "Vera", "Modell", "vera@example.com")
}

func testOpenID4VCIVcdmDifferentClaimsAddSecond(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)
	issueCredentialViaOpenID4VCI(t, c, 2, sessionHandler, vcdmCredentialConfigId, `{
		"given_name": "Victor",
		"family_name": "Modell",
		"email": "victor@example.com"
	}`)

	creds := vcdmCredentials(t, c)
	require.Len(t, creds, 2)
	require.NotEqual(t, creds[0].Hash, creds[1].Hash)
	for _, cred := range creds {
		require.Equal(t, vcdmCredentialId, cred.CredentialId)
	}
}

func testOpenID4VCIVcdmDeletion(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)
	cred := requireSingleVcdmCredential(t, c)

	require.NoError(t, c.RemoveCredentialsByHash(cred.CredentialInstanceIds))
	require.Empty(t, vcdmCredentials(t, c))
}

func testOpenID4VCIVcdmDenyStoresNothing(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createVcdmPreAuthOffer(t, vcdmTestClaims)
	startOpenID4VCISession(t, c, 1, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	denyPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Dismissed)
	require.Empty(t, vcdmCredentials(t, c))
}

// ---------------------------------------------------------------------------
// VCDM helpers
// ---------------------------------------------------------------------------

// createVcdmPreAuthOffer creates a pre-authorized code offer for the VCDM test
// credential with the given credentialSubject claims.
func createVcdmPreAuthOffer(t *testing.T, claimsJSON string) openid4vciOfferResponse {
	t.Helper()
	return postOffer(t, preAuthIssuerURL, preAuthAdminToken, fmt.Sprintf(`{
		"credentials": [%q],
		"grants": {
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
				"pre-authorized_code": "generate"
			}
		},
		"credentialDataSupplierInput": %s
	}`, vcdmCredentialConfigId, claimsJSON))
}

// vcdmCredentials returns the stored vc+sd-jwt credentials.
func vcdmCredentials(t *testing.T, c *client.Client) []*clientmodels.Credential {
	t.Helper()
	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	var result []*clientmodels.Credential
	for _, cred := range creds {
		if _, ok := cred.CredentialInstanceIds[clientmodels.Format_SdJwtVcdm]; ok {
			result = append(result, cred)
		}
	}
	return result
}

func requireSingleVcdmCredential(t *testing.T, c *client.Client) *clientmodels.Credential {
	t.Helper()
	creds := vcdmCredentials(t, c)
	require.Len(t, creds, 1, "expected exactly one stored VCDM credential")
	return creds[0]
}

// requireVcdmTestAttrs asserts the attributes of the VCDM test credential: the
// three offered claims under credentialSubject, followed by credentialSubject.id.
// Veramo sets that id to the holder key's DID (did:key, the binding method the
// wallet picks from veramo's metadata). It has no display metadata and differs
// per issuance, so its value is taken from the attributes after checking its
// shape.
func requireVcdmTestAttrs(t *testing.T, attrs []clientmodels.Attribute, givenName, familyName, email string) {
	t.Helper()
	requireAttrsInOrder(t, attrs, vcdmTestExpectedAttrs(givenName, familyName, email, vcdmHolderDid(t, attrs))...)
}

// vcdmTestExpectedAttrs lists the VCDM test credential's attributes in order,
// with credentialSubject.id last.
func vcdmTestExpectedAttrs(givenName, familyName, email, holderDid string) []expectedAttr {
	return []expectedAttr{
		{
			Path:        []any{"credentialSubject", "given_name"},
			DisplayName: new("Given Name"),
			Value:       strVal(givenName),
		},
		{
			Path:        []any{"credentialSubject", "family_name"},
			DisplayName: new("Family Name"),
			Value:       strVal(familyName),
		},
		{
			Path:        []any{"credentialSubject", "email"},
			DisplayName: new("Email"),
			Value:       strVal(email),
		},
		{
			Path:  []any{"credentialSubject", "id"},
			Value: strVal(holderDid),
		},
	}
}

// vcdmHolderDid returns the credentialSubject.id value, after checking it is a
// did:key.
func vcdmHolderDid(t *testing.T, attrs []clientmodels.Attribute) string {
	t.Helper()
	for _, attr := range attrs {
		if clientmodels.ClaimPathKey(attr.ClaimPath) != clientmodels.ClaimPathKey([]any{"credentialSubject", "id"}) {
			continue
		}
		require.NotNil(t, attr.Value, "credentialSubject.id should have a value")
		require.NotNil(t, attr.Value.String, "credentialSubject.id should be a string")
		id := *attr.Value.String
		require.True(t, strings.HasPrefix(id, "did:key:"), "credentialSubject.id should be the holder did:key, got %q", id)
		return id
	}
	require.FailNow(t, "credentialSubject.id attribute missing")
	return ""
}
