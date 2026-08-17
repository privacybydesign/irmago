package mdoc_dcql

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"

	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
)

const (
	testDocType   = "eu.europa.ec.av.1"
	testNamespace = "eu.europa.ec.av.1"
	// A doctype with more than one namespace, which the AV profile never has --
	// the shape mDL uses, and the only way to reach the per-namespace merge.
	secondNamespace = "org.iso.18013.5.1.aamva"
	testIssuerURL = "https://issuer.example.com"
	testClientId  = "x509_san_dns:verifier.example.com"
	testNonce     = "n-0S6_WzA2Mj"
	testResponseU = "https://verifier.example.com/response"
	testOrigin    = "https://verifier.example.com"
)

// TestFindCandidatesAndPrepareDisclosureRoundTrip walks one mdoc through every
// step the production paths take — issue, verify and re-encode for storage the
// way services.mdocCredentialFormatParser does, store, match a DCQL query,
// selective-disclose, sign deviceAuth over the OpenID4VP session transcript —
// and then verifies the DeviceResponse the way a conformant verifier would.
//
// It is deliberately end-to-end rather than per-function: every wire-format and
// claim-matching defect found in this handler so far round-tripped fine against
// a single layer and only showed up when the encode and decode sides were
// checked against each other.
func TestFindCandidatesAndPrepareDisclosureRoundTrip(t *testing.T) {
	env := newTestEnv(t)

	query := dcql.CredentialQuery{
		Id:     "av",
		Format: string(clientmodels.Format_MsoMdoc),
		Meta:   &dcql.Meta{DocTypeValue: testDocType},
		Claims: []dcql.Claim{
			{Path: []any{testNamespace, "age_over_18"}, Values: []any{true}},
		},
	}

	require.True(t, env.handler.CanHandleCredentialQuery(query))

	result, err := env.handler.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1, "the stored mdoc must match its own doctype")
	assert.Empty(t, result.ObtainableDescriptors)

	candidate := result.OwnedCandidates[0]
	assert.Equal(t, testDocType, candidate.CredentialId)
	assert.Equal(t, clientmodels.Format_MsoMdoc, candidate.Format)
	assert.Equal(t, env.hash, candidate.Hash)
	require.Len(t, candidate.Attributes, 1)
	assert.Equal(t, []any{testNamespace, "age_over_18"}, candidate.Attributes[0].ClaimPath)

	prepared, err := env.handler.PrepareDisclosure([]dcql.DisclosureSelection{{
		QueryId:              query.Id,
		CredentialHash:       candidate.Hash,
		ClaimPaths:           [][]any{{testNamespace, "age_over_18"}},
		RequireHolderBinding: true,
		ResponseUri:          testResponseU,
	}}, testNonce, testClientId)
	require.NoError(t, err)
	require.Len(t, prepared.QueryResponses, 1)
	assert.Equal(t, query.Id, prepared.QueryResponses[0].QueryId)
	require.Len(t, prepared.QueryResponses[0].Credentials, 1)

	// Verify the response as the verifier does: decode the base64url CBOR into a
	// DeviceResponse and check issuerAuth, the digests of what was disclosed, and
	// deviceAuth over the same session transcript the verifier derives itself.
	encoded, err := base64.RawURLEncoding.DecodeString(prepared.QueryResponses[0].Credentials[0])
	require.NoError(t, err)
	var response stdmdoc.DeviceResponse
	require.NoError(t, cbor.Unmarshal(encoded, &response))
	require.Len(t, response.Documents, 1)

	transcript, err := newOpenID4VPSessionTranscript(testClientId, testNonce, testResponseU, nil)
	require.NoError(t, err)

	results, err := env.verifier.VerifyDeviceResponse(response, testNamespace, testDocType, transcript)
	require.NoError(t, err)
	require.Len(t, results, 1)

	verified := results[0]
	assert.True(t, verified.Valid, "verification failed: %s", verified.Error)
	assert.True(t, verified.DeviceAuthValid, "deviceAuth did not verify: %s", verified.Error)
	assert.Equal(t, testDocType, verified.DocType)
	assert.Equal(t, map[string]any{"age_over_18": true}, verified.Attributes,
		"only the requested element may be disclosed")

	// The activity-log entry covers the same claim, and nothing else leaked into it.
	require.Len(t, prepared.CredentialLogs, 1)
	logEntry := prepared.CredentialLogs[0]
	assert.Equal(t, []clientmodels.CredentialFormat{clientmodels.Format_MsoMdoc}, logEntry.Formats)
	require.Len(t, logEntry.Attributes, 1)
	assert.Equal(t, []any{testNamespace, "age_over_18"}, logEntry.Attributes[0].ClaimPath)
}

// TestPrepareDisclosureRejectsUndisclosedElement pins that an element the DCQL
// query did not ask for never reaches the verifier, which is the property
// selective disclosure exists for and the one a wire-format regression breaks
// most quietly.
func TestPrepareDisclosureRejectsUndisclosedElement(t *testing.T) {
	env := newTestEnv(t)

	prepared, err := env.disclose(t)
	require.NoError(t, err)

	encoded, err := base64.RawURLEncoding.DecodeString(prepared.QueryResponses[0].Credentials[0])
	require.NoError(t, err)
	var response stdmdoc.DeviceResponse
	require.NoError(t, cbor.Unmarshal(encoded, &response))

	transcript, err := newOpenID4VPSessionTranscript(testClientId, testNonce, testResponseU, nil)
	require.NoError(t, err)
	results, err := env.verifier.VerifyDeviceResponse(response, testNamespace, testDocType, transcript)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.NotContains(t, results[0].Attributes, "age_over_21")
	assert.NotContains(t, results[0].Attributes, "age_over_16")
}

// TestFindCandidatesRejectsQueryWithoutDocType and the two cases below cover
// the branches FindCandidates takes when it cannot produce a candidate.
func TestFindCandidatesRejectsQueryWithoutDocType(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.handler.FindCandidates(dcql.CredentialQuery{
		Id:     "av",
		Format: string(clientmodels.Format_MsoMdoc),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "doctype_value")
}

func TestFindCandidatesDescribesUnownedDocType(t *testing.T) {
	env := newTestEnv(t)

	result, err := env.handler.FindCandidates(dcql.CredentialQuery{
		Id:     "pid",
		Format: string(clientmodels.Format_MsoMdoc),
		Meta:   &dcql.Meta{DocTypeValue: "eu.europa.ec.eudi.pid.1"},
		Claims: []dcql.Claim{{Path: []any{"eu.europa.ec.eudi.pid.1", "family_name"}}},
	})
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates)
	require.Len(t, result.ObtainableDescriptors, 1)
	assert.Equal(t, "eu.europa.ec.eudi.pid.1", result.ObtainableDescriptors[0].CredentialId)
}

func TestFindCandidatesSkipsCredentialMissingRequestedClaim(t *testing.T) {
	env := newTestEnv(t)

	result, err := env.handler.FindCandidates(dcql.CredentialQuery{
		Id:     "av",
		Format: string(clientmodels.Format_MsoMdoc),
		Meta:   &dcql.Meta{DocTypeValue: testDocType},
		Claims: []dcql.Claim{{Path: []any{testNamespace, "age_over_65"}}},
	})
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates)
	assert.Len(t, result.ObtainableDescriptors, 1)
}

// TestPrepareDisclosureBurnsOneInstancePerPresentation covers the single-use
// half of the batch model: each presentation consumes one instance and
// decrements the batch's remaining count, and once they are gone
// FindCandidates reports the batch as exhausted rather than silently offering
// a credential that cannot be presented.
func TestPrepareDisclosureBurnsOneInstancePerPresentation(t *testing.T) {
	env := newTestEnvWithBatchSize(t, 2)

	query := dcql.CredentialQuery{
		Id:     "av",
		Format: string(clientmodels.Format_MsoMdoc),
		Meta:   &dcql.Meta{DocTypeValue: testDocType},
		Claims: []dcql.Claim{{Path: []any{testNamespace, "age_over_18"}}},
	}

	result, err := env.handler.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)
	require.NotNil(t, result.OwnedCandidates[0].BatchInstanceCountRemaining)
	assert.Equal(t, uint(2), *result.OwnedCandidates[0].BatchInstanceCountRemaining)

	for remaining := uint(1); ; remaining-- {
		_, err := env.disclose(t)
		require.NoError(t, err)

		batch, err := env.store.GetBatchByHash(env.hash)
		require.NoError(t, err)
		assert.Equal(t, remaining, batch.RemainingCount)

		if remaining == 0 {
			break
		}
	}

	_, err = env.handler.FindCandidates(query)
	require.Error(t, err, "an exhausted batch must not be offered as a candidate")
	assert.Contains(t, err.Error(), "exhausted")
}

// TestPrepareDisclosureKeepsBatchOfOneReusable is the other half: a batch of one
// is not consumed, so the credential stays presentable. Marking it used would
// make a single-credential wallet work exactly once.
func TestPrepareDisclosureKeepsBatchOfOneReusable(t *testing.T) {
	env := newTestEnv(t)

	for i := range 2 {
		_, err := env.disclose(t)
		require.NoError(t, err, "presentation %d", i+1)
	}

	batch, err := env.store.GetBatchByHash(env.hash)
	require.NoError(t, err)
	assert.Equal(t, uint(1), batch.RemainingCount)

	instance, err := env.store.GetUnusedInstance(batch.ID)
	require.NoError(t, err)
	assert.False(t, instance.Used)
}

// CanHandleCredentialQuery is the dispatch every other handler relies on to not
// be handed an mdoc, and vice versa.
func TestCanHandleCredentialQuery(t *testing.T) {
	handler := &MdocDcqlHandler{}

	assert.True(t, handler.CanHandleCredentialQuery(dcql.CredentialQuery{Format: "mso_mdoc"}))
	assert.False(t, handler.CanHandleCredentialQuery(dcql.CredentialQuery{Format: "dc+sd-jwt"}))
	assert.False(t, handler.CanHandleCredentialQuery(dcql.CredentialQuery{}))
}

// TestFindCandidatesWithClaimSetsPicksFirstSatisfiableSet covers claim_sets,
// which this handler implements by copying eudi_sdjwt_dcql and which, until now,
// had no test in any format's package except irma_sdjwt_dcql -- so the mdoc copy
// had never executed.
//
// One query exercises all three behaviours at once: an unsatisfiable set is
// skipped (age_over_65 is not stored), the first satisfiable one wins over a
// later one that would also match, and only that set's claims are offered.
func TestFindCandidatesWithClaimSetsPicksFirstSatisfiableSet(t *testing.T) {
	env := newTestEnv(t)

	result, err := env.handler.FindCandidates(dcql.CredentialQuery{
		Id:     "av",
		Format: string(clientmodels.Format_MsoMdoc),
		Meta:   &dcql.Meta{DocTypeValue: testDocType},
		Claims: []dcql.Claim{
			{Id: "over65", Path: []any{testNamespace, "age_over_65"}},
			{Id: "over18", Path: []any{testNamespace, "age_over_18"}},
			{Id: "over16", Path: []any{testNamespace, "age_over_16"}},
		},
		ClaimSets: [][]string{{"over65"}, {"over18"}, {"over16"}},
	})
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)

	attrs := result.OwnedCandidates[0].Attributes
	require.Len(t, attrs, 1, "only the satisfied set's claims may be offered")
	assert.Equal(t, []any{testNamespace, "age_over_18"}, attrs[0].ClaimPath)
}

// TestFindCandidatesWithClaimSetsRequiresEveryClaimInASet pins the allFound
// half: a set is satisfied only when every claim in it matches, so a set that
// matches partially must be passed over rather than offered short.
func TestFindCandidatesWithClaimSetsRequiresEveryClaimInASet(t *testing.T) {
	env := newTestEnv(t)

	result, err := env.handler.FindCandidates(dcql.CredentialQuery{
		Id:     "av",
		Format: string(clientmodels.Format_MsoMdoc),
		Meta:   &dcql.Meta{DocTypeValue: testDocType},
		Claims: []dcql.Claim{
			{Id: "over18", Path: []any{testNamespace, "age_over_18"}},
			{Id: "over65", Path: []any{testNamespace, "age_over_65"}},
			{Id: "over16", Path: []any{testNamespace, "age_over_16"}},
		},
		// The first set is only half-satisfiable, so the second must win whole.
		ClaimSets: [][]string{{"over18", "over65"}, {"over18", "over16"}},
	})
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)

	paths := make([][]any, 0, 2)
	for _, attr := range result.OwnedCandidates[0].Attributes {
		paths = append(paths, attr.ClaimPath)
	}
	assert.Equal(t, [][]any{
		{testNamespace, "age_over_18"},
		{testNamespace, "age_over_16"},
	}, paths, "a partially satisfiable set must not be offered with its missing claim dropped")
}

// TestFindCandidatesWithClaimSetsNoneSatisfiable covers both ways a set fails:
// a claim that is not stored, and an id in claim_sets naming no claim at all.
func TestFindCandidatesWithClaimSetsNoneSatisfiable(t *testing.T) {
	env := newTestEnv(t)

	result, err := env.handler.FindCandidates(dcql.CredentialQuery{
		Id:     "av",
		Format: string(clientmodels.Format_MsoMdoc),
		Meta:   &dcql.Meta{DocTypeValue: testDocType},
		Claims: []dcql.Claim{
			{Id: "over65", Path: []any{testNamespace, "age_over_65"}},
		},
		ClaimSets: [][]string{{"over65"}, {"nosuchclaim"}},
	})
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates)
	assert.Len(t, result.ObtainableDescriptors, 1)
}

// TestFindCandidatesRefusesQueryWithoutClaims pins the mso_mdoc reading of an
// absent claims member. eudi_sdjwt_dcql treats it as "no selectively disclosable
// claims requested" and still matches, which leaves an SD-JWT its always-
// disclosed payload to present; an mdoc has no such payload, so the same reading
// would sign an empty namespaces map and offer the user an attribute-less
// credential. See the comment in FindCandidates.
func TestFindCandidatesRefusesQueryWithoutClaims(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.handler.FindCandidates(dcql.CredentialQuery{
		Id:     "av",
		Format: string(clientmodels.Format_MsoMdoc),
		Meta:   &dcql.Meta{DocTypeValue: testDocType},
	})
	require.Error(t, err, "a claim-less mdoc query can only produce a signature over no elements")
	assert.Contains(t, err.Error(), "no claims")
}

// TestFindCandidatesCarriesIntentToRetain covers the OpenID4VP mso_mdoc claims
// parameter the wallet cannot act on but must show: it changes what the user is
// consenting to. SD-JWT VC has no equivalent, so no SD-JWT test would ever have
// surfaced its absence.
func TestFindCandidatesCarriesIntentToRetain(t *testing.T) {
	env := newTestEnv(t)

	result, err := env.handler.FindCandidates(dcql.CredentialQuery{
		Id:     "av",
		Format: string(clientmodels.Format_MsoMdoc),
		Meta:   &dcql.Meta{DocTypeValue: testDocType},
		Claims: []dcql.Claim{
			{Path: []any{testNamespace, "age_over_18"}, IntentToRetain: true},
			{Path: []any{testNamespace, "age_over_16"}},
		},
	})
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)

	flagByPath := map[string]*bool{}
	for _, attr := range result.OwnedCandidates[0].Attributes {
		flagByPath[clientmodels.ClaimPathKey(attr.ClaimPath)] = attr.IntentToRetain
	}
	retained := flagByPath[clientmodels.ClaimPathKey([]any{testNamespace, "age_over_18"})]
	notRetained := flagByPath[clientmodels.ClaimPathKey([]any{testNamespace, "age_over_16"})]

	require.NotNil(t, retained)
	require.NotNil(t, notRetained,
		"every mdoc attribute carries the flag, so the UI can tell a declared false from a format that cannot declare")
	assert.True(t, *retained)
	assert.False(t, *notRetained)
}

// TestFindCandidatesRefusesMalformedClaimPath pins that a path which is not
// exactly [namespace, elementIdentifier] never matches a stored mdoc. The shape
// check is also what keeps such a path out of authorization
// (dcql.AuthorizationAttributeNames contributes no name for one), so the two
// have to agree: if a malformed path matched here it would disclose an element
// no relying party was authorized for.
func TestFindCandidatesRefusesMalformedClaimPath(t *testing.T) {
	for name, path := range map[string][]any{
		"one component":        {"age_over_18"},
		"three components":     {testNamespace, "age_over_18", "extra"},
		"non-string namespace": {0, "age_over_18"},
		"non-string element":   {testNamespace, 0},
		"empty":                {},
	} {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t)

			result, err := env.handler.FindCandidates(dcql.CredentialQuery{
				Id:     "av",
				Format: string(clientmodels.Format_MsoMdoc),
				Meta:   &dcql.Meta{DocTypeValue: testDocType},
				Claims: []dcql.Claim{{Path: path}},
			})
			require.NoError(t, err)
			assert.Empty(t, result.OwnedCandidates,
				"a claim path that is not [namespace, elementIdentifier] must not match a stored mdoc")
		})
	}
}

// TestSelectiveDiscloseByPathsSpansNamespaces covers the per-namespace grouping
// and merge, which every other test in this package leaves untouched because the
// AV profile has exactly one namespace. An mDL request spanning
// org.iso.18013.5.1 and its aamva companion would otherwise reach the merge for
// the first time in production, and the merge is the part that rebuilds
// IssuerSigned.NameSpaces from scratch.
func TestSelectiveDiscloseByPathsSpansNamespaces(t *testing.T) {
	doc := newTwoNamespaceMdoc(t, secondNamespace)

	disclosed, err := selectiveDiscloseByPaths(doc, [][]any{
		{testNamespace, "age_over_18"},
		{secondNamespace, "age_over_21"},
	})
	require.NoError(t, err)

	require.Len(t, disclosed.IssuerSigned.NameSpaces, 2, "both requested namespaces must survive the merge")
	assert.Equal(t, []string{"age_over_18"},
		disclosedElements(t, disclosed.IssuerSigned.NameSpaces[testNamespace]))
	assert.Equal(t, []string{"age_over_21"},
		disclosedElements(t, disclosed.IssuerSigned.NameSpaces[secondNamespace]))
}

// TestSelectiveDiscloseByPathsOmitsUnrequestedNamespace is the privacy half: a
// namespace nothing was asked from must be absent entirely, not present and
// empty. The credential carries both.
func TestSelectiveDiscloseByPathsOmitsUnrequestedNamespace(t *testing.T) {
	doc := newTwoNamespaceMdoc(t, secondNamespace)

	disclosed, err := selectiveDiscloseByPaths(doc, [][]any{{testNamespace, "age_over_18"}})
	require.NoError(t, err)

	require.Len(t, disclosed.IssuerSigned.NameSpaces, 1)
	_, present := disclosed.IssuerSigned.NameSpaces[secondNamespace]
	assert.False(t, present, "a namespace nothing was requested from must not appear at all")
}

// TestSelectiveDiscloseByPathsMalformedPathNeverWidensDisclosure pins the
// invariant that survives whichever way the malformed-path handling is settled:
// a path of the wrong shape may cause an element to be withheld, but it must
// never cause one to be revealed. Note age_over_21 stays undisclosed even though
// a three-component path names it.
func TestSelectiveDiscloseByPathsMalformedPathNeverWidensDisclosure(t *testing.T) {
	doc := newTwoNamespaceMdoc(t, secondNamespace)

	disclosed, err := selectiveDiscloseByPaths(doc, [][]any{
		{testNamespace, "age_over_18"},
		{testNamespace},
		{testNamespace, "age_over_21", "extra"},
		{secondNamespace, 0},
		{},
	})
	require.NoError(t, err)

	require.Len(t, disclosed.IssuerSigned.NameSpaces, 1)
	assert.Equal(t, []string{"age_over_18"},
		disclosedElements(t, disclosed.IssuerSigned.NameSpaces[testNamespace]))
}

// ---------------------------------------------------------------------------
// Test environment
// ---------------------------------------------------------------------------

type testEnv struct {
	handler  *MdocDcqlHandler
	verifier *stdmdoc.Verifier
	store    db.CredentialStore
	hash     string
}

// newTestEnv stores a batch of one, the reusable case.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvWithBatchSize(t, 1)
}

// newTestEnvWithBatchSize issues batchSize real mdocs, each with its own device
// key as issuance does, runs every one through the production format parser and
// stores them as one batch — so the handler reads exactly the bytes issuance
// writes rather than a hand-built fixture.
func newTestEnvWithBatchSize(t *testing.T, batchSize uint) *testEnv {
	t.Helper()

	issuer, err := stdmdoc.NewIssuer()
	require.NoError(t, err)
	verifier := stdmdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})
	parser := services.NewMdocCredentialFormatParser(verifier)

	var instances []models.IssuedCredentialInstance
	var first *services.ParsedCredential
	for range batchSize {
		holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		holderKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(holderKey)
		require.NoError(t, err)

		issued, err := issuer.Issue(testDocType, testNamespace, map[string]any{
			"age_over_18": true,
			"age_over_16": true,
			"age_over_21": false,
		}, &holderKey.PublicKey)
		require.NoError(t, err)

		issuedCBOR, err := cbor.Marshal(issued)
		require.NoError(t, err)

		// The same seam client.New registers for mso_mdoc: it decides both the
		// claims cache the handler matches on and the raw bytes it re-decodes.
		parsed, err := parser.ParseAndVerify(base64.RawURLEncoding.EncodeToString(issuedCBOR), testIssuerURL, true)
		require.NoError(t, err)
		require.Equal(t, models.CredentialFormatMsoMdoc, parsed.Format)
		require.Equal(t, testDocType, parsed.VerifiableCredentialType)
		require.NotNil(t, parsed.HolderBindingKeyThumbprint)
		if first == nil {
			first = parsed
		}

		instances = append(instances, models.IssuedCredentialInstance{
			RawCredential: parsed.RawCredentialBytes,
			HolderBindingKey: &models.HolderBindingKey{
				Algorithm:           models.KeyAlgorithmECDSA,
				PublicKeyThumbprint: datatypes.NullString{V: *parsed.HolderBindingKeyThumbprint, Valid: true},
				PrivateKey:          holderKeyPKCS8,
				ECDSA:               &models.ECDSAKeyMetadata{CurveName: "P-256"},
			},
		})
	}

	eudiStorage := newTestStorage(t)
	store := db.NewCredentialStore(eudiStorage.Db())

	const hash = "test-mdoc-batch-hash"
	require.NoError(t, store.StoreBatch(&models.CredentialBatch{
		IssuerURL:                first.IssuerURL,
		VerifiableCredentialType: first.VerifiableCredentialType,
		Format:                   first.Format,
		Hash:                     hash,
		ProcessedSdJwtPayload:    datatypes.JSON(first.ResolvedClaims),
		IssuedAt:                 nullTimeFromUnix(first.IssuedAt),
		ExpiresAt:                nullTimeFromUnix(first.ExpiresAt),
		NotBefore:                nullTimeFromUnix(first.NotBefore),
		BatchSize:                batchSize,
		RemainingCount:           batchSize,
		CredentialIssuer:         testIssuerURL,
		Instances:                instances,
	}))

	return &testEnv{
		handler:  NewMdocDcqlHandler(eudiStorage, clientmodels.NewCurrentLocale("en")),
		verifier: verifier,
		store:    store,
		hash:     hash,
	}
}

// TestPrepareDisclosureOverDcApiSignsTheDcApiHandover verifies a presentation
// delivered through the Digital Credentials API the way a conformant verifier
// would: against a transcript this test derives itself from the spec formula
// (Annex B.2.6.2), not from the production helper.
//
// Deriving it here is the point. A test that called newDcApiSessionTranscript
// would agree with whatever this package builds, including the URL-flow
// handover — which is exactly the mistake worth catching, since the DC API's
// inputs pass unremarked through the other variant: an origin-prefixed audience
// is still a string, and an empty response_uri is legal for an unencrypted URL
// session.
func TestPrepareDisclosureOverDcApiSignsTheDcApiHandover(t *testing.T) {
	env := newTestEnv(t)

	prepared, err := env.handler.PrepareDisclosure([]dcql.DisclosureSelection{{
		QueryId:              "av",
		CredentialHash:       env.hash,
		ClaimPaths:           [][]any{{testNamespace, "age_over_18"}},
		RequireHolderBinding: true,
		// What the DC API path actually passes: no response_uri, since the
		// response goes back through the platform (eudi/openid4vp/dc_api.go).
		ResponseUri: "",
		OverDcApi:   true,
		Origin:      testOrigin,
	}}, testNonce, "origin:"+testOrigin)
	require.NoError(t, err)
	require.Len(t, prepared.QueryResponses, 1)

	encoded, err := base64.RawURLEncoding.DecodeString(prepared.QueryResponses[0].Credentials[0])
	require.NoError(t, err)
	var response stdmdoc.DeviceResponse
	require.NoError(t, cbor.Unmarshal(encoded, &response))

	results, err := env.verifier.VerifyDeviceResponse(
		response, testNamespace, testDocType, expectedDcApiTranscript(t, testOrigin, testNonce))
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid, "verification failed: %s", results[0].Error)
	assert.True(t, results[0].DeviceAuthValid, "deviceAuth did not verify: %s", results[0].Error)
	assert.Equal(t, map[string]any{"age_over_18": true}, results[0].Attributes)
}

// TestPrepareDisclosureOverDcApiRejectsTheUrlFlowHandover is the negative half:
// the URL-flow transcript must not verify a DC API presentation. Without it the
// test above would still pass if both variants happened to agree.
func TestPrepareDisclosureOverDcApiRejectsTheUrlFlowHandover(t *testing.T) {
	env := newTestEnv(t)

	prepared, err := env.handler.PrepareDisclosure([]dcql.DisclosureSelection{{
		QueryId:              "av",
		CredentialHash:       env.hash,
		ClaimPaths:           [][]any{{testNamespace, "age_over_18"}},
		RequireHolderBinding: true,
		OverDcApi:            true,
		Origin:               testOrigin,
	}}, testNonce, "origin:"+testOrigin)
	require.NoError(t, err)

	encoded, err := base64.RawURLEncoding.DecodeString(prepared.QueryResponses[0].Credentials[0])
	require.NoError(t, err)
	var response stdmdoc.DeviceResponse
	require.NoError(t, cbor.Unmarshal(encoded, &response))

	urlFlow, err := newOpenID4VPSessionTranscript("origin:"+testOrigin, testNonce, "", nil)
	require.NoError(t, err)

	results, err := env.verifier.VerifyDeviceResponse(response, testNamespace, testDocType, urlFlow)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.False(t, results[0].DeviceAuthValid,
		"the URL-flow handover must not verify a presentation made over the DC API")
}

// TestPrepareDisclosureOverDcApiWithoutOriginFails pins that the origin is
// required rather than defaulted. The platform authenticates it, and it is the
// first element of what deviceAuth signs, so an empty one can only produce a
// signature no verifier reproduces.
func TestPrepareDisclosureOverDcApiWithoutOriginFails(t *testing.T) {
	env := newTestEnvWithBatchSize(t, 2)

	_, err := env.handler.PrepareDisclosure([]dcql.DisclosureSelection{{
		QueryId:              "av",
		CredentialHash:       env.hash,
		ClaimPaths:           [][]any{{testNamespace, "age_over_18"}},
		RequireHolderBinding: true,
		OverDcApi:            true,
	}}, testNonce, "")
	require.ErrorContains(t, err, "origin")

	// Failing must also be free: a refused session may not consume a single-use
	// instance the holder can never get back.
	batch, err := env.store.GetBatchByHash(env.hash)
	require.NoError(t, err)
	assert.Equal(t, uint(2), batch.RemainingCount)
}

// expectedDcApiTranscript spells out OpenID4VP Annex B.2.6.2 rather than calling
// the production helper, so a change to either side has to be made twice.
func expectedDcApiTranscript(t *testing.T, origin, nonce string) stdmdoc.SessionTranscript {
	t.Helper()

	// HandoverInfo = [origin, nonce, jwkThumbprint]; the response is unencrypted
	// here, which puts a CBOR null in the thumbprint slot.
	handoverInfo, err := cbor.Marshal([]any{origin, nonce, nil})
	require.NoError(t, err)
	digest := sha256.Sum256(handoverInfo)

	return stdmdoc.SessionTranscript{
		Handover: []any{"OpenID4VPDCAPIHandover", digest[:]},
	}
}

// disclose runs one age_over_18 presentation through the handler.
func (e *testEnv) disclose(t *testing.T) (*dcql.PreparedDisclosure, error) {
	t.Helper()
	return e.handler.PrepareDisclosure([]dcql.DisclosureSelection{{
		QueryId:              "av",
		CredentialHash:       e.hash,
		ClaimPaths:           [][]any{{testNamespace, "age_over_18"}},
		RequireHolderBinding: true,
		ResponseUri:          testResponseU,
	}}, testNonce, testClientId)
}

// newTwoNamespaceMdoc issues a real mdoc and grafts a second namespace onto it
// carrying the same items.
//
// The grafted namespace's digests are not in the MSO, so the result would not
// verify -- which is fine for what the tests using it assert: how
// selectiveDiscloseByPaths groups paths by namespace and merges the per-namespace
// results, not whether the merged document verifies. Issuing a genuinely
// two-namespace mdoc would mean extending stdmdoc.Issuer.Issue, which signs one
// namespace at a time, and that is production surface these tests do not need.
func newTwoNamespaceMdoc(t *testing.T, second string) *stdmdoc.MDoc {
	t.Helper()

	issuer, err := stdmdoc.NewIssuer()
	require.NoError(t, err)

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	doc, err := issuer.Issue(testDocType, testNamespace, map[string]any{
		"age_over_18": true,
		"age_over_21": false,
	}, &holderKey.PublicKey)
	require.NoError(t, err)

	doc.IssuerSigned.NameSpaces[second] = doc.IssuerSigned.NameSpaces[testNamespace]
	return doc
}

// disclosedElements names the elements actually present in a namespace's
// disclosed items, unwrapping Tag 24 the way a verifier does. Asserting on the
// identifiers rather than the item count is what distinguishes "one element
// disclosed" from "the right one disclosed".
func disclosedElements(t *testing.T, items []stdmdoc.Tag24Item) []string {
	t.Helper()

	names := make([]string, 0, len(items))
	for _, item := range items {
		var rawTag cbor.RawTag
		require.NoError(t, cbor.Unmarshal(item.EncodedItem, &rawTag))
		var innerBytes []byte
		require.NoError(t, cbor.Unmarshal(rawTag.Content, &innerBytes))
		var decoded stdmdoc.IssuerSignedItem
		require.NoError(t, cbor.Unmarshal(innerBytes, &decoded))
		names = append(names, decoded.ElementIdentifier)
	}
	return names
}

func newTestStorage(t *testing.T) storage.Storage {
	t.Helper()

	var aesKey [32]byte
	copy(aesKey[:], "0123456789abcdef0123456789abcdef")

	s, err := storage.NewStorageWithDialector(
		sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", aesKey[:])},
		filesystem.NewFileSystemStorage(aesKey, t.TempDir()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func nullTimeFromUnix(unix *int64) datatypes.NullTime {
	if unix == nil {
		return datatypes.NullTime{}
	}
	return datatypes.NullTime{V: time.Unix(*unix, 0).UTC(), Valid: true}
}
