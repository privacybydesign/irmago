package eudi_vcdm_dcql

// VCDM FindCandidates/PrepareDisclosure behaviour, exercised through the real
// handler (NewVcdmDcqlHandler + the production VCDM profile) rather than a mirror
// profile. These link SQLCipher (cgo) via the shared scaffolding, so they
// type-check locally but run in CI.

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/sdjwtdcqltest"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The composite @context+type identity a verifier echoes as a vct value to
// target this VCDM credential (F2/#682 convention). The test controls both the
// stored batch's type and the query, so the exact string only has to match itself.
const academicVcdmType = "https://www.w3.org/ns/credentials/v2 https://eduwallet.nl/context/academic/v1 VerifiableCredential AcademicBaseCredential"

// newTestHandler builds the real VCDM handler over an in-memory store. FindCandidates
// needs no key binder or revocation checker, so both are nil.
func newTestHandler(t *testing.T) (*Handler, db.VcdmStore) {
	t.Helper()
	ts := sdjwtdcqltest.NewTestStorage(t)
	store := db.NewVcdmStore(ts.Db())
	h := NewVcdmDcqlHandler(ts, store, nil, clientmodels.NewCurrentLocale("en"))
	return h, store
}

func newTestBatch(hash, credType string, payload map[string]any) *models.VcdmBatch {
	return sdjwtdcqltest.NewTestVcdmBatch(hash, credType, payload)
}

func parseDcqlQuery(t *testing.T, raw string) dcql.CredentialQuery {
	return sdjwtdcqltest.ParseDcqlQuery(t, raw)
}

func hasClaimPath(attrs []clientmodels.Attribute, path []any) bool {
	return sdjwtdcqltest.HasClaimPath(attrs, path)
}

// ========================================================================
// FindCandidates: matching, format isolation, envelope scoping
// ========================================================================

func TestVcdmFindCandidates_MatchesCompositeTypeAndSubjectClaims(t *testing.T) {
	h, store := newTestHandler(t)

	typeIdentity := "https://www.w3.org/ns/credentials/v2 VerifiableCredential ExampleCredential"
	batch := newTestBatch("hash-vcdm-match", typeIdentity, map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential", "ExampleCredential"},
		"issuer":            "https://issuer.example",
		"credentialSubject": map[string]any{"given_name": "Alice"},
	})
	require.NoError(t, store.StoreBatch(batch))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "vc+sd-jwt",
		"meta": {"vct_values": ["https://www.w3.org/ns/credentials/v2 VerifiableCredential ExampleCredential"]},
		"claims": [{"path": ["credentialSubject", "given_name"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)

	cand := result.OwnedCandidates[0]
	assert.Equal(t, typeIdentity, cand.CredentialId)
	assert.Equal(t, "hash-vcdm-match", cand.Hash)
	assert.Equal(t, clientmodels.Format_SdJwtVcdm, cand.Format)
	assert.True(t, hasClaimPath(cand.Attributes, []any{"credentialSubject", "given_name"}),
		"the requested credentialSubject claim should be previewed")
}

func TestVcdmFindCandidates_ExcludesSdJwtVcBatch(t *testing.T) {
	ts := sdjwtdcqltest.NewTestStorage(t)
	h := NewVcdmDcqlHandler(ts, db.NewVcdmStore(ts.Db()), nil, clientmodels.NewCurrentLocale("en"))

	// A dc+sd-jwt (SD-JWT VC) batch lives in the SD-JWT VC table and must not be
	// served for a vc+sd-jwt query.
	batch := sdjwtdcqltest.NewTestBatch("hash-sdjwtvc", "https://example.com/EmailCredential", map[string]any{
		"credentialSubject": map[string]any{"email": "test@example.com"},
	})
	require.NoError(t, db.NewSdJwtVcStore(ts.Db()).StoreBatch(batch))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "vc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]},
		"claims": [{"path": ["credentialSubject", "email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates, "a dc+sd-jwt batch is not a vc+sd-jwt candidate")
}

// TestVcdmFindCandidates_RealCredentialHidesEnvelope drives the disclosure
// preview off a real issued VCDM SD-JWT (so the post-disclosure view path runs,
// not the synthetic-batch fallback) and asserts the VCDM envelope
// (@context/type/issuer/validFrom/validUntil) never surfaces as a disclosable
// attribute — the real handler's credentialSubject-only scoping.
func TestVcdmFindCandidates_RealCredentialHidesEnvelope(t *testing.T) {
	h, store := newTestHandler(t)

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(vcdmsdjwt.AcademicBaseCredentialJSON), &payload))

	batch := newTestBatch("hash-vcdm-real", academicVcdmType, payload)
	raw := vcdmsdjwt.IssueTestSdJwtVcdm(t, vcdmsdjwt.AcademicBaseCredentialClaims(t))
	batch.Instances[0].RawCredential = []byte(raw)
	require.NoError(t, store.StoreBatch(batch))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "vc+sd-jwt",
		"meta": {"vct_values": ["`+academicVcdmType+`"]},
		"claims": [{"path": ["credentialSubject", "given_name"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)

	cand := result.OwnedCandidates[0]
	assert.True(t, hasClaimPath(cand.Attributes, []any{"credentialSubject", "given_name"}),
		"the requested credentialSubject claim should be previewed")

	for _, a := range cand.Attributes {
		require.NotEmpty(t, a.ClaimPath)
		top, _ := a.ClaimPath[0].(string)
		assert.NotContains(t, []string{"@context", "type", "issuer", "validFrom", "validUntil"}, top,
			"VCDM envelope key leaked into the disclosure preview: %v", a.ClaimPath)
	}
}

// TestVcdmFindCandidates_EmptyMetaMatchesByClaims mirrors the eduwallet PID
// request: format vc+sd-jwt, empty meta, a credentialSubject claim. Per §6.1 the
// credential must still match by claims alone even without vct_values.
func TestVcdmFindCandidates_EmptyMetaMatchesByClaims(t *testing.T) {
	h, store := newTestHandler(t)

	typeIdentity := "https://www.w3.org/ns/credentials/v2 VerifiableCredential PidCredential"
	batch := newTestBatch("hash-vcdm-pid", typeIdentity, map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential", "PidCredential"},
		"issuer":            "https://issuer.example",
		"credentialSubject": map[string]any{"personal_administrative_number": "PID-12345"},
	})
	require.NoError(t, store.StoreBatch(batch))

	query := parseDcqlQuery(t, `{
		"id": "PID",
		"format": "vc+sd-jwt",
		"meta": {},
		"claims": [{"path": ["credentialSubject", "personal_administrative_number"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1, "empty meta must still match a vc+sd-jwt credential by its claims")
	assert.Equal(t, clientmodels.Format_SdJwtVcdm, result.OwnedCandidates[0].Format)
}

// TestVcdmFindCandidates_TypeValuesSupersetMatch pins OpenID4VP §B.1.1: a
// vc+sd-jwt query targets a VCDM credential by its JSON-LD `type` set. The match
// is on the `type` array — not the @context-fused CredentialType — so a domain
// @context and an unrelated stored composite identity do not prevent it.
func TestVcdmFindCandidates_TypeValuesSupersetMatch(t *testing.T) {
	h, store := newTestHandler(t)

	batch := newTestBatch("hash-vcdm-tv", "some stored composite identity", map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2", "https://eduwallet.nl/context/academic/v1"},
		"type":              []any{"VerifiableCredential", "ExampleCredential"},
		"credentialSubject": map[string]any{"given_name": "Alice"},
	})
	require.NoError(t, store.StoreBatch(batch))

	for _, tv := range []string{
		`[["ExampleCredential"]]`,                         // one requested type, present
		`[["VerifiableCredential", "ExampleCredential"]]`, // full superset
	} {
		res, err := h.FindCandidates(parseDcqlQuery(t, `{
			"id": "q1", "format": "vc+sd-jwt",
			"meta": {"type_values": `+tv+`},
			"claims": [{"path": ["credentialSubject", "given_name"]}]
		}`))
		require.NoError(t, err)
		require.Len(t, res.OwnedCandidates, 1, "type_values %s should match by the type array", tv)
	}
}

func TestVcdmFindCandidates_TypeValuesDisjunctionAndNonMatch(t *testing.T) {
	h, store := newTestHandler(t)

	batch := newTestBatch("hash-vcdm-tv2", "composite", map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential", "ExampleCredential"},
		"credentialSubject": map[string]any{"given_name": "Alice"},
	})
	require.NoError(t, store.StoreBatch(batch))

	cases := []struct {
		name       string
		typeValues string
		wantMatch  bool
	}{
		{"disjunction: second inner array matches", `[["OtherCredential"], ["ExampleCredential"]]`, true},
		{"not a superset: an extra required type is absent", `[["ExampleCredential", "MissingType"]]`, false},
		{"no inner array matches", `[["NopeA"], ["NopeB"]]`, false},
	}
	for _, c := range cases {
		res, err := h.FindCandidates(parseDcqlQuery(t, `{
			"id": "q1", "format": "vc+sd-jwt",
			"meta": {"type_values": `+c.typeValues+`},
			"claims": [{"path": ["credentialSubject", "given_name"]}]
		}`))
		require.NoError(t, err, c.name)
		if c.wantMatch {
			require.Len(t, res.OwnedCandidates, 1, c.name)
		} else {
			require.Empty(t, res.OwnedCandidates, c.name)
		}
	}
}

// ========================================================================
// PrepareDisclosure: present a real VCDM credential and decode the result
// ========================================================================

func TestVcdmPrepareDisclosure_RoundTrip(t *testing.T) {
	h, store := newTestHandler(t)

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(vcdmsdjwt.AcademicBaseCredentialJSON), &payload))

	batch := newTestBatch("hash-vcdm-present", academicVcdmType, payload)
	raw := vcdmsdjwt.IssueTestSdJwtVcdm(t, vcdmsdjwt.AcademicBaseCredentialClaims(t))
	batch.Instances[0].RawCredential = []byte(raw)
	require.NoError(t, store.StoreBatch(batch))

	selections := []dcql.DisclosureSelection{{
		QueryId:        "q1",
		CredentialHash: "hash-vcdm-present",
		ClaimPaths:     [][]any{{"credentialSubject", "given_name"}},
	}}

	result, err := h.PrepareDisclosure(selections, "nonce-1", "verifier-1")
	require.NoError(t, err)
	require.Len(t, result.QueryResponses, 1)
	require.Len(t, result.QueryResponses[0].Credentials, 1)

	presentation := result.QueryResponses[0].Credentials[0]
	require.NotEmpty(t, presentation)

	// The presentation discloses exactly the selected credentialSubject claim:
	// given_name resolves, the other selectively-disclosable subject claims stay
	// hidden, and the envelope is untouched.
	view, err := sdjwt.PostDisclosureView(sdjwt.SdJwt(presentation), [][]any{{"credentialSubject", "given_name"}})
	require.NoError(t, err)

	subject, ok := view["credentialSubject"].(map[string]any)
	require.True(t, ok, "credentialSubject should be present in the disclosed view")
	assert.Equal(t, "Alice", subject["given_name"], "the selected claim should be disclosed")
	assert.NotContains(t, subject, "family_name", "unselected selectively-disclosable claims must stay hidden")

	// A batch of one keeps its single instance reusable.
	reloaded, err := store.GetBatchByHashAndFormat("hash-vcdm-present", models.CredentialFormatSdJwtVcdm)
	require.NoError(t, err)
	assert.Equal(t, uint(1), reloaded.RemainingCount)
}
