package eudi_vcdm_dcql

// VCDM FindCandidates/PrepareDisclosure behaviour, exercised through the real
// handler (NewVcdmDcqlHandler + the production VCDM profile) rather than a mirror
// profile. These link SQLCipher (cgo) via the shared scaffolding, so they
// type-check locally but run in CI.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/sdjwt_dcqltest"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

// The composite @context+type identity a verifier echoes as a vct value to
// target this VCDM credential (F2/#682 convention). The test controls both the
// stored batch's type and the query, so the exact string only has to match itself.
const academicVcdmType = "https://www.w3.org/ns/credentials/v2 https://eduwallet.nl/context/academic/v1 VerifiableCredential AcademicBaseCredential"

// newTestHandler builds the real VCDM handler over an in-memory store. FindCandidates
// needs no key binder or revocation checker, so both are nil.
func newTestHandler(t *testing.T) (*Handler, db.VcdmStore) {
	t.Helper()
	ts := sdjwt_dcqltest.NewTestStorage(t)
	store := db.NewVcdmStore(ts.Db())
	h := NewVcdmDcqlHandler(ts, store, nil, clientmodels.NewCurrentLocale("en"), nil)
	return h, store
}

// newTestHandlerWithKeyBinder builds the real VCDM handler with an in-memory key
// binder, for disclosures that sign a Verifiable Presentation.
func newTestHandlerWithKeyBinder(t *testing.T) (*Handler, db.VcdmStore, sdjwt.KeyBinder) {
	t.Helper()
	ts := sdjwt_dcqltest.NewTestStorage(t)
	store := db.NewVcdmStore(ts.Db())
	keyBinder := sdjwt.NewDefaultKeyBinderWithInMemoryStorage()
	h := NewVcdmDcqlHandler(ts, store, keyBinder, clientmodels.NewCurrentLocale("en"), nil)
	return h, store, keyBinder
}

// issueHolderBoundAcademicCredential issues the academic test credential bound
// to a fresh holder key of keyBinder, and returns it with that key.
func issueHolderBoundAcademicCredential(t *testing.T, keyBinder sdjwt.KeyBinder) (string, jwk.Key) {
	t.Helper()
	holderKeys, err := keyBinder.CreateKeyPairs(1)
	require.NoError(t, err)
	cnf, err := sdjwt.HolderKeyClaim(holderKeys[0])
	require.NoError(t, err)

	claims := vcdmsdjwt.AcademicBaseCredentialClaims(t)
	claims[len(claims)-1] = cnf
	return string(vcdmsdjwt.IssueTestSdJwtVcdm(t, claims)), holderKeys[0]
}

func newTestBatch(hash, credType string, payload map[string]any) *models.VcdmBatch {
	return sdjwt_dcqltest.NewTestVcdmBatch(hash, credType, payload)
}

func parseDcqlQuery(t *testing.T, raw string) dcql.CredentialQuery {
	return sdjwt_dcqltest.ParseDcqlQuery(t, raw)
}

func hasClaimPath(attrs []clientmodels.Attribute, path []any) bool {
	return sdjwt_dcqltest.HasClaimPath(attrs, path)
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
	ts := sdjwt_dcqltest.NewTestStorage(t)
	h := NewVcdmDcqlHandler(ts, db.NewVcdmStore(ts.Db()), nil, clientmodels.NewCurrentLocale("en"), nil)

	// A dc+sd-jwt (SD-JWT VC) batch lives in the SD-JWT VC table and must not be
	// served for a vc+sd-jwt query.
	batch := sdjwt_dcqltest.NewTestBatch("hash-sdjwtvc", "https://example.com/EmailCredential", map[string]any{
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

// Verifier authorization reads vct_values and not type_values, so both must
// hold when a query sets both. Otherwise a verifier authorized for one type
// could name it as a decoy and receive whatever its type_values match.
func TestVcdmFindCandidates_TypeValuesAndVctValuesBothApply(t *testing.T) {
	h, store := newTestHandler(t)

	typeIdentity := "https://www.w3.org/ns/credentials/v2 VerifiableCredential ExampleCredential"
	batch := newTestBatch("hash-vcdm-both", typeIdentity, map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential", "ExampleCredential"},
		"credentialSubject": map[string]any{"given_name": "Alice"},
	})
	require.NoError(t, store.StoreBatch(batch))

	cases := []struct {
		name      string
		vctValues string
		wantMatch bool
	}{
		{"vct_values names another type", `["https://example.com/authorized-decoy"]`, false},
		{"vct_values names this type", `["` + typeIdentity + `"]`, true},
	}
	for _, c := range cases {
		res, err := h.FindCandidates(parseDcqlQuery(t, `{
			"id": "q1", "format": "vc+sd-jwt",
			"meta": {"type_values": [["ExampleCredential"]], "vct_values": `+c.vctValues+`},
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

// academicPayload is the processed payload of the academic test credential,
// for the stored batch.
func academicPayload(t *testing.T) map[string]any {
	t.Helper()
	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(vcdmsdjwt.AcademicBaseCredentialJSON), &payload))
	return payload
}

func givenNameSelection(hash string) []dcql.DisclosureSelection {
	return []dcql.DisclosureSelection{{
		QueryId:              "q1",
		CredentialHash:       hash,
		ClaimPaths:           [][]any{{"credentialSubject", "given_name"}},
		RequireHolderBinding: true,
	}}
}

func TestVcdmPrepareDisclosure_RoundTrip(t *testing.T) {
	h, store, keyBinder := newTestHandlerWithKeyBinder(t)

	batch := newTestBatch("hash-vcdm-present", academicVcdmType, academicPayload(t))
	raw, holderKey := issueHolderBoundAcademicCredential(t, keyBinder)
	batch.Instances[0].RawCredential = []byte(raw)
	require.NoError(t, store.StoreBatch(batch))

	result, err := h.PrepareDisclosure(givenNameSelection("hash-vcdm-present"), "nonce-1", "verifier-1")
	require.NoError(t, err)
	require.Len(t, result.QueryResponses, 1)
	require.Len(t, result.QueryResponses[0].Credentials, 1)

	presentation := result.QueryResponses[0].Credentials[0]
	require.NotEmpty(t, presentation)

	// The credential goes out enveloped in a Verifiable Presentation signed with
	// the holder key from its cnf, over the verifier's nonce and audience.
	_, err = jws.Verify([]byte(presentation), jws.WithKey(jwa.ES256(), holderKey))
	require.NoError(t, err, "presentation must verify with the holder key from cnf")

	header, vp, err := sdjwt.DecodeJwtWithoutCheckingSignature(presentation)
	require.NoError(t, err)
	assert.Equal(t, vcdmsdjwt.PresentationTyp, header["typ"])
	assert.Equal(t, "verifier-1", vp["aud"])
	assert.Equal(t, "nonce-1", vp["nonce"])
	enveloped := envelopedSdJwt(t, vp)

	// The enveloped SD-JWT discloses exactly the selected credentialSubject
	// claim: given_name resolves, the other selectively-disclosable subject
	// claims stay hidden, and the envelope is untouched.
	view, err := sdjwt.PostDisclosureView(enveloped, [][]any{{"credentialSubject", "given_name"}})
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

func TestVcdmPrepareDisclosure_WithoutHolderBindingSendsTheSdJwt(t *testing.T) {
	h, store, keyBinder := newTestHandlerWithKeyBinder(t)

	batch := newTestBatch("hash-vcdm-unbound", academicVcdmType, academicPayload(t))
	raw, _ := issueHolderBoundAcademicCredential(t, keyBinder)
	batch.Instances[0].RawCredential = []byte(raw)
	require.NoError(t, store.StoreBatch(batch))

	selections := givenNameSelection("hash-vcdm-unbound")
	selections[0].RequireHolderBinding = false

	result, err := h.PrepareDisclosure(selections, "nonce-1", "verifier-1")
	require.NoError(t, err)
	require.Len(t, result.QueryResponses, 1)
	require.Len(t, result.QueryResponses[0].Credentials, 1)

	// The credential goes out as an SD-JWT, with no presentation around it and
	// no KB-JWT: it ends in the ~ that closes the last disclosure.
	presentation := result.QueryResponses[0].Credentials[0]
	require.True(t, strings.HasSuffix(presentation, "~"), "an SD-JWT without KB-JWT ends in ~")

	view, err := sdjwt.PostDisclosureView(sdjwt.SdJwt(presentation), [][]any{{"credentialSubject", "given_name"}})
	require.NoError(t, err)
	subject, ok := view["credentialSubject"].(map[string]any)
	require.True(t, ok, "credentialSubject should be present in the disclosed view")
	assert.Equal(t, "Alice", subject["given_name"], "the selected claim should be disclosed")
	assert.NotContains(t, subject, "family_name", "unselected selectively-disclosable claims must stay hidden")
}

func TestVcdmPrepareDisclosure_BatchOfTwo_MarksInstanceUsed(t *testing.T) {
	h, store, keyBinder := newTestHandlerWithKeyBinder(t)

	batch := newTestBatch("hash-vcdm-batch2", academicVcdmType, academicPayload(t))
	batch.BatchSize = 2
	batch.RemainingCount = 2
	rawA, keyA := issueHolderBoundAcademicCredential(t, keyBinder)
	rawB, keyB := issueHolderBoundAcademicCredential(t, keyBinder)
	batch.Instances = []models.VcdmBatchInstance{
		{RawCredential: []byte(rawA)},
		{RawCredential: []byte(rawB)},
	}
	require.NoError(t, store.StoreBatch(batch))

	// Each disclosure sends an unused instance, signed with that instance's
	// own holder key, and uses it up.
	sentWith := map[string]bool{}
	for i, wantRemaining := range []uint{1, 0} {
		result, err := h.PrepareDisclosure(givenNameSelection("hash-vcdm-batch2"), "nonce", "verifier")
		require.NoError(t, err, "disclosure %d", i+1)
		presentation := []byte(result.QueryResponses[0].Credentials[0])
		for name, key := range map[string]jwk.Key{"a": keyA, "b": keyB} {
			if _, err := jws.Verify(presentation, jws.WithKey(jwa.ES256(), key)); err == nil {
				sentWith[name] = true
			}
		}

		reloaded, err := store.GetBatchByHashAndFormat("hash-vcdm-batch2", models.CredentialFormatSdJwtVcdm)
		require.NoError(t, err)
		assert.Equal(t, wantRemaining, reloaded.RemainingCount, "after disclosure %d", i+1)
	}
	assert.Equal(t, map[string]bool{"a": true, "b": true}, sentWith, "each instance should be sent once")

	_, err := h.PrepareDisclosure(givenNameSelection("hash-vcdm-batch2"), "nonce", "verifier")
	require.Error(t, err, "a batch of two with both instances used should fail")
}

// ========================================================================
// FindCandidates: validity window
// ========================================================================

func TestVcdmFindCandidates_ValidityWindow(t *testing.T) {
	cases := []struct {
		name      string
		expiresAt time.Time
		notBefore time.Time
		wantMatch bool
	}{
		{"expired", time.Now().Add(-time.Hour), time.Now().Add(-48 * time.Hour), false},
		{"not yet valid", time.Now().Add(48 * time.Hour), time.Now().Add(time.Hour), false},
		{"valid", time.Now().Add(24 * time.Hour), time.Now().Add(-24 * time.Hour), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, store := newTestHandler(t)

			typeIdentity := "https://www.w3.org/ns/credentials/v2 VerifiableCredential ExampleCredential"
			batch := newTestBatch("hash-vcdm-validity", typeIdentity, map[string]any{
				"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
				"type":              []any{"VerifiableCredential", "ExampleCredential"},
				"credentialSubject": map[string]any{"given_name": "Alice"},
			})
			batch.ExpiresAt = datatypes.NullTime{V: c.expiresAt, Valid: true}
			batch.NotBefore = datatypes.NullTime{V: c.notBefore, Valid: true}
			require.NoError(t, store.StoreBatch(batch))

			result, err := h.FindCandidates(parseDcqlQuery(t, `{
				"id": "q1",
				"format": "vc+sd-jwt",
				"meta": {"vct_values": ["`+typeIdentity+`"]},
				"claims": [{"path": ["credentialSubject", "given_name"]}]
			}`))
			require.NoError(t, err)
			if c.wantMatch {
				require.Len(t, result.OwnedCandidates, 1)
			} else {
				assert.Empty(t, result.OwnedCandidates)
			}
		})
	}
}

// envelopedSdJwt returns the SD-JWT from the single EnvelopedVerifiableCredential
// in a Verifiable Presentation payload.
func envelopedSdJwt(t *testing.T, vp map[string]any) sdjwt.SdJwt {
	t.Helper()
	creds, ok := vp["verifiableCredential"].([]any)
	require.True(t, ok, "verifiableCredential should be an array")
	require.Len(t, creds, 1)
	cred, ok := creds[0].(map[string]any)
	require.True(t, ok, "enveloped credential should be an object")
	assert.Equal(t, "EnvelopedVerifiableCredential", cred["type"])
	id, ok := cred["id"].(string)
	require.True(t, ok, "enveloped credential id should be a string")
	require.True(t, strings.HasPrefix(id, vcdmsdjwt.EnvelopedCredentialDataUrlPrefix), "id should be a vc+sd-jwt data URL, got %q", id)
	return sdjwt.SdJwt(strings.TrimPrefix(id, vcdmsdjwt.EnvelopedCredentialDataUrlPrefix))
}
