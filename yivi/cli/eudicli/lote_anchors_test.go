package eudicli

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// The anchor list's curation: the committed example under testdata/lote-source-anchors
// is the worked example an operator copies and the fixture these tests read.

func exampleAnchorSource(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", "lote-source-anchors")
}

var anchorExampleCerts = map[string]string{
	"example-issuing-ca":  "issuing-ca.crt",
	"example-verifier-ca": "verifier-ca.crt",
}

// withAnchorSource copies the anchor example and edits it, so a negative test can
// break one thing without a fixture per failure. The returned directory holds the
// example's certificates under their example names.
func withAnchorSource(t *testing.T, edit func(scheme map[string]any, entities map[string]map[string]any)) string {
	t.Helper()
	src := exampleAnchorSource(t)
	dir := t.TempDir()

	scheme := readJSON(t, filepath.Join(src, schemeFileName))
	entities := map[string]map[string]any{}
	for slug := range anchorExampleCerts {
		entities[slug] = readJSON(t, filepath.Join(src, entitiesDirName, slug, entityFileName))
	}
	edit(scheme, entities)

	writeJSON(t, filepath.Join(dir, schemeFileName), scheme)
	for slug, cert := range anchorExampleCerts {
		entityDir := filepath.Join(dir, entitiesDirName, slug)
		require.NoError(t, os.MkdirAll(entityDir, 0o755))
		writeJSON(t, filepath.Join(entityDir, entityFileName), entities[slug])
		raw, err := os.ReadFile(filepath.Join(src, entitiesDirName, slug, cert))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(entityDir, cert), raw, 0o644))
	}
	return dir
}

func firstService(entity map[string]any) map[string]any {
	return entity["services"].([]any)[0].(map[string]any)
}

func TestBuildAnchors_TheCommittedExampleIsConformant(t *testing.T) {
	list, _, err := loadSource(exampleAnchorSource(t), issuedAt, sequenceFromScheme)
	require.NoError(t, err)

	require.Equal(t, lote.LoTETypeTrustAnchors, list.SchemeInformation.LoTEType, "the type follows what the list delivers")
	require.Equal(t, "NL:Yivi Trust Anchors", list.SchemeInformation.SchemeName["en"])
	require.Equal(t, issuedAt.AddDate(0, 0, 180), list.SchemeInformation.NextUpdate)

	require.Len(t, list.Entities, 2)
	issuing := entityNamed(t, list, "Example Trust Services").Services[0].Information
	require.Equal(t, lote.ServiceTypeIssuerCA, issuing.Type)
	require.True(t, issuing.IsAnchor())
	require.Equal(t, clientmodels.TrustLevel_Medium, issuing.Confers())
	require.Equal(t, []string{"https://trust.example.com/crl/attestation.crl"}, issuing.CRLDistributionPoints())
	require.Len(t, issuing.DigitalIdentity.X509Certificates, 1)
	require.Empty(t, issuing.DigitalIdentity.X509SKIs)

	verifying := entityNamed(t, list, "Example Relying Party CA B.V.").Services[0].Information
	require.Equal(t, lote.ServiceTypeVerifierCA, verifying.Type)
	require.Equal(t, clientmodels.TrustLevel_Medium, verifying.Confers(), "an entry saying nothing confers medium")

	// The document `build` writes is a conformant Annex A list, ServiceSupplyPoints
	// and all.
	require.NoError(t, lote.ValidateList(list))
}

func TestBuildAnchors_RejectsAPartyRoleOnAnAnchorScheme(t *testing.T) {
	dir := withAnchorSource(t, func(_ map[string]any, entities map[string]map[string]any) {
		firstService(entities["example-issuing-ca"])["role"] = "issuer"
	})
	requireBuildFails(t, dir, "this scheme delivers anchors")
}

func TestBuild_RejectsACaRoleOnAPartyScheme(t *testing.T) {
	dir := withSource(t, func(_, entity map[string]any) {
		firstService(entity)["role"] = "verifier-ca"
	})
	requireBuildFails(t, dir, "this scheme delivers parties")
}

func TestBuild_RejectsCaFieldsOnAPartyRole(t *testing.T) {
	dir := withSource(t, func(_, entity map[string]any) {
		firstService(entity)["confers"] = "high"
	})
	requireBuildFails(t, dir, "CA roles only")
}

func TestBuildAnchors_RejectsAKeyReferenceOnACaRole(t *testing.T) {
	dir := withAnchorSource(t, func(_ map[string]any, entities map[string]map[string]any) {
		firstService(entities["example-issuing-ca"])["identity"] = map[string]any{"certificate_skis": []any{"issuing-ca.crt"}}
	})
	requireBuildFails(t, dir, "certificate_skis and dids are not allowed")
}

func TestBuildAnchors_RejectsACertificateThatIsNotACa(t *testing.T) {
	dir := withAnchorSource(t, func(map[string]any, map[string]map[string]any) {})
	// The party example's verifier leaf, where the CA should be.
	leaf, err := os.ReadFile(filepath.Join(exampleSource(t), entitiesDirName, "example-municipality", "example-verifier.crt"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, entitiesDirName, "example-issuing-ca", "issuing-ca.crt"), leaf, 0o644))
	requireBuildFails(t, dir, "not a CA certificate")
}

func TestBuildAnchors_RejectsConfersAboveTheCeiling(t *testing.T) {
	dir := withAnchorSource(t, func(scheme map[string]any, entities map[string]map[string]any) {
		scheme["confers_ceiling"] = "medium"
		firstService(entities["example-issuing-ca"])["confers"] = "high"
		firstService(entities["example-issuing-ca"])["markings"] = []any{"contracted"}
	})
	requireBuildFails(t, dir, "exceeds this scheme's confers_ceiling")
}

// Promoting a CA the operator does not run to the top rung is the decision review
// exists to see, so it has to be said in so many words.
func TestBuildAnchors_HighOnAForeignCaNeedsTheContractedMarking(t *testing.T) {
	dir := withAnchorSource(t, func(_ map[string]any, entities map[string]map[string]any) {
		firstService(entities["example-issuing-ca"])["confers"] = "high"
	})
	requireBuildFails(t, dir, "contracted")

	marked := withAnchorSource(t, func(_ map[string]any, entities map[string]map[string]any) {
		firstService(entities["example-issuing-ca"])["confers"] = "high"
		firstService(entities["example-issuing-ca"])["markings"] = []any{"contracted"}
	})
	list, _, err := loadSource(marked, issuedAt, sequenceFromScheme)
	require.NoError(t, err)
	require.Equal(t, clientmodels.TrustLevel_High, entityNamed(t, list, "Example Trust Services").Services[0].Information.Confers())
}

func TestBuildAnchors_RejectsAMissingCrlDistributionPoint(t *testing.T) {
	dir := withAnchorSource(t, func(_ map[string]any, entities map[string]map[string]any) {
		delete(firstService(entities["example-issuing-ca"]), "crl_distribution_points")
	})
	requireBuildFails(t, dir, "crl_distribution_points is required")
}

func TestBuildAnchors_RejectsAPlaintextCrlDistributionPoint(t *testing.T) {
	dir := withAnchorSource(t, func(_ map[string]any, entities map[string]map[string]any) {
		firstService(entities["example-issuing-ca"])["crl_distribution_points"] = []any{"http://trust.example.com/crl/attestation.crl"}
	})
	requireBuildFails(t, dir, "https")
}

func TestBuildAnchors_RejectsTheSameCaUnderTwoEntities(t *testing.T) {
	dir := withAnchorSource(t, func(_ map[string]any, entities map[string]map[string]any) {
		firstService(entities["example-verifier-ca"])["role"] = "issuer-ca"
	})
	// Same certificate bytes under a different filename in the other entity.
	same, err := os.ReadFile(filepath.Join(dir, entitiesDirName, "example-issuing-ca", "issuing-ca.crt"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, entitiesDirName, "example-verifier-ca", "verifier-ca.crt"), same, 0o644))
	requireBuildFails(t, dir, "already anchored")
}

func TestBuildAnchors_RejectsACeilingOnAPartyScheme(t *testing.T) {
	dir := withSource(t, func(scheme, _ map[string]any) {
		scheme["confers_ceiling"] = "high"
	})
	requireBuildFails(t, dir, "confers_ceiling is only meaningful")
}

// ----------------------------------------------------------------------------
// pinned
// ----------------------------------------------------------------------------

func TestPinned_ListsTheCompiledInAnchorsAsTheWalletInstallsThem(t *testing.T) {
	anchors, err := pinnedAnchors()
	require.NoError(t, err)

	byKey := map[string]pinnedAnchor{}
	for _, anchor := range anchors {
		byKey[anchor.Environment+"/"+anchor.Pool] = anchor
		require.Len(t, anchor.SHA256, 64)
		require.NotEmpty(t, anchor.SKI, "a CA carries a subject key identifier")
	}
	// The anchor is the CA that issues the leaves, not the shared root.
	require.Contains(t, byKey["production/issuers"].Subject, "Yivi Attestation Providers CA")
	require.Equal(t, clientmodels.TrustLevel_High, byKey["production/issuers"].Confers)
	require.Contains(t, byKey["production/verifiers"].Subject, "Yivi Relying Parties CA")
	require.Contains(t, byKey["staging/issuers"].Subject, "Yivi Staging Attestation Providers CA")
	require.NotContains(t, byKey, "production/trustlists", "empty until the Trust List CA exists")
}

// ----------------------------------------------------------------------------
// verify --signer-ski
// ----------------------------------------------------------------------------

func runVerify(t *testing.T, keyDir, input, signerSKI string) error {
	t.Helper()
	Logger = logrus.New()
	Logger.SetOutput(io.Discard)
	require.NoError(t, loteVerifyCmd.Flags().Set("anchor", filepath.Join(keyDir, "ca.crt")))
	require.NoError(t, loteVerifyCmd.Flags().Set("against", ""))
	require.NoError(t, loteVerifyCmd.Flags().Set("signer-ski", signerSKI))
	loteVerifyCmd.SetOut(io.Discard)
	return loteVerifyCmd.RunE(loteVerifyCmd, []string{input})
}

func TestVerifyCommand_PinsTheSigner(t *testing.T) {
	keyDir := runKeygen(t, "Yivi Example")
	input := writeBuiltDocument(t, nil)
	output := filepath.Join(t.TempDir(), "list.jws")
	require.NoError(t, runSign(t, keyDir, input, output))

	chain, err := readCertificateChain(filepath.Join(keyDir, "signer.crt"))
	require.NoError(t, err)
	require.NotEmpty(t, chain[0].SubjectKeyId, "keygen writes a certificate a source can pin")
	ski := hex.EncodeToString(chain[0].SubjectKeyId)

	require.NoError(t, runVerify(t, keyDir, output, ski))
	require.NoError(t, runVerify(t, keyDir, output, ""), "no pin checks nothing beyond the chain")
	require.ErrorContains(t, runVerify(t, keyDir, output, "00"+ski[2:]), "subject key identifier",
		"a certificate under the right CA is not enough")
	require.ErrorContains(t, runVerify(t, keyDir, output, "not hex"), "--signer-ski")
	_ = time.Now
}
