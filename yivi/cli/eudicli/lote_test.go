package eudicli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// The committed example under testdata/lote-source is both the worked example an
// operator copies and the fixture these tests read, so the example cannot rot
// into something `build` would reject.
func exampleSource(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", "lote-source")
}

var issuedAt = time.Date(2026, 8, 12, 9, 0, 0, 0, time.UTC)

// entityNamed finds a built entity by its English name, so renaming a curation
// file — which changes the order — does not point an assertion at the wrong
// party.
func entityNamed(t *testing.T, list lote.List, name string) lote.Entity {
	t.Helper()
	for _, entity := range list.Entities {
		if entity.Information.Name.Translated()["en"] == name {
			return entity
		}
	}
	t.Fatalf("no entity named %q in the built list", name)
	return lote.Entity{}
}

func TestBuild_TheCommittedExampleIsConformant(t *testing.T) {
	list, _, err := loadSource(exampleSource(t), issuedAt, sequenceFromScheme)
	require.NoError(t, err)

	scheme := list.SchemeInformation
	require.Equal(t, "NL:Yivi Recognized Parties", scheme.SchemeName["en"])
	require.Equal(t, uint64(1), scheme.SequenceNumber)
	require.Equal(t, lote.LoTEVersion, scheme.LoTEVersionIdentifier)
	require.Equal(t, lote.LoTETypeRecognizedParties, scheme.LoTEType)
	require.Equal(t, "NL", scheme.SchemeTerritory)
	require.Equal(t, issuedAt, scheme.ListIssueDateTime)
	require.Equal(t, issuedAt.AddDate(0, 0, 30), scheme.NextUpdate)

	// The scheme URIs default to Yivi's without the curation file naming them.
	require.Equal(t, lote.StatusDeterminationApproachYivi, scheme.StatusDeterminationApproach)
	require.Equal(t, lote.SchemeTypeCommunityRulesYivi, string(scheme.SchemeTypeCommunityRules["en"]))

	// Entity order follows filename order, so a rebuild of unchanged input is
	// byte-identical, which the wallet's change detection relies on.
	require.Len(t, list.Entities, 2)
	require.Equal(t, "Example Issuing Ltd", list.Entities[0].Information.Name.Translated()["en"])
	require.Equal(t, "Example Municipality", list.Entities[1].Information.Name.Translated()["en"])
}

// A service keyed on a certificate's key gets that key read out of the named
// certificate, so an entry cannot be keyed on a value the lookup would miss.
func TestBuild_ReadsTheSubjectKeyIdentifierOutOfTheCertificate(t *testing.T) {
	list, _, err := loadSource(exampleSource(t), issuedAt, sequenceFromScheme)
	require.NoError(t, err)

	expected, err := readCertificate(
		filepath.Join(exampleSource(t), entitiesDirName, "example-municipality"), "example-verifier.crt")
	require.NoError(t, err)
	require.NotEmpty(t, expected.SubjectKeyId)

	municipality := entityNamed(t, list, "Example Municipality")
	identity := municipality.Services[0].Information.DigitalIdentity
	require.Equal(t, [][]byte{expected.SubjectKeyId}, identity.X509SKIs)
}

// The curation role becomes the service type URI, and no status is emitted at
// all: on a list carrying none, being listed is the grant.
func TestBuild_MapsRolesOntoURIsAndEmitsNoStatus(t *testing.T) {
	list, _, err := loadSource(exampleSource(t), issuedAt, sequenceFromScheme)
	require.NoError(t, err)

	for _, entity := range list.Entities {
		for _, service := range entity.Services {
			require.Empty(t, service.Information.Status,
				"a published Yivi list carries no ServiceStatus")
			require.True(t, service.Information.IsGranted(),
				"and every service on it is therefore granted")
		}
	}

	services := entityNamed(t, list, "Example Issuing Ltd").Services
	require.Len(t, services, 1, "the withdrawn service is absent, not marked")
	require.Equal(t, lote.ServiceTypeIssuer, services[0].Information.Type)

	require.Equal(t, lote.ServiceTypeVerifier,
		entityNamed(t, list, "Example Municipality").Services[0].Information.Type)
}

// A withdrawal is an absence in the output, so it has to be reported — otherwise
// off-boarding a party looks identical to never having listed them.
func TestBuild_ReportsWithdrawnServicesAsExclusions(t *testing.T) {
	_, stats, err := loadSource(exampleSource(t), issuedAt, sequenceFromScheme)
	require.NoError(t, err)
	require.Equal(t, 1, stats.WithdrawnServices)
	require.Empty(t, stats.DroppedEntities)
}

// An entity whose every service is withdrawn leaves the document entirely: Annex
// A requires at least one service per entity.
func TestBuild_DropsAnEntityWhoseEveryServiceIsWithdrawn(t *testing.T) {
	dir := withSource(t, func(_, entity map[string]any) {
		services := entity["services"].([]any)
		services[0].(map[string]any)["status"] = "withdrawn"
	})

	list, stats, err := loadSource(dir, issuedAt, sequenceFromScheme)
	require.NoError(t, err)
	require.Empty(t, list.Entities)
	require.Equal(t, 1, stats.WithdrawnServices)
	require.Len(t, stats.DroppedEntities, 1)
}

// ServiceName is mandatory in Annex A, and it overrides the entity name for
// display, so a service that does not name itself inherits it.
func TestBuild_UnnamedServiceInheritsTheEntityName(t *testing.T) {
	list, _, err := loadSource(exampleSource(t), issuedAt, sequenceFromScheme)
	require.NoError(t, err)

	require.Equal(t, "Example Municipality",
		entityNamed(t, list, "Example Municipality").Services[0].Information.Name.Translated()["en"])
	require.Equal(t, "Example Diplomas",
		entityNamed(t, list, "Example Issuing Ltd").Services[0].Information.Name.Translated()["en"],
		"a service that names itself keeps its own name")
}

func TestBuild_IsDeterministic(t *testing.T) {
	first, _, err := loadSource(exampleSource(t), issuedAt, sequenceFromScheme)
	require.NoError(t, err)
	second, _, err := loadSource(exampleSource(t), issuedAt, sequenceFromScheme)
	require.NoError(t, err)

	firstRaw, err := json.Marshal(lote.Document{LoTE: first})
	require.NoError(t, err)
	secondRaw, err := json.Marshal(lote.Document{LoTE: second})
	require.NoError(t, err)
	require.Equal(t, string(firstRaw), string(secondRaw))
}

// ----------------------------------------------------------------------------
// Validation
// ----------------------------------------------------------------------------

// withSource copies the example and edits it, so a negative test can break one
// thing without a fixture per failure.
func withSource(t *testing.T, edit func(scheme map[string]any, entity map[string]any)) string {
	t.Helper()
	const slug = "example-municipality"

	dir := t.TempDir()
	entityDir := filepath.Join(dir, entitiesDirName, slug)
	require.NoError(t, os.MkdirAll(entityDir, 0o755))

	sourceEntityDir := filepath.Join(exampleSource(t), entitiesDirName, slug)
	scheme := readJSON(t, filepath.Join(exampleSource(t), schemeFileName))
	entity := readJSON(t, filepath.Join(sourceEntityDir, entityFileName))
	edit(scheme, entity)

	writeJSON(t, filepath.Join(dir, schemeFileName), scheme)
	writeJSON(t, filepath.Join(entityDir, entityFileName), entity)

	// The certificate lives beside the entity that names it.
	certificate, err := os.ReadFile(filepath.Join(sourceEntityDir, "example-verifier.crt"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(entityDir, "example-verifier.crt"), certificate, 0o644))
	return dir
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var into map[string]any
	require.NoError(t, json.Unmarshal(raw, &into))
	return into
}

func writeJSON(t *testing.T, path string, value map[string]any) {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o644))
}

func requireBuildFails(t *testing.T, dir, contains string) {
	t.Helper()
	_, _, err := loadSource(dir, issuedAt, sequenceFromScheme)
	require.Error(t, err)
	require.ErrorContains(t, err, contains)
}

// Clause 6.3.6 prescribes `CC:name`, which the wallet does not police.
func TestBuild_RejectsASchemeNameNotPrefixedWithTheTerritory(t *testing.T) {
	dir := withSource(t, func(scheme, _ map[string]any) {
		scheme["scheme_name"] = map[string]any{"en": "Yivi Recognized Parties"}
	})
	requireBuildFails(t, dir, "clause 6.3.6")
}

func TestBuild_RejectsAMissingEnglishSchemeName(t *testing.T) {
	dir := withSource(t, func(scheme, _ map[string]any) {
		scheme["scheme_name"] = map[string]any{"nl": "NL:Yivi Erkende Partijen"}
	})
	requireBuildFails(t, dir, "scheme_name")
}

// The binding's oneOf allows policies or legal notices, never a mixture.
func TestBuild_RejectsBothAPolicyAndALegalNotice(t *testing.T) {
	dir := withSource(t, func(scheme, _ map[string]any) {
		scheme["legal_notice"] = "All rights reserved."
	})
	requireBuildFails(t, dir, "mutually exclusive")
}

func TestBuild_RejectsNeitherAPolicyNorALegalNotice(t *testing.T) {
	dir := withSource(t, func(scheme, _ map[string]any) {
		delete(scheme, "policy_uri")
	})
	requireBuildFails(t, dir, "policy_uri or legal_notice")
}

// Clause 6.3.2 defines the sequence number relative to the list already in force,
// which scheme.json cannot see — so the publisher's number wins wherever it has one.
func TestBuild_ThePublishersSequenceNumberOverridesTheCuratedOne(t *testing.T) {
	list, _, err := loadSource(exampleSource(t), issuedAt, 47)
	require.NoError(t, err)
	require.EqualValues(t, 47, list.SchemeInformation.SequenceNumber,
		"--sequence-number must win over scheme.json")
}

// Curated is still honoured, so a manual or development build needs no flag.
func TestBuild_FallsBackToTheCuratedSequenceNumber(t *testing.T) {
	list, _, err := loadSource(exampleSource(t), issuedAt, sequenceFromScheme)
	require.NoError(t, err)
	require.EqualValues(t, 1, list.SchemeInformation.SequenceNumber)
}

// Neither source supplying one is an error rather than a default: a list that
// silently numbered itself 1 would be refused by every wallet already holding one.
func TestBuild_RejectsASequenceNumberFromNeitherSource(t *testing.T) {
	dir := withSource(t, func(scheme, _ map[string]any) {
		delete(scheme, "sequence_number")
	})
	requireBuildFails(t, dir, "sequence_number")
}

// TEAddress is mandatory in both halves and unread by the wallet, so a missing
// one would otherwise only surface as a schema failure much later.
func TestBuild_RejectsAnEntityWithoutAnElectronicAddress(t *testing.T) {
	dir := withSource(t, func(_, entity map[string]any) {
		address := entity["address"].(map[string]any)
		delete(address, "electronic")
	})
	requireBuildFails(t, dir, "address.electronic")
}

func TestBuild_RejectsAnEntityWithoutAnInformationURI(t *testing.T) {
	dir := withSource(t, func(_, entity map[string]any) {
		delete(entity, "information_uri")
	})
	requireBuildFails(t, dir, "information_uri")
}

func TestBuild_RejectsAnUnknownRole(t *testing.T) {
	dir := withSource(t, func(_, entity map[string]any) {
		services := entity["services"].([]any)
		services[0].(map[string]any)["role"] = "auditor"
	})
	requireBuildFails(t, dir, "unknown role")
}

func TestBuild_RejectsAnUnknownStatus(t *testing.T) {
	dir := withSource(t, func(_, entity map[string]any) {
		services := entity["services"].([]any)
		services[0].(map[string]any)["status"] = "suspended"
	})
	requireBuildFails(t, dir, "unknown status")
}

// A service naming no identity can never match a party: a silent non-grant.
func TestBuild_RejectsAServiceWithNoIdentity(t *testing.T) {
	dir := withSource(t, func(_, entity map[string]any) {
		services := entity["services"].([]any)
		services[0].(map[string]any)["identity"] = map[string]any{}
	})
	requireBuildFails(t, dir, "identity names nothing")
}

// Two entries granting the same party in the same role is not a merge: the wallet
// takes the first granting entry, so the second is dead weight or a contradiction.
func TestBuild_RejectsADuplicateIdentityAcrossEntities(t *testing.T) {
	dir := withSource(t, func(_, entity map[string]any) {
		services := entity["services"].([]any)
		services[0].(map[string]any)["identity"] = map[string]any{
			"dids": []any{"did:web:duplicate.example", "did:web:duplicate.example"},
		}
	})
	requireBuildFails(t, dir, "already granted")
}

// A hand-written curation file with a misspelled key would otherwise drop a grant
// silently.
func TestBuild_RejectsUnknownFields(t *testing.T) {
	dir := withSource(t, func(_, entity map[string]any) {
		entity["organisation_identifier"] = "VATNL-000000001" // British spelling
	})
	requireBuildFails(t, dir, "organisation_identifier")
}

func TestBuild_RejectsACertificatePathEscapingTheEntityDirectory(t *testing.T) {
	dir := withSource(t, func(_, entity map[string]any) {
		services := entity["services"].([]any)
		services[0].(map[string]any)["identity"] = map[string]any{
			"certificate_skis": []any{"../../../etc/passwd"},
		}
	})
	requireBuildFails(t, dir, "bare filename")
}

// ----------------------------------------------------------------------------
// Signing
// ----------------------------------------------------------------------------

// testSigner is a root plus a signing certificate under it, with a caller-chosen
// subject so the clause 6.8.0 checks can be exercised both ways.
type testSigner struct {
	key    *ecdsa.PrivateKey
	leaf   *x509.Certificate
	root   *x509.Certificate
	anchor eudi_jwt.X509VerificationContext
}

func newTestSigner(t *testing.T, country, organization string) *testSigner {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDer, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDer)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "test signer",
			Country:      []string{country},
			Organization: []string{organization},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	leafDer, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, leafKey.Public(), rootKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDer)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &testSigner{
		key:  leafKey,
		leaf: leaf,
		root: root,
		anchor: &eudi_jwt.StaticVerificationContext{VerifyOpts: x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}},
	}
}

// A release gate diffs what `build` just produced against what `show --json` reads
// back from the published list, so any difference between the two renderers would
// show up as a spurious change on every publish. They share documentJSON to make
// that structural; this pins it.
func TestShowJson_RendersWhatBuildWrote(t *testing.T) {
	list, _, err := loadSource(exampleSource(t), issuedAt, 12)
	require.NoError(t, err)

	built, err := documentJSON(list)
	require.NoError(t, err)

	signer := newTestSigner(t, "NL", "Yivi Example")
	signed, err := lote.Sign(lote.Document{LoTE: list}, []*x509.Certificate{signer.leaf}, signer.key, time.Now())
	require.NoError(t, err)

	// The path `show --json` takes: verify first, then render what came back.
	recovered, err := lote.VerifySigned(signed, signer.anchor)
	require.NoError(t, err)
	shown, err := documentJSON(*recovered)
	require.NoError(t, err)

	require.Equal(t, string(built), string(shown),
		"a signed list read back must render byte-identically to the document that was built")
}

// The whole loop: a curated directory becomes a signed document the wallet's own
// verifier accepts and its own snapshot grants from.
func TestSign_ACuratedDirectoryGrantsThroughTheWalletsOwnChecker(t *testing.T) {
	list, _, err := loadSource(exampleSource(t), issuedAt, sequenceFromScheme)
	require.NoError(t, err)

	signer := newTestSigner(t, "NL", "Yivi Example")

	signed, err := lote.Sign(lote.Document{LoTE: list}, []*x509.Certificate{signer.leaf}, signer.key, time.Now())
	require.NoError(t, err)

	verified, err := lote.VerifySigned(signed, signer.anchor)
	require.NoError(t, err, "a document this tool signs must verify the way the wallet verifies")
	require.Equal(t, "NL:Yivi Recognized Parties", verified.SchemeInformation.SchemeName["en"])

	// And it grants: the DID-keyed issuer is found through the real lookup.
	checker := lote.NewChecker(lote.Config{
		Sources: []lote.Source{{
			Key:      "NL:Yivi Recognized Parties",
			LoTEType: lote.LoTETypeRecognizedParties,
			URL:      "http://unused.example",
			Confers:  clientmodels.TrustLevel_High,
		}},
		X509Context: signer.anchor,
		Store:       stubStore{"NL:Yivi Recognized Parties": signed},
		Now:         func() time.Time { return issuedAt.Add(time.Hour) },
	})
	listing := checker.Snapshot().Lookup(trust.RoleIssuer,
		trust.Evidence{Identifiers: []string{"did:web:issuing.example.com"}})
	require.NotNil(t, listing, "the built list must actually grant the party it lists")
	require.Equal(t, "Example Diplomas", listing.Name["en"])

	// The withdrawn service is carried but grants nothing.
	require.Nil(t, checker.Snapshot().Lookup(trust.RoleVerifier,
		trust.Evidence{Identifiers: []string{"did:web:retired.example.com"}}))
}

type stubStore map[string][]byte

func (s stubStore) Get(listId string) ([]byte, bool) {
	raw, ok := s[listId]
	return raw, ok
}

func (s stubStore) Put(listId string, rawJws []byte) error {
	s[listId] = rawJws
	return nil
}

// ----------------------------------------------------------------------------
// keygen
// ----------------------------------------------------------------------------

// runKeygen drives the command the way the CLI does, and returns the directory it
// wrote to. Flags are package-level state, so every one this command reads is set
// on each call.
func runKeygen(t *testing.T, organization string) string {
	t.Helper()
	dir := t.TempDir()
	// The root command assigns this in the real CLI; RunE logs through it.
	Logger = logrus.New()
	Logger.SetOutput(io.Discard)
	require.NoError(t, loteKeygenCmd.Flags().Set("out-dir", dir))
	require.NoError(t, loteKeygenCmd.Flags().Set("country", "NL"))
	require.NoError(t, loteKeygenCmd.Flags().Set("organization", organization))
	require.NoError(t, loteKeygenCmd.Flags().Set("days", "1"))
	loteKeygenCmd.SetOut(io.Discard)
	require.NoError(t, loteKeygenCmd.RunE(loteKeygenCmd, nil))
	return dir
}

// keygen exists so a pull-request check can answer "would this document sign?"
// without the real key. That is only true if the chain it writes clears every gate
// `sign` applies: clause 6.8.0's subject binding, the digitalSignature key usage,
// and the wallet's own verification against the CA generated alongside it.
func TestKeygen_WritesAChainThatSignsTheExampleList(t *testing.T) {
	dir := runKeygen(t, "Yivi Example")

	chain, err := readCertificateChain(filepath.Join(dir, "signer.crt"))
	require.NoError(t, err)
	key, err := readSigningKey(filepath.Join(dir, "signer.key"))
	require.NoError(t, err)

	list, _, err := loadSource(exampleSource(t), issuedAt, 3)
	require.NoError(t, err)

	// lote.Sign is where clause 6.8.0 is enforced, so a subject that did not match
	// the example scheme would fail here rather than at release.
	signed, err := lote.Sign(lote.Document{LoTE: list}, chain, key, time.Now())
	require.NoError(t, err)

	ca, err := readCertificateChain(filepath.Join(dir, "ca.crt"))
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca[0])
	anchor := &eudi_jwt.StaticVerificationContext{VerifyOpts: x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}}

	_, err = lote.VerifySigned(signed, anchor)
	require.NoError(t, err, "the generated chain must verify the way the wallet verifies")
}

// The subject is the whole reason keygen takes flags: a chain whose Organization
// does not match the scheme must fail clause 6.8.0, or the check proves nothing.
func TestKeygen_AMismatchedSubjectStillFailsClause680(t *testing.T) {
	dir := runKeygen(t, "Someone Else")

	chain, err := readCertificateChain(filepath.Join(dir, "signer.crt"))
	require.NoError(t, err)
	key, err := readSigningKey(filepath.Join(dir, "signer.key"))
	require.NoError(t, err)

	list, _, err := loadSource(exampleSource(t), issuedAt, 3)
	require.NoError(t, err)

	_, err = lote.Sign(lote.Document{LoTE: list}, chain, key, time.Now())
	require.Error(t, err, "an Organization outside SchemeOperatorName must not sign")
}
