package eudicli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
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

// entityNamed finds a built entity by its English name. Tests look entities up
// rather than indexing them, so renaming a curation file — which changes the
// order, since files are read in filename order — does not silently point an
// assertion at the wrong party.
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
	list, err := loadSource(exampleSource(t), issuedAt)
	require.NoError(t, err)

	scheme := list.SchemeInformation
	require.Equal(t, "NL:Yivi Recognized Parties", scheme.Identity())
	require.Equal(t, uint64(1), scheme.SequenceNumber)
	require.Equal(t, lote.LoTEVersion, scheme.LoTEVersionIdentifier)
	require.Equal(t, lote.LoTETypeRecognizedParties, scheme.LoTEType)
	require.Equal(t, "NL", scheme.SchemeTerritory)
	require.Equal(t, issuedAt, scheme.ListIssueDateTime)
	require.Equal(t, issuedAt.AddDate(0, 0, 30), scheme.NextUpdate)

	// The scheme URIs default to Yivi's without the curation file naming them:
	// there is one place they are decided, and it is not a per-scheme JSON file.
	require.Equal(t, lote.StatusDeterminationApproachYivi, scheme.StatusDeterminationApproach)
	require.Equal(t, lote.SchemeTypeCommunityRulesYivi, string(scheme.SchemeTypeCommunityRules["en"]))

	// Entity order follows filename order, so a rebuild of unchanged input is
	// byte-identical — which is what the wallet's change detection relies on.
	require.Len(t, list.Entities, 2)
	require.Equal(t, "Example Issuing Ltd", list.Entities[0].Information.Name.Translated()["en"])
	require.Equal(t, "Example Municipality", list.Entities[1].Information.Name.Translated()["en"])
}

// A service keyed on a certificate's key gets that key read out of the named
// certificate, rather than the curator transcribing base64 — so an entry cannot
// be keyed on a value the wallet's lookup would never match.
func TestBuild_ReadsTheSubjectKeyIdentifierOutOfTheCertificate(t *testing.T) {
	list, err := loadSource(exampleSource(t), issuedAt)
	require.NoError(t, err)

	expected, err := readCertificate(exampleSource(t), "example-verifier.crt")
	require.NoError(t, err)
	require.NotEmpty(t, expected.SubjectKeyId)

	municipality := entityNamed(t, list, "Example Municipality")
	identity := municipality.Services[0].Information.DigitalIdentity
	require.Equal(t, [][]byte{expected.SubjectKeyId}, identity.X509SKIs)
}

// The curation word becomes the status URI, and a withdrawn service is carried so
// the withdrawal is visible rather than dropped.
func TestBuild_MapsRolesAndStatusesOntoURIs(t *testing.T) {
	list, err := loadSource(exampleSource(t), issuedAt)
	require.NoError(t, err)

	services := entityNamed(t, list, "Example Issuing Ltd").Services
	require.Len(t, services, 2)
	require.Equal(t, lote.ServiceTypeIssuer, services[0].Information.Type)
	require.Equal(t, lote.ServiceStatusGranted, services[0].Information.Status,
		"an omitted status means granted")
	require.Equal(t, lote.ServiceTypeVerifier, services[1].Information.Type)
	require.Equal(t, lote.ServiceStatusWithdrawn, services[1].Information.Status)
}

// ServiceName is mandatory in Annex A, and a service that does not name itself
// inherits the entity's — which is also what keeps the entity name on screen,
// since a service name overrides it for display.
func TestBuild_UnnamedServiceInheritsTheEntityName(t *testing.T) {
	list, err := loadSource(exampleSource(t), issuedAt)
	require.NoError(t, err)

	require.Equal(t, "Example Municipality",
		entityNamed(t, list, "Example Municipality").Services[0].Information.Name.Translated()["en"])
	require.Equal(t, "Example Diplomas",
		entityNamed(t, list, "Example Issuing Ltd").Services[0].Information.Name.Translated()["en"],
		"a service that names itself keeps its own name")
}

func TestBuild_IsDeterministic(t *testing.T) {
	first, err := loadSource(exampleSource(t), issuedAt)
	require.NoError(t, err)
	second, err := loadSource(exampleSource(t), issuedAt)
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

// withSource copies the example and applies edits to it, so a negative test can
// break one thing without a fixture per failure.
func withSource(t *testing.T, edit func(scheme map[string]any, entity map[string]any)) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, entitiesDirName), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, certsDirName), 0o755))

	scheme := readJSON(t, filepath.Join(exampleSource(t), schemeFileName))
	entity := readJSON(t, filepath.Join(exampleSource(t), entitiesDirName, "example-municipality.json"))
	edit(scheme, entity)

	writeJSON(t, filepath.Join(dir, schemeFileName), scheme)
	writeJSON(t, filepath.Join(dir, entitiesDirName, "example-municipality.json"), entity)

	certificate, err := os.ReadFile(filepath.Join(exampleSource(t), certsDirName, "example-verifier.crt"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, certsDirName, "example-verifier.crt"), certificate, 0o644))
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
	_, err := loadSource(dir, issuedAt)
	require.Error(t, err)
	require.ErrorContains(t, err, contains)
}

// Clause 6.3.6 prescribes `CC:name`. The wallet does not police it, so if build
// does not, nothing does.
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

func TestBuild_RejectsAMissingSequenceNumber(t *testing.T) {
	dir := withSource(t, func(scheme, _ map[string]any) {
		delete(scheme, "sequence_number")
	})
	requireBuildFails(t, dir, "sequence_number")
}

// TEAddress is mandatory in both halves, and unread by the wallet — so a missing
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

// A service naming no identity can never match a party, so it is a silent
// non-grant — exactly the failure mode this tool exists to prevent.
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

func TestBuild_RejectsACertificatePathEscapingTheCertsDirectory(t *testing.T) {
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

// testSigner is a root plus a signing certificate under it, with a subject the
// caller chooses so the clause 6.8.0 checks can be exercised both ways.
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

// The whole loop: a curated directory becomes a signed document that the wallet's
// own verifier accepts and its own snapshot grants from. Everything else in this
// file is a detail of one of these two steps.
func TestSign_ACuratedDirectoryGrantsThroughTheWalletsOwnChecker(t *testing.T) {
	list, err := loadSource(exampleSource(t), issuedAt)
	require.NoError(t, err)

	signer := newTestSigner(t, "NL", "Yivi Example")
	require.NoError(t, checkSigningCertificate(signer.leaf, list.SchemeInformation))

	alg, err := signatureAlgorithm(signer.key)
	require.NoError(t, err)
	signed, err := signDocument(lote.Document{LoTE: list}, []*x509.Certificate{signer.leaf}, signer.key, alg)
	require.NoError(t, err)

	verified, err := lote.VerifySigned(signed, signer.anchor)
	require.NoError(t, err, "a document this tool signs must verify the way the wallet verifies")
	require.Equal(t, "NL:Yivi Recognized Parties", verified.SchemeInformation.Identity())

	// And it grants: the DID-keyed issuer is found through the real lookup.
	checker := lote.NewChecker(lote.Config{
		Sources: []lote.Source{{
			ListId:   "NL:Yivi Recognized Parties",
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

// Clause 6.8.0 binds the certificate to the scheme it signs for. Nothing at
// runtime checks it, so these two are the only enforcement that exists.
func TestSign_RejectsACertificateWhoseOrganizationIsNotTheSchemeOperator(t *testing.T) {
	list, err := loadSource(exampleSource(t), issuedAt)
	require.NoError(t, err)

	signer := newTestSigner(t, "NL", "Someone Else BV")
	err = checkSigningCertificate(signer.leaf, list.SchemeInformation)
	require.ErrorContains(t, err, "clause 6.8.0")
	require.ErrorContains(t, err, "organization")
}

func TestSign_RejectsACertificateWhoseCountryIsNotTheSchemeTerritory(t *testing.T) {
	list, err := loadSource(exampleSource(t), issuedAt)
	require.NoError(t, err)

	signer := newTestSigner(t, "BE", "Yivi Example")
	err = checkSigningCertificate(signer.leaf, list.SchemeInformation)
	require.ErrorContains(t, err, "clause 6.8.0")
	require.ErrorContains(t, err, "country")
}

func TestSign_RejectsACertificateWithoutDigitalSignatureKeyUsage(t *testing.T) {
	list, err := loadSource(exampleSource(t), issuedAt)
	require.NoError(t, err)

	signer := newTestSigner(t, "NL", "Yivi Example")
	// Strip the key usage the wallet checks explicitly.
	signer.leaf.KeyUsage = 0
	require.ErrorContains(t, checkSigningCertificate(signer.leaf, list.SchemeInformation), "digitalSignature")
}

func TestSignatureAlgorithm_FollowsTheCurve(t *testing.T) {
	for _, tc := range []struct {
		curve elliptic.Curve
		alg   string
	}{
		{elliptic.P256(), "ES256"},
		{elliptic.P384(), "ES384"},
		{elliptic.P521(), "ES512"},
	} {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		require.NoError(t, err)
		alg, err := signatureAlgorithm(key)
		require.NoError(t, err)
		require.Equal(t, tc.alg, alg.String())
	}
}
