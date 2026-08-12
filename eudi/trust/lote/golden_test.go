package lote

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/stretchr/testify/require"
)

// A committed, signed LoTE — the one document in the suite that this package did
// not marshal itself.
//
// Every other test builds its list out of the structs in model.go, so a change to
// their JSON tags (renaming `next_update`, dropping `other_ids`, moving
// `markings` onto the entity) passes the entire suite while breaking every list a
// real publisher emits. Those tags are the wire contract with whatever publishes
// Yivi's list, and this is the only test that can notice them changing.
//
// It also documents the format: testdata/lote-publisher/golden/list.json is the
// same list in readable form, and TestGoldenReadableCopyMatchesTheSignedOne
// proves the two agree — so the readable copy cannot drift into a lie. Between
// them they show every shape the wallet understands: both certificate key forms,
// a DID, a withdrawal, service-level name and logo overrides, markings (the
// retired onboarded-by-yivi bytes among them) that must be carried and
// ignored, and multilingual names.
//
// **It must never rot.** verify() deliberately does not check the list's own time
// bounds, so a committed document verifies forever; the currency and lookup
// assertions pin a clock inside the validity window instead of reading the wall
// clock. Only the signing certificate's own notAfter (ten years) bounds this
// test, like the rest of the committed material.
//
// Regenerate with testdata/lote-publisher/mkgolden.sh, which signs through the
// publisher's own code path rather than reimplementing it.

const (
	goldenListId = "urn:yivi:trustlist:golden"

	goldenDid          = "did:web:verifier.example.com"
	goldenWithdrawnDid = "did:web:withdrawn.example.com"
)

func goldenDir(t *testing.T) string {
	t.Helper()
	// eudi/trust/lote → repo root.
	return filepath.Join("..", "..", "..", "testdata", "lote-publisher", "golden")
}

func goldenRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenDir(t), "list.jws"))
	require.NoError(t, err)
	return raw
}

// goldenAnchors is the trust store the golden document's chain validates against,
// with its clock pinned so the certificate's own validity window is checked as of
// a fixed date rather than today.
func goldenAnchors(t *testing.T) eudi_jwt.X509VerificationContext {
	t.Helper()
	rootPem, err := os.ReadFile(filepath.Join(goldenDir(t), "certs", "root.crt"))
	require.NoError(t, err)
	chain, err := utils.ParsePemCertificateChain(rootPem)
	require.NoError(t, err)
	require.NotEmpty(t, chain)

	pool := x509.NewCertPool()
	pool.AddCert(chain[0])
	return &eudi_jwt.StaticVerificationContext{VerifyOpts: x509.VerifyOptions{
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: goldenTime(t),
	}}
}

// goldenTime is the moment every assertion here is evaluated at: the golden
// signing certificate's notBefore plus a day.
//
// Derived rather than hardcoded, and derived from the *certificate* rather than
// the list, because the verification context needs it before the list has been
// parsed. It is inside both validity windows by construction — mkgolden.sh dates
// the list from the same generation moment — and it does not move with the wall
// clock, so this test means the same thing whenever it runs.
func goldenTime(t *testing.T) time.Time {
	t.Helper()
	return goldenSignerCertificate(t).NotBefore.Add(24 * time.Hour)
}

func goldenSignerCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	der, err := os.ReadFile(filepath.Join(goldenDir(t), "certs", "signer.der"))
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func goldenPartyCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	der, err := os.ReadFile(filepath.Join(goldenDir(t), "certs", "party.der"))
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestGoldenDocumentVerifiesAndParses is the regression guard: a document nobody
// re-signed, parsed by whatever model.go currently says a LoTE looks like.
func TestGoldenDocumentVerifiesAndParses(t *testing.T) {
	verified, err := verify(goldenRaw(t), goldenAnchors(t))
	require.NoError(t, err, "the committed document must keep verifying")

	scheme := verified.list.SchemeInformation
	require.Equal(t, goldenListId, scheme.Identity(), "SchemeName's English entry is the list's identity")
	require.Equal(t, uint64(42), scheme.SequenceNumber)

	// The scheme-explicit mandatory fields (Table 1). They are asserted here
	// rather than only validated against the schema because this is the test that
	// notices a JSON tag changing, and a renamed mandatory field is exactly the
	// kind of break that would otherwise pass the whole suite.
	require.Equal(t, LoTEVersion, scheme.LoTEVersionIdentifier)
	require.Equal(t, LoTETypeRecognizedParties, scheme.LoTEType)
	require.Equal(t, "Yivi Golden", scheme.SchemeOperatorName.Translated()["en"])
	require.Equal(t, "NL", scheme.SchemeTerritory)
	require.Equal(t, StatusDeterminationApproachYivi, scheme.StatusDeterminationApproach)
	require.NotEmpty(t, scheme.SchemeInformationURI["en"])
	require.NotEmpty(t, scheme.SchemeTypeCommunityRules["en"])
	require.NotEmpty(t, scheme.SchemeOperatorAddress.PostalAddress)
	require.NotEmpty(t, scheme.SchemeOperatorAddress.ElectronicAddress)
	require.NotEmpty(t, scheme.PolicyOrLegalNotice)
	// The timestamps are generation-relative, so the assertion is on their shape
	// and relationship rather than on literal dates: both must have parsed out of
	// RFC 3339 into real times, thirty days apart.
	require.False(t, scheme.ListIssueDateTime.IsZero(), "list_issue_date_time must parse")
	require.False(t, scheme.NextUpdate.IsZero(), "next_update must parse")
	require.Equal(t, 30*24*time.Hour, scheme.NextUpdate.Sub(scheme.ListIssueDateTime))

	require.True(t, verified.current(goldenTime(t)), "current as of the pinned date")
	require.False(t, verified.current(scheme.NextUpdate.Add(2*ClockSkew)),
		"and not current well past next_update")

	require.Len(t, verified.list.Entities, 4)

	// Every field of the first entity, because these are the names on the wire.
	party := verified.list.Entities[0].Information
	require.Equal(t, "VATNL-000000001", party.OrganizationIdentifier())
	require.Equal(t, clientmodels.TranslatedString{"en": "Example Municipality", "nl": "Example Municipality"},
		party.Name.Translated())
	require.Equal(t, "https://trustlist.example/logos/municipality.png", party.LogoURI())

	// TEAddress and TEInformationURI are mandatory (clause 6.5.0), so a document
	// that omits them is non-conformant even though the wallet never reads them.
	require.NotEmpty(t, party.Address.PostalAddress, "TEAddress requires a postal address")
	require.NotEmpty(t, party.Address.ElectronicAddress, "TEAddress requires an electronic address")
	require.Equal(t, "NL", party.Address.PostalAddress[0].Country)
	require.NotEmpty(t, party.InformationURI["en"])
	require.Len(t, verified.list.Entities[0].Services, 1)

	service := verified.list.Entities[0].Services[0].Information
	require.Equal(t, ServiceTypeVerifier, service.Type)
	role, ok := service.Type.Role()
	require.True(t, ok, "the service type URI must map to a ladder role")
	require.Equal(t, trust.RoleVerifier, role)
	require.Equal(t, ServiceStatusGranted, service.Status)
	require.NotEmpty(t, service.Name, "ServiceName is mandatory (clause 6.6.0)")
	require.Len(t, service.DigitalIdentity.X509Certificates, 1)
	require.Equal(t, goldenPartyCertificate(t).Raw, service.DigitalIdentity.X509Certificates[0].Val,
		"the certificate key form carries the DER in the pkiOb's val")
	require.Contains(t, service.Markings(), "onboarded-by-yivi",
		"markings must survive parsing; the wallet carries them without acting on them")

	// The SKI key form, the service-level overrides, and markings that must
	// survive parsing without being acted on.
	skiService := verified.list.Entities[1].Services[0].Information
	require.Equal(t, [][]byte{goldenPartyCertificate(t).SubjectKeyId}, skiService.DigitalIdentity.X509SKIs)
	require.Equal(t, clientmodels.TranslatedString{"en": "Example Diplomas"}, skiService.Name.Translated())
	require.Equal(t, "https://trustlist.example/logos/diplomas.png", skiService.LogoURI())
	require.Contains(t, skiService.Markings(), "some-future-qualifier")

	// The DID convention — a bare string under Annex A, not a {type,value} pair —
	// and a withdrawal that is listed but grants nothing.
	didService := verified.list.Entities[2].Services[0].Information
	require.Equal(t, []string{goldenDid}, didService.DigitalIdentity.OtherIds)
	require.Equal(t, ServiceStatusWithdrawn, verified.list.Entities[3].Services[0].Information.Status)
}

// TestGoldenReadableCopyMatchesTheSignedOne keeps golden/list.json honest: it is
// there to be read by humans, so it must parse to exactly the list that was
// signed.
func TestGoldenReadableCopyMatchesTheSignedOne(t *testing.T) {
	verified, err := verify(goldenRaw(t), goldenAnchors(t))
	require.NoError(t, err)

	readable, err := os.ReadFile(filepath.Join(goldenDir(t), "list.json"))
	require.NoError(t, err)

	var fromReadable Document
	require.NoError(t, json.Unmarshal(readable, &fromReadable))
	require.Equal(t, *verified.list, fromReadable.LoTE,
		"golden/list.json must be the same list as golden/list.jws; re-run mkgolden.sh")
}

// TestGoldenDocumentGrantsThroughTheChecker runs the committed document through
// the whole channel — store, checker, snapshot, keying — as of the pinned date,
// so the shapes above are not merely parsed but acted on.
func TestGoldenDocumentGrantsThroughTheChecker(t *testing.T) {
	store := memoryStore{}
	require.NoError(t, store.Put(goldenListId, goldenRaw(t)))

	checker := NewChecker(Config{
		Sources: []Source{{
			ListId:   goldenListId,
			LoTEType: LoTETypeRecognizedParties,
			URL:      "http://unused.example",
			Confers:  clientmodels.TrustLevel_High,
		}},
		X509Context: goldenAnchors(t),
		Store:       store,
		Now:         func() time.Time { return goldenTime(t) },
	})
	snapshot := checker.Snapshot()

	certificateParty := trust.Evidence{Certificate: goldenPartyCertificate(t)}
	listing := snapshot.Lookup(trust.RoleVerifier, certificateParty)
	require.NotNil(t, listing, "the certificate-keyed entry must grant")
	require.Equal(t, "Example Municipality", listing.Name["en"])
	require.Equal(t, clientmodels.TrustLevel_High, listing.Level,
		"every granted entry confers what the source does")

	// The same party, in its issuer role, matches the SKI-keyed entry instead —
	// and picks up that service's overriding name.
	asIssuer := snapshot.Lookup(trust.RoleIssuer, certificateParty)
	require.NotNil(t, asIssuer)
	require.Equal(t, "Example Diplomas", asIssuer.Name["en"])
	require.Equal(t, clientmodels.TrustLevel_High, asIssuer.Level,
		"its markings — known bytes or unknown — neither add nor subtract")

	require.NotNil(t, snapshot.Lookup(trust.RoleVerifier, trust.Evidence{Identifiers: []string{goldenDid}}),
		"the DID entry must grant")
	require.Nil(t, snapshot.Lookup(trust.RoleIssuer, trust.Evidence{Identifiers: []string{goldenWithdrawnDid}}),
		"a withdrawn service grants nothing")
}
