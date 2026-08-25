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
// not marshal itself, and so the only test that notices a JSON tag changing. Every
// other test builds its list out of the structs in model.go, so a rename passes
// the whole suite while breaking every list a real publisher emits.
//
// testdata/lote-publisher/golden/list.json is the same list in readable form, kept
// honest by TestGoldenReadableCopyMatchesTheSignedOne. Between them they cover
// every shape the wallet understands: both certificate key forms, a DID, a
// withdrawal, service-level overrides, carried-but-ignored markings, and
// multilingual names.
//
// It must not rot: verify() does not check the list's own time bounds, and the
// assertions pin a clock inside the validity window rather than reading the wall
// clock, so only the signing certificate's notAfter bounds this test.
//
// Regenerate with testdata/lote-publisher/mkgolden.sh.

const (
	// Clause 6.3.6 form: `CC:name`, CC being the SchemeTerritory. The wallet
	// compares the identity verbatim against its source's ListId and never checks
	// the format, so the golden document is what says a conformant one looks like.
	goldenListId = "NL:Yivi Golden Trust List"

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

// goldenAnchors pins its clock, so the certificate's validity window is checked
// as of a fixed date rather than today.
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
// signing certificate's notBefore plus a day. Derived from the certificate rather
// than the list, because the verification context needs it before the list has
// been parsed, and inside both validity windows by construction — mkgolden.sh
// dates the list from the same generation moment.
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

// A document nobody re-signed, parsed by whatever model.go currently says a LoTE
// looks like.
func TestGoldenDocumentVerifiesAndParses(t *testing.T) {
	verified, err := verify(goldenRaw(t), goldenAnchors(t))
	require.NoError(t, err, "the committed document must keep verifying")

	scheme := verified.list.SchemeInformation
	require.Equal(t, goldenListId, scheme.SchemeName["en"], "SchemeName's English entry is the list's identity")
	require.Equal(t, uint64(42), scheme.SequenceNumber)

	// The scheme-explicit mandatory fields (Table 1), asserted rather than merely
	// schema-validated: this is the test that notices a tag changing.
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
	// Generation-relative, so the assertion is on shape and relationship: parsed
	// out of RFC 3339, thirty days apart.
	require.False(t, scheme.ListIssueDateTime.IsZero(), "list_issue_date_time must parse")
	require.False(t, scheme.NextUpdate.IsZero(), "next_update must parse")
	require.Equal(t, 30*24*time.Hour, scheme.NextUpdate.Sub(scheme.ListIssueDateTime))

	require.True(t, verified.current(goldenTime(t)), "current as of the pinned date")
	require.False(t, verified.current(scheme.NextUpdate.Add(2*ClockSkew)),
		"and not current well past next_update")

	require.Len(t, verified.list.Entities, 4)

	party := verified.list.Entities[0].Information
	require.Equal(t, "VATNL-000000001", party.OrganizationIdentifier())
	require.Equal(t, clientmodels.TranslatedString{"en": "Example Municipality", "nl": "Example Municipality"},
		party.Name.Translated())
	require.Equal(t, "https://trustlist.example/logos/municipality.png", party.LogoURI())

	// TEAddress and TEInformationURI are mandatory (clause 6.5.0) even though the
	// wallet never reads them.
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
	// No status at all, which means granted (clause 6.6.0 NOTE 1).
	require.Empty(t, service.Status, "a Yivi list carries no ServiceStatus")
	require.True(t, service.IsGranted(), "and an absent status is a grant")
	require.NotEmpty(t, service.Name, "ServiceName is mandatory (clause 6.6.0)")
	require.Len(t, service.DigitalIdentity.X509Certificates, 1)
	require.Equal(t, goldenPartyCertificate(t).Raw, service.DigitalIdentity.X509Certificates[0].Val,
		"the certificate key form carries the DER in the pkiOb's val")
	require.Contains(t, service.Markings(), "onboarded-by-yivi",
		"markings must survive parsing; the wallet carries them without acting on them")

	// The SKI key form, service-level overrides, and carried-but-unread markings.
	skiService := verified.list.Entities[1].Services[0].Information
	require.Equal(t, [][]byte{goldenPartyCertificate(t).SubjectKeyId}, skiService.DigitalIdentity.X509SKIs)
	require.Equal(t, clientmodels.TranslatedString{"en": "Example Diplomas"}, skiService.Name.Translated())
	require.Equal(t, "https://trustlist.example/logos/diplomas.png", skiService.LogoURI())
	require.Contains(t, skiService.Markings(), "some-future-qualifier")

	// A DID as a bare string under Annex A, and a withdrawal that grants nothing.
	didService := verified.list.Entities[2].Services[0].Information
	require.Equal(t, []string{goldenDid}, didService.DigitalIdentity.OtherIds)

	// The fourth entity carries an explicit withdrawn status, so the document
	// exercises both branches of the absent-means-granted rule.
	withdrawn := verified.list.Entities[3].Services[0].Information
	require.Equal(t, ServiceStatusWithdrawn, withdrawn.Status)
	require.False(t, withdrawn.IsGranted(), "an explicit withdrawal is not a grant")
}

// golden/list.json must parse to exactly the list that was signed.
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

// The committed document through the whole channel — store, checker, snapshot,
// keying — so the shapes above are acted on and not merely parsed.
func TestGoldenDocumentGrantsThroughTheChecker(t *testing.T) {
	store := memoryStore{}
	require.NoError(t, store.Put(goldenListId, goldenRaw(t)))

	checker := NewChecker(Config{
		Sources: []Source{{
			Key:      goldenListId,
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
