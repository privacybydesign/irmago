package lote

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/trust"
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
// a DID, the onboarded-by-Yivi marking, a withdrawal, service-level name and logo
// overrides, an unknown marking that must be carried and ignored, and
// multilingual names.
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
	block, _ := pem.Decode(rootPem)
	require.NotNil(t, block)
	root, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(root)
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
	require.Equal(t, goldenListId, scheme.ListIdentifier)
	require.Equal(t, uint64(42), scheme.SequenceNumber)
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
	party := verified.list.Entities[0]
	require.Equal(t, "VATNL-000000001", party.OrganizationIdentifier)
	require.Equal(t, clientmodels.TranslatedString{"en": "Gemeente Voorbeeld", "nl": "Gemeente Voorbeeld"}, party.Name)
	require.Equal(t, "https://trustlist.example/logos/voorbeeld.png", party.LogoURI)
	require.Len(t, party.Services, 1)

	service := party.Services[0]
	require.Equal(t, ServiceTypeVerifier, service.Type)
	require.Equal(t, ServiceStatusGranted, service.Status)
	require.Equal(t, goldenPartyCertificate(t).Raw, service.DigitalIdentity.X509Certificate,
		"the certificate key form carries the DER")
	require.True(t, service.HasMarking(MarkingOnboardedByYivi))

	// The SKI key form, the service-level overrides, and an unknown marking that
	// must survive parsing without being acted on.
	skiService := verified.list.Entities[1].Services[0]
	require.Equal(t, goldenPartyCertificate(t).SubjectKeyId, skiService.DigitalIdentity.X509SKI)
	require.Equal(t, clientmodels.TranslatedString{"en": "Voorbeeld Diplomas"}, skiService.Name)
	require.Equal(t, "https://trustlist.example/logos/diplomas.png", skiService.LogoURI)
	require.True(t, skiService.HasMarking("some-future-qualifier"))
	require.False(t, skiService.HasMarking(MarkingOnboardedByYivi))

	// The DID convention, and a withdrawal that is listed but grants nothing.
	didService := verified.list.Entities[2].Services[0]
	require.Equal(t, []OtherId{{Type: OtherIdTypeDid, Value: goldenDid}}, didService.DigitalIdentity.OtherIds)
	require.Equal(t, ServiceStatusWithdrawn, verified.list.Entities[3].Services[0].Status)
}

// TestGoldenReadableCopyMatchesTheSignedOne keeps golden/list.json honest: it is
// there to be read by humans, so it must parse to exactly the list that was
// signed.
func TestGoldenReadableCopyMatchesTheSignedOne(t *testing.T) {
	verified, err := verify(goldenRaw(t), goldenAnchors(t))
	require.NoError(t, err)

	readable, err := os.ReadFile(filepath.Join(goldenDir(t), "list.json"))
	require.NoError(t, err)

	var fromReadable List
	require.NoError(t, json.Unmarshal(readable, &fromReadable))
	require.Equal(t, *verified.list, fromReadable,
		"golden/list.json must be the same list as golden/list.jws; re-run mkgolden.sh")
}

// TestGoldenDocumentGrantsThroughTheChecker runs the committed document through
// the whole channel — store, checker, snapshot, keying — as of the pinned date,
// so the shapes above are not merely parsed but acted on.
func TestGoldenDocumentGrantsThroughTheChecker(t *testing.T) {
	store := NewMemoryStore()
	require.NoError(t, store.Put(goldenListId, goldenRaw(t)))

	checker := NewChecker(Config{
		Sources:     []Source{{ListId: goldenListId, URL: "http://unused.example", OperatedByYivi: true}},
		X509Context: goldenAnchors(t),
		Store:       store,
		Now:         func() time.Time { return goldenTime(t) },
	})
	snapshot := checker.Snapshot()

	certificateParty := trust.Evidence{Certificate: goldenPartyCertificate(t)}
	listing := snapshot.Lookup(trust.RoleVerifier, certificateParty)
	require.NotNil(t, listing, "the certificate-keyed entry must grant")
	require.Equal(t, "Gemeente Voorbeeld", listing.Name["en"])
	require.True(t, listing.OnboardedByYivi, "marked, on a list flagged as Yivi's own")

	// The same party, in its issuer role, matches the SKI-keyed entry instead —
	// and picks up that service's overriding name.
	asIssuer := snapshot.Lookup(trust.RoleIssuer, certificateParty)
	require.NotNil(t, asIssuer)
	require.Equal(t, "Voorbeeld Diplomas", asIssuer.Name["en"])
	require.False(t, asIssuer.OnboardedByYivi, "that entry carries only an unknown marking")

	require.NotNil(t, snapshot.Lookup(trust.RoleVerifier, trust.Evidence{Identifiers: []string{goldenDid}}),
		"the DID entry must grant")
	require.Nil(t, snapshot.Lookup(trust.RoleIssuer, trust.Evidence{Identifiers: []string{goldenWithdrawnDid}}),
		"a withdrawn service grants nothing")
}
