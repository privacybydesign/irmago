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

// The anchor list's golden twin: a committed, signed anchor list that this package
// did not marshal, so a rename of the members only an anchor list carries —
// ServiceSupplyPoints, YiviConfers, the CA service types, the anchor LoTEType —
// fails here and nowhere else.
//
// Built from testdata/lote-source-anchors by `yivi eudi lote build` and signed by
// `sign`, under a throwaway chain `keygen` wrote; regenerate with
// testdata/lote-publisher/mkgolden-anchors.sh. Like the party golden, the
// assertions pin a clock derived from the signing certificate, so only that
// certificate's notAfter bounds the test.

func goldenAnchorsDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", "lote-publisher", "golden-anchors")
}

func goldenAnchorsRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenAnchorsDir(t), "list.jws"))
	require.NoError(t, err)
	return raw
}

func goldenAnchorsCertificate(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenAnchorsDir(t), "certs", name))
	require.NoError(t, err)
	chain, err := utils.ParsePemCertificateChain(raw)
	require.NoError(t, err)
	require.Len(t, chain, 1)
	return chain[0]
}

func goldenAnchorsTime(t *testing.T) time.Time {
	t.Helper()
	return goldenAnchorsCertificate(t, "signer.crt").NotBefore.Add(24 * time.Hour)
}

func goldenAnchorsContext(t *testing.T) eudi_jwt.X509VerificationContext {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(goldenAnchorsCertificate(t, "ca.crt"))
	return &eudi_jwt.StaticVerificationContext{VerifyOpts: x509.VerifyOptions{
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: goldenAnchorsTime(t),
	}}
}

func TestGoldenAnchorListVerifiesAndParses(t *testing.T) {
	signerSKI := goldenAnchorsCertificate(t, "signer.crt").SubjectKeyId
	require.NotEmpty(t, signerSKI, "the golden signer carries the key identifier a source pins")

	verified, err := verify(goldenAnchorsRaw(t), goldenAnchorsContext(t), signerSKI)
	require.NoError(t, err, "the committed anchor list must keep verifying, pin included")

	scheme := verified.list.SchemeInformation
	require.Equal(t, LoTETypeTrustAnchors, scheme.LoTEType)
	require.Equal(t, "NL:Yivi Trust Anchors", scheme.SchemeName["en"])
	require.Equal(t, uint64(1), scheme.SequenceNumber)
	require.Equal(t, 180*24*time.Hour, scheme.NextUpdate.Sub(scheme.ListIssueDateTime), "an anchor list carries a six-month window")

	require.Len(t, verified.list.Entities, 2)
	issuing := verified.list.Entities[0].Services[0].Information
	require.Equal(t, ServiceTypeIssuerCA, issuing.Type)
	require.True(t, issuing.IsAnchor())
	require.Equal(t, clientmodels.TrustLevel_Medium, issuing.Confers())
	require.Equal(t, []string{"https://trust.example.com/crl/attestation.crl"}, issuing.CRLDistributionPoints(),
		"ServiceSupplyPoints is where the CRLs live on the wire")
	require.Len(t, issuing.DigitalIdentity.X509Certificates, 1)
	ca, err := x509.ParseCertificate(issuing.DigitalIdentity.X509Certificates[0].Val)
	require.NoError(t, err)
	require.True(t, ca.IsCA)

	verifying := verified.list.Entities[1].Services[0].Information
	require.Equal(t, ServiceTypeVerifierCA, verifying.Type)

	// The wire carries the members by their Annex A and Yivi names.
	var raw map[string]any
	payload, err := json.Marshal(Document{LoTE: *verified.list})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(payload, &raw))
	service := raw["LoTE"].(map[string]any)["TrustedEntitiesList"].([]any)[0].(map[string]any)["TrustedEntityServices"].([]any)[0].(map[string]any)["ServiceInformation"].(map[string]any)
	require.Contains(t, service, "ServiceSupplyPoints")
	require.Contains(t, service["ServiceInformationExtensions"].([]any)[0], "YiviConfers")
}

func TestGoldenAnchorListReadableCopyMatchesTheSignedOne(t *testing.T) {
	verified, err := verify(goldenAnchorsRaw(t), goldenAnchorsContext(t), nil)
	require.NoError(t, err)

	readable, err := os.ReadFile(filepath.Join(goldenAnchorsDir(t), "list.json"))
	require.NoError(t, err)
	var fromReadable Document
	require.NoError(t, json.Unmarshal(readable, &fromReadable))

	signed, err := json.Marshal(Document{LoTE: *verified.list})
	require.NoError(t, err)
	reread, err := json.Marshal(fromReadable)
	require.NoError(t, err)
	require.JSONEq(t, string(signed), string(reread), "list.json is the signed document in readable form")
}

func TestGoldenAnchorListDeliversThroughTheChecker(t *testing.T) {
	store := memoryStore{}
	const key = "golden-anchors"
	store[key] = goldenAnchorsRaw(t)

	checker := NewChecker(Config{
		Sources: []Source{{
			Key:       key,
			LoTEType:  LoTETypeTrustAnchors,
			URL:       "http://unused.example",
			Confers:   clientmodels.TrustLevel_High,
			Delivers:  DeliversAnchors,
			SignerSKI: goldenAnchorsCertificate(t, "signer.crt").SubjectKeyId,
		}},
		X509Context: goldenAnchorsContext(t),
		Store:       store,
		Now:         func() time.Time { return goldenAnchorsTime(t) },
	})

	anchors := checker.Anchors()
	require.Len(t, anchors, 2)
	require.Equal(t, trust.RoleIssuer, anchors[0].Role)
	require.Equal(t, "Yivi Test EUDI Root CA", anchors[0].Certificate.Subject.CommonName)
	require.Equal(t, clientmodels.TrustLevel_Medium, anchors[0].Confers)
	require.Equal(t, trust.RoleVerifier, anchors[1].Role)
	require.Equal(t, "Demo Requestors Root", anchors[1].Certificate.Subject.CommonName)

	// And it is an anchor list: it grants no party, whatever it carries.
	require.Nil(t, checker.Snapshot().Lookup(trust.RoleIssuer, trust.Evidence{Certificate: anchors[0].Certificate}))
}
