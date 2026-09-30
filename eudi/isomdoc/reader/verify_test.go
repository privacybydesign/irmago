package reader_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/isomdoc/reader"
	"github.com/stretchr/testify/require"
)

// The verification half. What is under test here is not the cryptography — the
// proof system has its own tests — but the two things a relying party gets wrong
// by omission: believing a proof without asking whose issuer key it is relative
// to, and letting a document that was never checked pass as one that was.

// acceptingSystem verifies every proof it is handed. That is the point: it
// removes the cryptography from these tests so that what remains is whether the
// checks AROUND the proof are applied. A system that refused everything would
// pass these tests for the wrong reason.
type acceptingSystem struct {
	specs []mdoc.ZkSystemSpec
}

func (s *acceptingSystem) Name() string                     { return mdoc.ZkSystemLongfellowV1 }
func (s *acceptingSystem) SystemSpecs() []mdoc.ZkSystemSpec { return s.specs }

func (s *acceptingSystem) MatchingSpec(offered []mdoc.ZkSystemSpec, _ int) (mdoc.ZkSystemSpec, bool) {
	if len(s.specs) == 0 {
		return mdoc.ZkSystemSpec{}, false
	}
	return s.specs[0], true
}

func (s *acceptingSystem) GenerateProof(
	spec mdoc.ZkSystemSpec, document mdoc.MDoc, _ mdoc.SessionTranscript, timestamp time.Time,
) (*mdoc.ZkDocument, error) {
	return &mdoc.ZkDocument{
		DocumentData: mdoc.NewZkDocumentData(spec.ID, document.DocType, timestamp, nil, nil),
		Proof:        []byte{0xde, 0xad},
	}, nil
}

func (s *acceptingSystem) VerifyProof(mdoc.ZkDocument, mdoc.ZkSystemSpec, mdoc.SessionTranscript) error {
	return nil
}

// issuer is a minimal attestation provider: a self-signed root, and a document
// signer beneath it. Two of these produce two unrelated trust worlds, which is
// what the untrusted-issuer test needs.
type issuer struct {
	root  *x509.Certificate
	chain []*x509.Certificate
}

func newIssuer(t testing.TB, name string) issuer {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name + " IACA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name + " document signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTemplate, root, &signerKey.PublicKey, rootKey)
	require.NoError(t, err)
	signer, err := x509.ParseCertificate(signerDER)
	require.NoError(t, err)

	return issuer{root: root, chain: []*x509.Certificate{signer, root}}
}

// zkResponse encodes a DeviceResponse carrying one proof over the given chain.
func zkResponse(t testing.TB, specID, docType string, chain []*x509.Certificate, now time.Time) []byte {
	t.Helper()

	document := mdoc.ZkDocument{
		DocumentData: mdoc.NewZkDocumentData(specID, docType, now, map[string][]mdoc.ZkSignedItem{
			docType: {{ElementIdentifier: "age_over_18", ElementValue: cbor.RawMessage{0xf5}}},
		}, chain),
		Proof: []byte{0xde, 0xad, 0xbe, 0xef},
	}
	response := mdoc.NewDeviceResponse().WithZkDocuments(document)
	encoded, err := response.Encode()
	require.NoError(t, err)
	return encoded
}

// verifyingBuilder is testBuilder plus the two things verification needs: a
// trust model, and a system that can run the offered circuits.
func verifyingBuilder(t testing.TB, roots []*x509.Certificate) reader.Builder {
	t.Helper()

	builder := testBuilder(t)
	builder.Verifier = mdoc.NewVerifier(roots)
	builder.ZkSystems = mdoc.NewZkSystemRepository(&acceptingSystem{specs: testSpecs()})
	return builder
}

// TestVerifyRefusesAnUntrustedIssuer is the finding this file exists for. The
// proof verifies — acceptingSystem says so — and the presentation must still be
// refused, because a proof establishes that SOME key signed the attestation and
// says nothing at all about whose key it is. A wallet that mints its own IACA
// produces exactly this response.
func TestVerifyRefusesAnUntrustedIssuer(t *testing.T) {
	trusted := newIssuer(t, "trusted")
	rogue := newIssuer(t, "rogue")

	builder := verifyingBuilder(t, []*x509.Certificate{trusted.root})
	request, err := builder.Build(testOrigin, testDocType, testElements())
	require.NoError(t, err)

	now := time.Now()
	response := zkResponse(t, testSpecs()[0].ID, testDocType, rogue.chain, now)

	_, err = builder.Verify(request, response, testDocType, now)
	require.Error(t, err, "a proof under an unpinned issuer is a sound proof of a worthless statement")
	require.Contains(t, err.Error(), "chain verification failed")
}

// TestVerifyAcceptsATrustedIssuer: the same response under a pinned root is
// accepted, and what comes back names the issuer it was established under.
func TestVerifyAcceptsATrustedIssuer(t *testing.T) {
	trusted := newIssuer(t, "trusted")

	builder := verifyingBuilder(t, []*x509.Certificate{trusted.root})
	request, err := builder.Build(testOrigin, testDocType, testElements())
	require.NoError(t, err)

	now := time.Now()
	response := zkResponse(t, testSpecs()[0].ID, testDocType, trusted.chain, now)

	verified, err := builder.Verify(request, response, testDocType, now)
	require.NoError(t, err)
	require.Len(t, verified, 1)

	require.True(t, verified[0].ZeroKnowledge)
	require.Equal(t, testDocType, verified[0].DocType)
	require.Equal(t, testSpecs()[0].ID, verified[0].Spec.ID)
	require.Equal(t, trusted.chain[0], verified[0].IssuerSigner,
		"the document signer it was established under, not the one it claimed")
	require.Contains(t, verified[0].Elements, testDocType)
}

// TestVerifyRefusesAProofAboutAnotherDocType: the proof binds its elements to
// the docType it was made for, not to the one that was asked for, so answering a
// request for one document with a proof about another is a substitution nothing
// in the cryptography prevents.
func TestVerifyRefusesAProofAboutAnotherDocType(t *testing.T) {
	trusted := newIssuer(t, "trusted")

	builder := verifyingBuilder(t, []*x509.Certificate{trusted.root})
	request, err := builder.Build(testOrigin, testDocType, testElements())
	require.NoError(t, err)

	now := time.Now()
	response := zkResponse(t, testSpecs()[0].ID, "org.iso.18013.5.1.mDL", trusted.chain, now)

	_, err = builder.Verify(request, response, testDocType, now)
	require.Error(t, err)
	require.Contains(t, err.Error(), "was requested")
}

// TestVerifyRefusesAnUnofferedCircuit: A.8's accepted-circuit gate still applies
// through this path. The spec is one the repository knows, so it resolves — and
// it is not one this builder offered, which is what must refuse it.
func TestVerifyRefusesAnUnofferedCircuit(t *testing.T) {
	trusted := newIssuer(t, "trusted")

	builder := verifyingBuilder(t, []*x509.Certificate{trusted.root})
	// Offer only the first circuit while the repository still holds both, so the
	// second resolves by id and is then refused by the gate rather than by lookup.
	builder.Specs = testSpecs()[:1]

	request, err := builder.Build(testOrigin, testDocType, testElements())
	require.NoError(t, err)

	now := time.Now()
	response := zkResponse(t, testSpecs()[1].ID, testDocType, trusted.chain, now)

	_, err = builder.Verify(request, response, testDocType, now)
	require.Error(t, err)
}

// TestVerifyNeedsATrustModel: a Builder without a Verifier must refuse rather
// than verify the proof alone, which is the shape of the defect this guards.
func TestVerifyNeedsATrustModel(t *testing.T) {
	trusted := newIssuer(t, "trusted")

	builder := testBuilder(t)
	builder.ZkSystems = mdoc.NewZkSystemRepository(&acceptingSystem{specs: testSpecs()})

	request, err := builder.Build(testOrigin, testDocType, testElements())
	require.NoError(t, err)

	now := time.Now()
	response := zkResponse(t, testSpecs()[0].ID, testDocType, trusted.chain, now)

	_, err = builder.Verify(request, response, testDocType, now)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no Verifier configured")
}

// TestVerifyRefusesAResponseThatDisclosedNothing: a refusal is a well-formed
// response and must not come back as an empty success.
func TestVerifyRefusesAResponseThatDisclosedNothing(t *testing.T) {
	trusted := newIssuer(t, "trusted")

	builder := verifyingBuilder(t, []*x509.Certificate{trusted.root})
	request, err := builder.Build(testOrigin, testDocType, testElements())
	require.NoError(t, err)

	empty, err := mdoc.NewDeviceResponse().Encode()
	require.NoError(t, err)

	_, err = builder.Verify(request, empty, testDocType, time.Now())
	require.Error(t, err)
	require.Contains(t, err.Error(), "carries no documents")
}
