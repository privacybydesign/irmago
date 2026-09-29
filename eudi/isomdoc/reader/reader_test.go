package reader_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/isomdoc"
	"github.com/privacybydesign/irmago/eudi/isomdoc/reader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

const (
	testDocType = "eu.europa.ec.av.1"
	testOrigin  = "https://verifier.example.com"
)

// testSpecs are two circuits shaped like the real ones. The hashes are not real
// circuits and do not need to be: nothing here verifies a proof, and what is
// under test is that the offer and the accepted set come from one list.
func testSpecs() []mdoc.ZkSystemSpec {
	spec := func(id, hash string, attributes int64) mdoc.ZkSystemSpec {
		return mdoc.ZkSystemSpec{
			ID:     id,
			System: mdoc.ZkSystemLongfellowV1,
			Params: map[string]any{
				mdoc.ZkParamVersion:       int64(7),
				mdoc.ZkParamCircuitHash:   hash,
				mdoc.ZkParamNumAttributes: attributes,
				mdoc.ZkParamBlockEncHash:  int64(4265),
				mdoc.ZkParamBlockEncSig:   int64(4096),
			},
		}
	}
	return []mdoc.ZkSystemSpec{
		spec("longfellow-libzk-v1_7_1_aaa", "aaa", 1),
		spec("longfellow-libzk-v1_7_2_bbb", "bbb", 2),
	}
}

// testBuilder returns a Builder with a self-signed reader chain.
//
// Self-signed is enough here because no trust store is consulted: these tests
// are about what gets assembled, not about whether a wallet would trust it,
// which readerauth_test.go already covers in the package that owns it.
func testBuilder(t *testing.T) reader.Builder {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test reader"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return reader.Builder{
		Chain:     []*x509.Certificate{certificate},
		Signer:    key,
		Algorithm: cose.AlgorithmES256,
		Specs:     testSpecs(),
	}
}

func testElements() mdoc.DataElements {
	return mdoc.DataElements{"age_over_18": false, "age_over_75": false}
}

// TestBuildProducesARequestTheWalletParses is the assertion worth having: the
// bytes this package emits go through the wallet's own entry point rather than
// through a reimplementation of it. A reader that assembled something only its
// own tests could read would pass every other test in this file.
func TestBuildProducesARequestTheWalletParses(t *testing.T) {
	request, err := testBuilder(t).Build(testOrigin, testDocType, testElements())
	require.NoError(t, err)

	decoded, err := mdoc.DecodeDeviceRequest(request.DeviceRequest)
	require.NoError(t, err)
	require.NoError(t, decoded.Validate())
	require.Len(t, decoded.DocRequests, 1)

	// The wallet's own translation, not ours.
	_, err = isomdoc.DcqlQueryFromDeviceRequest(decoded)
	require.NoError(t, err)

	items, err := decoded.DocRequests[0].Items()
	require.NoError(t, err)
	assert.Equal(t, testDocType, items.DocType)
	assert.Equal(t, testElements(), items.NameSpaces[testDocType],
		"the namespace is the docType and carries both elements with their intentToRetain flags")

	assert.NotEmpty(t, decoded.DocRequests[0].ReaderAuth, "readerAuth must be signed")
}

func TestBuildCarriesTheZkRequest(t *testing.T) {
	builder := testBuilder(t)
	request, err := builder.Build(testOrigin, testDocType, testElements())
	require.NoError(t, err)

	decoded, err := mdoc.DecodeDeviceRequest(request.DeviceRequest)
	require.NoError(t, err)
	items, err := decoded.DocRequests[0].Items()
	require.NoError(t, err)

	zk, present, err := mdoc.ZkRequestFrom(items)
	require.NoError(t, err)
	require.True(t, present, "a builder with specs must offer them")
	assert.False(t, zk.ZkRequired, "the A.6 fallback stays available unless a deployment says otherwise")
	require.Len(t, zk.SystemSpecs, len(builder.Specs))
	for i, spec := range builder.Specs {
		assert.Equal(t, spec.ID, zk.SystemSpecs[i].ID)
	}
}

func TestNoSpecsMeansNoZkRequest(t *testing.T) {
	builder := testBuilder(t)
	builder.Specs = nil

	request, err := builder.Build(testOrigin, testDocType, testElements())
	require.NoError(t, err)

	decoded, err := mdoc.DecodeDeviceRequest(request.DeviceRequest)
	require.NoError(t, err)
	items, err := decoded.DocRequests[0].Items()
	require.NoError(t, err)

	_, present, err := mdoc.ZkRequestFrom(items)
	require.NoError(t, err)
	assert.False(t, present, "a reader that deals in no circuits sends a plain ISO request")
}

// TestSealedResponseRoundTrips exercises the three values that have to agree:
// the recipient key, the encryptionInfo text and the origin. Sealing with what
// Build handed back and opening it again is the cheapest way to catch a
// transcript that was rebuilt rather than kept.
func TestSealedResponseRoundTrips(t *testing.T) {
	request, err := testBuilder(t).Build(testOrigin, testDocType, testElements())
	require.NoError(t, err)

	payload := []byte("a DeviceResponse would be here")
	sealed, err := mdoc.SealDCAPIResponse(payload, &request.Recipient.PublicKey, request.Transcript)
	require.NoError(t, err)
	encoded, err := cbor.Marshal(sealed)
	require.NoError(t, err)

	opened, err := request.OpenBase64(base64.RawURLEncoding.EncodeToString(encoded))
	require.NoError(t, err)
	assert.Equal(t, payload, opened)
}

// TestOpenRefusesAResponseSealedToAnotherRequest is the negative half: two
// requests differ in both their ephemeral key and their transcript, so a
// response meant for one must not open under the other. Without this, a builder
// that reused a key or a nonce would pass the round trip above.
func TestOpenRefusesAResponseSealedToAnotherRequest(t *testing.T) {
	builder := testBuilder(t)
	first, err := builder.Build(testOrigin, testDocType, testElements())
	require.NoError(t, err)
	second, err := builder.Build("https://elsewhere.example.com", testDocType, testElements())
	require.NoError(t, err)

	sealed, err := mdoc.SealDCAPIResponse([]byte("for the first"), &first.Recipient.PublicKey, first.Transcript)
	require.NoError(t, err)

	_, err = second.Open(sealed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a failed proof",
		"the error has to say what actually went wrong, or it sends the reader looking at the prover")
}

// TestRestoreOpensWhatTheBuilderSealed is the two-process case: the request is
// built once, only encryptionInfo/origin/key are kept, and the response is
// opened from those alone. If the transcript were not reproducible from what a
// store can hold, this is where it would show.
func TestRestoreOpensWhatTheBuilderSealed(t *testing.T) {
	built, err := testBuilder(t).Build(testOrigin, testDocType, testElements())
	require.NoError(t, err)

	payload := []byte("a DeviceResponse would be here")
	sealed, err := mdoc.SealDCAPIResponse(payload, &built.Recipient.PublicKey, built.Transcript)
	require.NoError(t, err)
	encoded, err := cbor.Marshal(sealed)
	require.NoError(t, err)

	// Only what a session store would have kept.
	restored, err := reader.Restore(built.EncryptionInfo, built.Origin, built.Recipient)
	require.NoError(t, err)

	opened, err := restored.OpenBase64(base64.RawURLEncoding.EncodeToString(encoded))
	require.NoError(t, err)
	assert.Equal(t, payload, opened)
}

func TestRestoreRefusesIncompleteState(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = reader.Restore("", testOrigin, key)
	assert.ErrorContains(t, err, "encryptionInfo")

	_, err = reader.Restore("info", "", key)
	assert.ErrorContains(t, err, "origin")

	_, err = reader.Restore("info", testOrigin, nil)
	assert.ErrorContains(t, err, "recipient key")
}

func TestAcceptedCircuitsComeFromTheOfferedSpecs(t *testing.T) {
	builder := testBuilder(t)
	accepted := builder.AcceptedCircuits()

	for _, spec := range builder.Specs {
		assert.NoError(t, accepted.Accepts(spec), "a circuit that was offered must be accepted: %s", spec.ID)
	}

	stranger := mdoc.ZkSystemSpec{
		ID:     "longfellow-libzk-v1_7_1_unlisted",
		System: mdoc.ZkSystemLongfellowV1,
		Params: map[string]any{mdoc.ZkParamCircuitHash: "unlisted"},
	}
	assert.Error(t, accepted.Accepts(stranger), "a circuit that was never offered must not be accepted")
}

func TestBuildRefusesIncompleteInput(t *testing.T) {
	for _, test := range []struct {
		name     string
		mutate   func(*reader.Builder)
		origin   string
		docType  string
		elements mdoc.DataElements
		contains string
	}{
		{
			name:     "no origin",
			origin:   "",
			docType:  testDocType,
			elements: testElements(),
			contains: "origin",
		},
		{
			name:     "no elements",
			origin:   testOrigin,
			docType:  testDocType,
			elements: mdoc.DataElements{},
			contains: "no data elements",
		},
		{
			name:     "no docType",
			origin:   testOrigin,
			docType:  "",
			elements: testElements(),
			contains: "docType",
		},
		{
			name:     "no chain",
			mutate:   func(b *reader.Builder) { b.Chain = nil },
			origin:   testOrigin,
			docType:  testDocType,
			elements: testElements(),
			contains: "certificate chain",
		},
		{
			name:     "no signer",
			mutate:   func(b *reader.Builder) { b.Signer = nil },
			origin:   testOrigin,
			docType:  testDocType,
			elements: testElements(),
			contains: "signer",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			builder := testBuilder(t)
			if test.mutate != nil {
				test.mutate(&builder)
			}
			_, err := builder.Build(test.origin, test.docType, test.elements)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.contains)
		})
	}
}
