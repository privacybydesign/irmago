package mdoc

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc/zk"
	"github.com/stretchr/testify/require"
)

// ============================================================
// A fake native system, so the adapter can be tested without one
// ============================================================

type fakeZkNative struct {
	circuits   []zk.Circuit
	proof      []byte
	proveErr   error
	verifyErr  error
	lastProve  zk.ProofRequest
	lastVerify zk.VerificationRequest
	proveCalls int
}

func (f *fakeZkNative) Name() string           { return ZkSystemLongfellowV1 }
func (f *fakeZkNative) Circuits() []zk.Circuit { return f.circuits }

func (f *fakeZkNative) Prove(request zk.ProofRequest) ([]byte, error) {
	f.lastProve = request
	f.proveCalls++
	if f.proveErr != nil {
		return nil, f.proveErr
	}
	return f.proof, nil
}

func (f *fakeZkNative) Verify(request zk.VerificationRequest) error {
	f.lastVerify = request
	return f.verifyErr
}

// The four v6 circuits the captured EUDI AV reader offered, as the native side
// would report them.
func avCircuits() []zk.Circuit {
	return []zk.Circuit{
		{
			System: ZkSystemLongfellowV1, Version: 6, NumAttributes: 1,
			BlockEncHash: 4096, BlockEncSig: 2945,
			Hash: "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
		},
		{
			System: ZkSystemLongfellowV1, Version: 6, NumAttributes: 2,
			BlockEncHash: 4025, BlockEncSig: 2945,
			Hash: "b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e",
		},
	}
}

func newFakeProverSystem(t *testing.T) (*ProverSystem, *fakeZkNative) {
	t.Helper()
	native := &fakeZkNative{circuits: avCircuits(), proof: []byte("a proof")}
	return NewProverSystem(native), native
}

// ============================================================
// Spec assembly
// ============================================================

// The identifier convention is the AV profile's, and it is easy to transpose:
// version and attribute count come before the two block-encoding parameters.
// Pinned against the identifier the captured reader actually sent.
func TestProverSystemSpecIDFollowsTheProfileConvention(t *testing.T) {
	system, _ := newFakeProverSystem(t)

	specs := system.SystemSpecs()
	require.Len(t, specs, 2)

	require.Equal(t,
		"longfellow-libzk-v1_6_1_4096_2945_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
		specs[0].ID)
	require.Equal(t, ZkSystemLongfellowV1, specs[0].System)

	version, ok := specs[0].Version()
	require.True(t, ok)
	require.Equal(t, int64(6), version)

	count, ok := specs[0].NumAttributes()
	require.True(t, ok)
	require.Equal(t, int64(1), count)

	hash, ok := specs[0].CircuitHash()
	require.True(t, ok)
	require.Equal(t, "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6", hash)
}

// A spec this adapter mints and one the captured reader sent must be recognised
// as the same circuit. That is the whole point of SameCircuit comparing
// parameters rather than identifiers.
func TestProverSystemSpecsMatchTheCapturedReaderOffer(t *testing.T) {
	system, _ := newFakeProverSystem(t)
	mine := system.SystemSpecs()[0]

	theirs := ZkSystemSpec{
		ID:     "some other label entirely",
		System: ZkSystemLongfellowV1,
		Params: map[string]any{
			ZkParamVersion:       uint64(6),
			ZkParamNumAttributes: uint64(1),
			ZkParamBlockEncHash:  uint64(4096),
			ZkParamBlockEncSig:   uint64(2945),
			ZkParamCircuitHash:   "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
		},
	}
	require.True(t, mine.SameCircuit(theirs))
}

func TestProverSystemMatchingSpecRequiresTheExactAttributeCount(t *testing.T) {
	system, _ := newFakeProverSystem(t)
	offered := system.SystemSpecs()

	_, ok := system.MatchingSpec(offered, 1)
	require.True(t, ok, "one attribute is offered and held")

	_, ok = system.MatchingSpec(offered, 2)
	require.True(t, ok, "two attributes likewise")

	// A circuit proves a fixed number of statements, so three elements cannot be
	// answered by the two-attribute circuit. This is a fallback, not a failure.
	_, ok = system.MatchingSpec(offered, 3)
	require.False(t, ok)
}

func TestProverSystemMatchingSpecPrefersTheNewestVersion(t *testing.T) {
	hash := "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6"
	native := &fakeZkNative{circuits: []zk.Circuit{
		{
			System: ZkSystemLongfellowV1, Version: 6, NumAttributes: 1,
			BlockEncHash: 4096, BlockEncSig: 2945, Hash: hash,
		},
		{
			System: ZkSystemLongfellowV1, Version: 7, NumAttributes: 1,
			BlockEncHash: 4151, BlockEncSig: 4096, Hash: hash + "-v7",
		},
	}}
	system := NewProverSystem(native)

	spec, ok := system.MatchingSpec(system.SystemSpecs(), 1)
	require.True(t, ok)

	version, _ := spec.Version()
	require.Equal(t, int64(7), version, "newest common version wins")
}

// Nothing in common is a fallback, and the caller — not this adapter — decides
// what that means.
func TestProverSystemMatchingSpecReportsNoCommonCircuit(t *testing.T) {
	system, _ := newFakeProverSystem(t)

	stranger := ZkSystemSpec{
		ID:     "stranger",
		System: ZkSystemLongfellowV1,
		Params: map[string]any{
			ZkParamVersion:       int64(6),
			ZkParamNumAttributes: int64(1),
			ZkParamCircuitHash:   "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	_, ok := system.MatchingSpec([]ZkSystemSpec{stranger}, 1)
	require.False(t, ok)
}

// ============================================================
// Proving
// ============================================================

func provableDocument(t *testing.T) (*TestIssuer, *MDoc, SessionTranscript) {
	t.Helper()
	issuer, _, _, presented, transcript, deviceAuth, _, _ := buildHappyPathMDoc(t)

	withDeviceSigned, err := AttachDeviceSigned(presented, deviceAuth)
	require.NoError(t, err)
	return issuer, withDeviceSigned, transcript
}

// The prover refuses a document with no deviceSigned — MDOC_PROVER_DEVICE_
// SIGNED_MISSING — because one of §A.8's statements is about the device
// signature over the transcript. Catching it here names the cause instead of
// letting an opaque native code surface several layers up.
func TestGenerateProofRefusesADocumentWithoutDeviceSigned(t *testing.T) {
	system, native := newFakeProverSystem(t)
	_, _, _, presented, transcript, _, _, _ := buildHappyPathMDoc(t)

	_, err := system.GenerateProof(system.SystemSpecs()[0], *presented, transcript, time.Now())
	require.ErrorContains(t, err, "deviceSigned")
	require.Zero(t, native.proveCalls, "the native prover must not be reached")
}

// What crosses the boundary is bytes, and these are the bytes that have bitten
// us before: a DeviceResponse rather than a bare document, and issuer key
// coordinates padded to a fixed 32 bytes.
func TestGenerateProofHandsTheNativeSideTheBytesItExpects(t *testing.T) {
	system, native := newFakeProverSystem(t)
	issuer, document, transcript := provableDocument(t)
	timestamp := time.Date(2024, 3, 15, 9, 0, 0, 0, time.UTC)

	zkDocument, err := system.GenerateProof(system.SystemSpecs()[0], *document, transcript, timestamp)
	require.NoError(t, err)
	require.Equal(t, []byte("a proof"), zkDocument.Proof)

	request := native.lastProve

	// A DeviceResponse, not a bare document: the native prover takes the first
	// document out of one.
	var response DeviceResponse
	require.NoError(t, cbor.Unmarshal(request.DeviceResponse, &response),
		"what was handed over must decode as a DeviceResponse")
	require.Len(t, response.Documents, 1)

	// The issuer key is the DS certificate's, rendered the way the ABI reads it.
	dsKey, ok := issuer.DSCert().PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, "0x"+hex.EncodeToString(dsKey.X.FillBytes(make([]byte, 32))), request.IssuerKeyX)
	require.Equal(t, "0x"+hex.EncodeToString(dsKey.Y.FillBytes(make([]byte, 32))), request.IssuerKeyY)
	require.Len(t, request.IssuerKeyX, 66)

	require.Equal(t, "eu.europa.ec.av.1", request.DocType)
	require.Equal(t, timestamp, request.Timestamp)

	// The one disclosed element, with its value as the CBOR it was signed as:
	// 0xf5 is CBOR true.
	require.Len(t, request.Attributes, 1)
	require.Equal(t, "age_over_18", request.Attributes[0].Identifier)
	require.Equal(t, []byte{0xf5}, request.Attributes[0].Value)
}

// The cleartext half must echo the spec ID the proof was produced under, so the
// verifier can resolve the same circuit, and must carry the issuer chain, which
// the verifier needs to check the key the proof is stated against.
func TestGenerateProofAssemblesTheCleartextHalf(t *testing.T) {
	system, _ := newFakeProverSystem(t)
	_, document, transcript := provableDocument(t)
	spec := system.SystemSpecs()[0]
	timestamp := time.Date(2024, 3, 15, 9, 0, 0, 500_000_000, time.UTC)

	zkDocument, err := system.GenerateProof(spec, *document, transcript, timestamp)
	require.NoError(t, err)

	data := zkDocument.DocumentData
	require.Equal(t, spec.ID, data.ZkSystemSpecID)
	require.Equal(t, "eu.europa.ec.av.1", data.DocType)
	require.NotEmpty(t, data.MsoX5Chain)

	// Truncated to the whole second the prover will actually use, so the value
	// recorded here and the value proved cannot disagree.
	require.Equal(t, timestamp.Truncate(time.Second), data.Timestamp)

	require.Len(t, data.IssuerSigned["eu.europa.ec.av.1"], 1)
	require.Equal(t, "age_over_18", data.IssuerSigned["eu.europa.ec.av.1"][0].ElementIdentifier)
}

// A prover that was selected and then failed is an error, never a quiet
// fallback: a wallet that disclosed in the clear because proving broke would
// turn a crash into an over-disclosure.
func TestGenerateProofSurfacesANativeFailure(t *testing.T) {
	system, native := newFakeProverSystem(t)
	native.proveErr = fmt.Errorf("MDOC_PROVER_GENERAL_FAILURE")
	_, document, transcript := provableDocument(t)

	_, err := system.GenerateProof(system.SystemSpecs()[0], *document, transcript, time.Now())
	require.ErrorContains(t, err, "MDOC_PROVER_GENERAL_FAILURE")
}

func TestGenerateProofRefusesAnEmptyProof(t *testing.T) {
	system, native := newFakeProverSystem(t)
	native.proof = nil
	_, document, transcript := provableDocument(t)

	_, err := system.GenerateProof(system.SystemSpecs()[0], *document, transcript, time.Now())
	require.ErrorContains(t, err, "empty proof")
}

// ============================================================
// Verifying
// ============================================================

func TestVerifyProofRebuildsTheSameRequest(t *testing.T) {
	system, native := newFakeProverSystem(t)
	_, document, transcript := provableDocument(t)
	spec := system.SystemSpecs()[0]

	zkDocument, err := system.GenerateProof(spec, *document, transcript, time.Now())
	require.NoError(t, err)

	require.NoError(t, system.VerifyProof(*zkDocument, spec, transcript))

	// Everything the verifier checks against must match what was proved.
	require.Equal(t, native.lastProve.Circuit, native.lastVerify.Circuit)
	require.Equal(t, native.lastProve.DocType, native.lastVerify.DocType)
	require.Equal(t, native.lastProve.IssuerKeyX, native.lastVerify.IssuerKeyX)
	require.Equal(t, native.lastProve.IssuerKeyY, native.lastVerify.IssuerKeyY)
	require.Equal(t, native.lastProve.Transcript, native.lastVerify.Transcript)
	require.Equal(t, native.lastProve.Attributes, native.lastVerify.Attributes)
	require.Equal(t, []byte("a proof"), native.lastVerify.Proof)
}

func TestVerifyProofSurfacesARejection(t *testing.T) {
	system, native := newFakeProverSystem(t)
	native.verifyErr = fmt.Errorf("merkle_check failed")
	_, document, transcript := provableDocument(t)
	spec := system.SystemSpecs()[0]

	zkDocument, err := system.GenerateProof(spec, *document, transcript, time.Now())
	require.NoError(t, err)
	require.ErrorContains(t, system.VerifyProof(*zkDocument, spec, transcript), "merkle_check failed")
}

// ============================================================
// The ordering invariant
// ============================================================

// The native verifier's attribute array is positional, so prover and verifier
// have to build the same list in the same order or a sound proof is rejected.
// Within a namespace that is the wire order; across namespaces it cannot be,
// because IssuerSigned.NameSpaces is a Go map and ranging over one is
// deliberately randomised.
//
// This is the test that would catch someone "simplifying" the sort away: run it
// enough times that a map-order dependency cannot survive.
func TestProveAndVerifyAgreeOnAttributeOrderAcrossNamespaces(t *testing.T) {
	document := MDoc{
		DocType: "eu.europa.ec.av.1",
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{
				"c.namespace": {issuerSignedItemFor(t, 1, "c_one"), issuerSignedItemFor(t, 2, "c_two")},
				"a.namespace": {issuerSignedItemFor(t, 3, "a_one")},
				"b.namespace": {issuerSignedItemFor(t, 4, "b_one"), issuerSignedItemFor(t, 5, "b_two")},
			},
		},
	}

	var first []zk.Attribute
	for range 50 {
		elements, err := orderedElements(document)
		require.NoError(t, err)
		proved := zkAttributesOf(elements)

		// What the verifier rebuilds from the cleartext half of the document.
		rebuilt := zkAttributesOfSigned(signedItemsOf(elements))
		require.Equal(t, proved, rebuilt, "prover and verifier disagree on attribute order")

		if first == nil {
			first = proved
			continue
		}
		require.Equal(t, first, proved, "attribute order is not stable across runs")
	}

	// Namespaces sorted, wire order preserved within each.
	require.Equal(t,
		[]string{"a_one", "b_one", "b_two", "c_one", "c_two"},
		identifiersOf(first))
}

func TestOrderedElementsRefusesADocumentWithNothingToProve(t *testing.T) {
	_, err := orderedElements(MDoc{DocType: "eu.europa.ec.av.1"})
	require.ErrorContains(t, err, "discloses no elements")
}

// issuerSignedItemFor builds one tag-24 wrapped IssuerSignedItem.
func issuerSignedItemFor(t *testing.T, digestID uint64, identifier string) Tag24Item {
	t.Helper()
	encoded, err := cbor.Marshal(IssuerSignedItem{
		DigestID:          digestID,
		Random:            make([]byte, 16),
		ElementIdentifier: identifier,
		ElementValue:      true,
	})
	require.NoError(t, err)

	wrapped, err := cbor.Marshal(cbor.Tag{Number: 24, Content: encoded})
	require.NoError(t, err)
	return Tag24Item{EncodedItem: wrapped}
}

func identifiersOf(attributes []zk.Attribute) []string {
	identifiers := make([]string, 0, len(attributes))
	for _, attribute := range attributes {
		identifiers = append(identifiers, attribute.Identifier)
	}
	return identifiers
}
