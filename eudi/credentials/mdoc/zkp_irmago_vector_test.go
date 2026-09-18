package mdoc

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ============================================================
// OUR OWN ZK VECTOR — a presentation this package produced
// ============================================================
//
// zkp_multipaz_vector_test.go runs Multipaz's bytes through our decoder. This is
// the other direction: a presentation built by THIS package, around a proof the
// real longfellow library produced over a credential this package issued.
//
// #724 Phase 1's gate is that symmetry — "a proof generated here verifies under
// Google's reference verifier, and one of Google's vectors verifies here". A
// decoder that is wrong in the same way as its encoder passes every test that
// only ever round-trips through itself.
//
// # How testdata/irmago_zk_deviceresponse.cbor was made
//
// Three stages, split because cgo must never enter irmago (#724: "irmago never
// compiles C++ — not even in a tagged job"). Programs live in the longfellow-go
// scaffolding, not here:
//
//	A. gen   (in irmago)   issues an eu.europa.ec.av.1 credential with
//	                       NewTestIssuer, signs deviceAuth over a DC API session
//	                       transcript, emits inputs.json
//	B. prove (in the container) loads the v6/1-attribute circuit, verifies it with
//	                       circuit_id, runs run_mdoc_prover, and verifies its own
//	                       output before writing proof.bin
//	C. wrap  (in irmago)   builds ZkDocument + DeviceResponse with this package
//
// Two properties of the fixture are deliberate and distinguish it from the
// Multipaz one:
//
//   - docType is eu.europa.ec.av.1, not org.iso.18013.5.1.mDL — the profile this
//     wallet actually implements.
//   - the transcript is the DC API handover, not a proximity one. The AV profile
//     mandates the DC API; the Multipaz fixture is proximity, so this covers a
//     shape nothing else did.
//
// The proof is not re-verified here and cannot be: that needs the native prover
// this build does not have. Two things outside this package did verify it:
//
//   - stage B, at the point the proof was made; and
//   - GOOGLE'S REFERENCE VERIFIER, which parsed this exact fixture with its own
//     CBOR code, recovered the issuer key from our msoX5chain, and accepted the
//     proof. That is #724 Phase 1's gate, and it is why these tests may assert
//     on shape alone without being a decoder that agrees only with its encoder.
//
// Regenerate with longfellow-go's verify-zk-pipeline.ps1, which reruns all four
// stages including that verification. Every run produces a WHOLLY DIFFERENT
// blob — a fresh issuer key and fresh proof randomness — so refresh the fixture
// only when the encoding changes, never routinely.

const irmagoVector = "testdata/irmago_zk_deviceresponse.cbor"

func irmagoZkResponse(t *testing.T) DeviceResponse {
	t.Helper()

	raw, err := os.ReadFile(irmagoVector)
	require.NoError(t, err)

	var response DeviceResponse
	require.NoError(t, Unmarshal(raw, &response))
	return response
}

// TestIrmagoZkVectorShape pins what this package emits for a ZK presentation.
func TestIrmagoZkVectorShape(t *testing.T) {
	response := irmagoZkResponse(t)

	require.Equal(t, DeviceResponseVersionZk, response.Version,
		"a response carrying zkDocuments is a second-edition response")
	require.Equal(t, ResponseStatusOK, response.Status)
	require.Empty(t, response.Documents, "a proof replaces the disclosure")
	require.Len(t, response.ZkDocuments, 1)

	document := response.ZkDocuments[0]
	require.Greater(t, len(document.Proof), 100_000,
		"a longfellow proof is hundreds of kilobytes")

	data := document.DocumentData
	require.Equal(t, AgeVerificationDocType, data.DocType)
	require.Equal(t, "longfellow-libzk-v1_6_1_4096_2945_"+
		"137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
		data.ZkSystemSpecID)
	require.False(t, data.Timestamp.IsZero())
	require.Equal(t, data.Timestamp.UTC().Truncate(time.Second), data.Timestamp.UTC(),
		"10.2.7 types the timestamp as tdate; whole seconds is what the prover was given")
}

// TestIrmagoZkVectorCarriesTheIssuerChain: a verifier cannot extract the issuer
// key from a ZK presentation the way it would from a disclosure — the MSO is
// hidden by the proof. msoX5chain is how it learns the key the proof was made
// against, which is #724's open question O2.
func TestIrmagoZkVectorCarriesTheIssuerChain(t *testing.T) {
	data := irmagoZkResponse(t).ZkDocuments[0].DocumentData

	require.Len(t, data.MsoX5Chain, 2, "leaf plus its IACA")
	leaf := data.MsoX5Chain[0]
	require.NotNil(t, leaf.PublicKey)
	require.Equal(t, "Test Age Verification DS - 001", leaf.Subject.CommonName,
		"the leaf is the document signer whose key the proof was taken against")
	require.NoError(t, leaf.CheckSignatureFrom(data.MsoX5Chain[1]),
		"the chain must actually chain")
}

// TestIrmagoZkVectorDisclosesOnlyWhatWasProved: the cleartext half names exactly
// the element the proof is about. Anything else here would be disclosed in the
// clear by a presentation whose entire point is not disclosing it.
func TestIrmagoZkVectorDisclosesOnlyWhatWasProved(t *testing.T) {
	data := irmagoZkResponse(t).ZkDocuments[0].DocumentData

	require.Len(t, data.IssuerSigned, 1)
	items := data.IssuerSigned[AgeVerificationNameSpace]
	require.Len(t, items, 1)
	require.Equal(t, "age_over_18", items[0].ElementIdentifier)
	require.Equal(t, []byte{0xf5}, []byte(items[0].ElementValue), "CBOR true")

	require.Empty(t, data.DeviceSigned,
		"the AV profile has no holder-asserted claims")
}

// TestIrmagoZkVectorRoundTrips: decode and re-encode reproduces the file exactly.
//
// This is a stronger claim than 18013-5 requires and is only true of OUR OWN
// fixture. 8.1 waives canonical map ordering — "the fourth rule regarding
// sorting of map keys is not required" — so a conformant peer may order maps
// differently, and the Multipaz vector accordingly does not reproduce byte for
// byte at the top level. What must hold for both, and does, is that the tag-24
// zkDocumentData is passed through as received; see
// TestMultipazZkDocumentDataBytesArePreserved.
//
// Asserting the whole file here is worth it because every byte of it was
// produced by this package: the outer DeviceResponse map by our encoder, the
// zkDocumentData by preservation. A difference therefore means our own encoding
// drifted, which is exactly what a committed fixture is for.
func TestIrmagoZkVectorRoundTrips(t *testing.T) {
	raw, err := os.ReadFile(irmagoVector)
	require.NoError(t, err)

	var decoded DeviceResponse
	require.NoError(t, Unmarshal(raw, &decoded))

	reEncoded, err := decoded.Encode()
	require.NoError(t, err)
	require.Equal(t, raw, reEncoded,
		"a fixture this package wrote must re-encode to itself, byte for byte")

	var reDecoded DeviceResponse
	require.NoError(t, Unmarshal(reEncoded, &reDecoded))
	require.Equal(t, decoded.ZkDocuments[0].Proof, reDecoded.ZkDocuments[0].Proof)
	require.Equal(t, decoded.ZkDocuments[0].DocumentData, reDecoded.ZkDocuments[0].DocumentData)
}
