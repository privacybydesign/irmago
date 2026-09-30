package mdoc

import (
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// These tests check this package's ZK structures against captured wire samples
// from a real Age Verification exchange — a DeviceRequest carrying a zkRequest
// and the DeviceResponse that answered it. They are the closest thing to a
// normative reference available: the second edition of ISO/IEC 18013-5 is not
// published, only a draft in ballot, so the AV profile's own traffic is what
// conformance is measured against.
//
// Everything below is transcribed from those samples. Where a test asserts a
// key name, a tag number or a parameter value, that is what the sample shows.

// avSampleDSCertificate is the msoX5chain from the captured response: the AV
// reference implementation's document signer, issued by "Age Verification
// Issuer CA 01".
const avSampleDSCertificate = "308202bd30820263a00302010202147076c1d015eabc3fd67b3fd7aa78a6cfe3cd2f85" +
	"300a06082a8648ce3d04030230693126302406035504030c1d41676520566572696669636174696f6e2049737375" +
	"657220434120303131323030060355040a0c2941676520566572696669636174696f6e205265666572656e636520" +
	"496d706c656d656e746174696f6e310b3009060355040613024555301e170d3235303730313130353731315a170d" +
	"3236303932343130353731305a30653122302006035504030c1941676520566572696669636174696f6e204453202" +
	"d2030303131323030060355040a0c2941676520566572696669636174696f6e205265666572656e636520496d706c" +
	"656d656e746174696f6e310b30090603550406130245553059301306072a8648ce3d020106082a8648ce3d0301070" +
	"34200046789e96e797e2e04f7f3cbb54a12410412410db000fb6d63dc977d8b5d35a4f93b71f297d9d308ba2e955e" +
	"8563afa0604833aae10ecb1aaefbe4159b5b8b9057a381ec3081e9301f0603551d23041830168014cb7095804c991" +
	"edc6d0b7cfeebe041ca22542ed830160603551d250101ff040c300a06082b8102020000010230440603551d1f043d" +
	"303b3039a037a035863368747470733a2f2f6973737565722e616765766572696669636174696f6e2e6465762f706" +
	"b692f45555f43415f30312e63726c301d0603551d0e04160414ff1bba97b2ca7ef5aea3301486f1fbc98b4598fa30" +
	"0e0603551d0f0101ff04040302078030390603551d12043230300603551d1204293027822568747470733a2f2f636" +
	"f6d6d697373696f6e2e6575726f70612e65752f696e6465785f656e300a06082a8648ce3d04030203480030450220" +
	"4aaf5b867e6f1202e0f4924de8b689319471f9ce6b3b9cb7355fa68a014e2637022100ddb326b3c089df558f5732e" +
	"aaa5e87c0d5d5140624602f3598afdabf180db66a"

// avSampleSpecs are the four circuits the captured reader offered: longfellow
// v6 for one through four attributes. Note the parameter order encoded in the
// identifier — <version>_<numAttributes>_<blockEncHash>_<blockEncSig>_<hash> —
// which is the order Multipaz's circuit filenames use and is easy to transpose.
func avSampleSpecs() []ZkSystemSpec {
	spec := func(id string, version, count, blockEncHash, blockEncSig uint64, hash string) ZkSystemSpec {
		return ZkSystemSpec{
			ID:     id,
			System: ZkSystemLongfellowV1,
			Params: map[string]any{
				ZkParamVersion:       version,
				ZkParamCircuitHash:   hash,
				ZkParamNumAttributes: count,
				ZkParamBlockEncHash:  blockEncHash,
				ZkParamBlockEncSig:   blockEncSig,
			},
		}
	}
	return []ZkSystemSpec{
		spec("longfellow-libzk-v1_6_1_4096_2945_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
			6, 1, 4096, 2945, "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6"),
		spec("longfellow-libzk-v1_6_2_4025_2945_b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e",
			6, 2, 4025, 2945, "b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e"),
		spec("longfellow-libzk-v1_6_3_4121_2945_b2211223b954b34a1081e3fbf71b8ea2de28efc888b4be510f532d6ba76c2010",
			6, 3, 4121, 2945, "b2211223b954b34a1081e3fbf71b8ea2de28efc888b4be510f532d6ba76c2010"),
		spec("longfellow-libzk-v1_6_4_4283_2945_c70b5f44a1365c53847eb8948ad5b4fdc224251a2bc02d958c84c862823c49d6",
			6, 4, 4283, 2945, "c70b5f44a1365c53847eb8948ad5b4fdc224251a2bc02d958c84c862823c49d6"),
	}
}

// TestAVSampleZkRequestRoundTrip checks the request half against the capture:
// the four offered circuits survive a round trip with every parameter intact,
// and zkRequired is false — the reader accepting the plain A.6 fallback, which
// is the profile's normal posture.
func TestAVSampleZkRequestRoundTrip(t *testing.T) {
	request := ZkRequest{SystemSpecs: avSampleSpecs(), ZkRequired: false}

	encoded, err := cbor.Marshal(request)
	require.NoError(t, err)

	var decoded ZkRequest
	require.NoError(t, cbor.Unmarshal(encoded, &decoded))

	require.False(t, decoded.ZkRequired)
	require.Len(t, decoded.SystemSpecs, 4)

	for i, want := range avSampleSpecs() {
		got := decoded.SystemSpecs[i]
		require.Equal(t, want.ID, got.ID)
		require.Equal(t, ZkSystemLongfellowV1, got.System)
		require.True(t, want.SameCircuit(got))

		version, ok := got.Version()
		require.True(t, ok)
		require.Equal(t, int64(6), version)

		count, ok := got.NumAttributes()
		require.True(t, ok)
		require.Equal(t, int64(i+1), count)

		blockEncHash, ok := got.IntParam(ZkParamBlockEncHash)
		require.True(t, ok)
		wantBlockEncHash, _ := want.IntParam(ZkParamBlockEncHash)
		require.Equal(t, wantBlockEncHash, blockEncHash)

		blockEncSig, ok := got.IntParam(ZkParamBlockEncSig)
		require.True(t, ok)
		require.Equal(t, int64(2945), blockEncSig)
	}
}

// TestAVSampleSelectsOneAttributeCircuit is the decision the captured exchange
// actually made: a request for the single element age_over_18, answered under
// the one-attribute circuit out of the four on offer.
func TestAVSampleSelectsOneAttributeCircuit(t *testing.T) {
	held := avSampleSpecs()
	repository := NewZkSystemRepository(&fakeZkSystem{name: ZkSystemLongfellowV1, specs: held})

	system, spec, ok := repository.SelectProver(ZkRequest{SystemSpecs: held}, 1)
	require.True(t, ok)
	require.Equal(t, ZkSystemLongfellowV1, system.Name())
	require.Equal(t, held[0].ID, spec.ID)

	hash, _ := spec.CircuitHash()
	require.Equal(t, "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6", hash)
}

func avSampleZkDocument(t *testing.T) ZkDocument {
	t.Helper()

	der, err := hex.DecodeString(avSampleDSCertificate)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	trueValue, err := cbor.Marshal(true)
	require.NoError(t, err)

	timestamp, err := time.Parse(time.RFC3339, "2026-02-05T08:44:59Z")
	require.NoError(t, err)

	return ZkDocument{
		DocumentData: NewZkDocumentData(
			"longfellow-libzk-v1_6_1_4096_2945_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
			"eu.europa.ec.av.1",
			timestamp,
			map[string][]ZkSignedItem{
				"eu.europa.ec.av.1": {{ElementIdentifier: "age_over_18", ElementValue: trueValue}},
			},
			[]*x509.Certificate{cert},
		),
		// The captured proof is ~90 KB; its bytes are opaque to this package,
		// so a short stand-in exercises the envelope just as well.
		Proof: []byte{0xb3, 0x03, 0x08, 0xf8},
	}
}

// TestAVSampleZkDocumentShape checks the response half key by key against the
// capture.
func TestAVSampleZkDocumentShape(t *testing.T) {
	document := avSampleZkDocument(t)

	encoded, err := cbor.Marshal(document)
	require.NoError(t, err)

	var envelope map[string]any
	require.NoError(t, cbor.Unmarshal(encoded, &envelope))
	require.Len(t, envelope, 2)

	proof, ok := envelope["proof"].([]byte)
	require.True(t, ok, "proof decoded as %T", envelope["proof"])
	require.Equal(t, document.Proof, proof)

	tagged, ok := envelope["documentData"].(cbor.Tag)
	require.True(t, ok, "documentData decoded as %T", envelope["documentData"])
	require.Equal(t, uint64(24), tagged.Number)

	inner, ok := tagged.Content.([]byte)
	require.True(t, ok)

	var data map[string]any
	require.NoError(t, cbor.Unmarshal(inner, &data))

	require.Equal(t,
		"longfellow-libzk-v1_6_1_4096_2945_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
		data["zkSystemId"])
	require.Equal(t, "eu.europa.ec.av.1", data["docType"])

	timestamp, ok := data["timestamp"].(time.Time)
	require.True(t, ok, "timestamp decoded as %T, so it is not a tdate", data["timestamp"])
	require.Equal(t, "2026-02-05T08:44:59Z", timestamp.UTC().Format(time.RFC3339))

	// deviceSigned is present and empty, as in the capture — an absent key and
	// an empty map are different things on the wire.
	require.Contains(t, data, "deviceSigned")
	deviceSigned, ok := data["deviceSigned"].(map[any]any)
	require.True(t, ok, "deviceSigned decoded as %T", data["deviceSigned"])
	require.Empty(t, deviceSigned)

	issuerSigned, ok := data["issuerSigned"].(map[any]any)
	require.True(t, ok)
	elements, ok := issuerSigned["eu.europa.ec.av.1"].([]any)
	require.True(t, ok)
	require.Len(t, elements, 1)
	element, ok := elements[0].(map[any]any)
	require.True(t, ok)
	require.Equal(t, "age_over_18", element["elementIdentifier"])
	require.Equal(t, true, element["elementValue"])

	// A single certificate is a bare byte string, not an array of one.
	der, err := hex.DecodeString(avSampleDSCertificate)
	require.NoError(t, err)
	chain, ok := data["msoX5chain"].([]byte)
	require.True(t, ok, "msoX5chain decoded as %T", data["msoX5chain"])
	require.Equal(t, der, chain)
}

// TestAVSampleZkDocumentDecodes reads the same document back through this
// package's own decoder.
func TestAVSampleZkDocumentDecodes(t *testing.T) {
	encoded, err := cbor.Marshal(avSampleZkDocument(t))
	require.NoError(t, err)

	var decoded ZkDocument
	require.NoError(t, cbor.Unmarshal(encoded, &decoded))

	require.Equal(t, "eu.europa.ec.av.1", decoded.DocumentData.DocType)
	require.Len(t, decoded.DocumentData.MsoX5Chain, 1)

	cert := decoded.DocumentData.MsoX5Chain[0]
	require.Equal(t, "Age Verification DS - 001", cert.Subject.CommonName)
	require.Equal(t, "Age Verification Issuer CA 01", cert.Issuer.CommonName)

	items := decoded.DocumentData.IssuerSigned["eu.europa.ec.av.1"]
	require.Len(t, items, 1)
	require.Equal(t, "age_over_18", items[0].ElementIdentifier)

	var value bool
	require.NoError(t, cbor.Unmarshal(items[0].ElementValue, &value))
	require.True(t, value)
}

// TestAVSampleDeviceResponseShape checks the envelope the document travels in:
// version, zkDocuments, status — and no `documents` key, which is what the
// capture shows for a proof-only response.
func TestAVSampleDeviceResponseShape(t *testing.T) {
	encoded, err := cbor.Marshal(NewZkDeviceResponse(avSampleZkDocument(t)))
	require.NoError(t, err)

	var response map[string]any
	require.NoError(t, cbor.Unmarshal(encoded, &response))

	require.Len(t, response, 3)
	// "1.1", not "1.0". zkDocuments is a second-edition member, so a response
	// carrying one is a second-edition response. This assertion said "1.0" until
	// a DeviceResponse Multipaz actually produced was decoded here and came back
	// 1.1 — see zkp_multipaz_vector_test.go and DeviceResponseVersionZk.
	require.Equal(t, "1.1", response["version"])
	require.Equal(t, uint64(0), response["status"])
	require.NotContains(t, response, "documents")

	documents, ok := response["zkDocuments"].([]any)
	require.True(t, ok)
	require.Len(t, documents, 1)

	var decoded DeviceResponse
	require.NoError(t, Unmarshal(encoded, &decoded))
	require.Empty(t, decoded.Documents)
	require.Len(t, decoded.ZkDocuments, 1)
}
