package mdoc

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// The ZK wire format has no readable normative source in the 2021 edition of
// ISO/IEC 18013-5 and the second edition is a paywalled draft, so these tests
// assert against Multipaz's byte shapes (org.multipaz.mdoc.zkp), which is the
// reference the AV interop events run against. Where a test names a key or a
// tag, that name or tag came from Multipaz's Kotlin source, not from a guess
// about what it ought to be.

func zkTestSpec() ZkSystemSpec {
	return ZkSystemSpec{
		ID:     "longfellow-libzk-v1_7_1_4151_4096_8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121",
		System: ZkSystemLongfellowV1,
		Params: map[string]any{
			ZkParamCircuitHash:   "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121",
			ZkParamVersion:       uint64(7),
			ZkParamNumAttributes: uint64(1),
			ZkParamBlockEncHash:  uint64(4151),
			ZkParamBlockEncSig:   uint64(4096),
		},
	}
}

func TestZkSystemSpecTypedParams(t *testing.T) {
	spec := zkTestSpec()

	hash, ok := spec.CircuitHash()
	require.True(t, ok)
	require.Equal(t, "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121", hash)

	version, ok := spec.Version()
	require.True(t, ok)
	require.Equal(t, int64(7), version)

	count, ok := spec.NumAttributes()
	require.True(t, ok)
	require.Equal(t, int64(1), count)

	_, ok = spec.StringParam("nonexistent")
	require.False(t, ok)
	_, ok = spec.IntParam(ZkParamCircuitHash)
	require.False(t, ok, "a string parameter must not read back as an integer")
}

// TestZkSystemSpecSameCircuitIgnoresID pins the decision that circuit identity
// is the parameters, not the label: the reader and the wallet build their specs
// independently and only the parameters are guaranteed to agree.
func TestZkSystemSpecSameCircuitIgnoresID(t *testing.T) {
	mine := zkTestSpec()

	theirs := zkTestSpec()
	theirs.ID = "some-other-implementations-label"
	require.True(t, mine.SameCircuit(theirs))

	otherHash := zkTestSpec()
	otherHash.Params[ZkParamCircuitHash] = "0000000000000000000000000000000000000000000000000000000000000000"
	require.False(t, mine.SameCircuit(otherHash))

	otherCount := zkTestSpec()
	otherCount.Params[ZkParamNumAttributes] = uint64(4)
	require.False(t, mine.SameCircuit(otherCount))

	otherSystem := zkTestSpec()
	otherSystem.System = "some-other-zk-system"
	require.False(t, mine.SameCircuit(otherSystem))
}

func TestZkRequestRoundTrip(t *testing.T) {
	request := ZkRequest{SystemSpecs: []ZkSystemSpec{zkTestSpec()}, ZkRequired: true}

	encoded, err := cbor.Marshal(request)
	require.NoError(t, err)

	var decoded ZkRequest
	require.NoError(t, cbor.Unmarshal(encoded, &decoded))
	require.True(t, decoded.ZkRequired)
	require.Len(t, decoded.SystemSpecs, 1)
	require.Equal(t, request.SystemSpecs[0].ID, decoded.SystemSpecs[0].ID)
	require.Equal(t, request.SystemSpecs[0].System, decoded.SystemSpecs[0].System)
	require.True(t, request.SystemSpecs[0].SameCircuit(decoded.SystemSpecs[0]))
}

// TestZkRequestUsesMultipazKeyNames checks the three key names a reader and a
// wallet have to agree on before anything else can work.
func TestZkRequestUsesMultipazKeyNames(t *testing.T) {
	encoded, err := cbor.Marshal(ZkRequest{SystemSpecs: []ZkSystemSpec{zkTestSpec()}})
	require.NoError(t, err)

	var generic map[string]any
	require.NoError(t, cbor.Unmarshal(encoded, &generic))
	require.Contains(t, generic, "systemSpecs")
	require.Contains(t, generic, "zkRequired")

	specs, ok := generic["systemSpecs"].([]any)
	require.True(t, ok)
	require.Len(t, specs, 1)
	spec, ok := specs[0].(map[any]any)
	require.True(t, ok)
	require.Contains(t, spec, "zkSystemId")
	require.Contains(t, spec, "system")
	require.Contains(t, spec, "params")
}

// TestZkRequestDefaultsToFallbackAllowed documents the profile's normal
// posture: unless the reader says otherwise, a wallet that cannot prove is
// expected to present the plain A.6 mdoc rather than fail.
func TestZkRequestDefaultsToFallbackAllowed(t *testing.T) {
	encoded, err := cbor.Marshal(ZkRequest{SystemSpecs: []ZkSystemSpec{zkTestSpec()}})
	require.NoError(t, err)

	var decoded ZkRequest
	require.NoError(t, cbor.Unmarshal(encoded, &decoded))
	require.False(t, decoded.ZkRequired)
}

func zkTestDocumentData(t *testing.T, chain []*x509.Certificate) ZkDocumentData {
	t.Helper()

	// A CBOR `true`, encoded the way an IssuerSignedItem would carry it.
	trueValue, err := cbor.Marshal(true)
	require.NoError(t, err)

	return NewZkDocumentData(
		zkTestSpec().ID,
		"eu.europa.ec.av.1",
		time.Date(2026, 9, 15, 12, 30, 45, 123456789, time.UTC),
		map[string][]ZkSignedItem{
			"eu.europa.ec.av.1": {{ElementIdentifier: "age_over_18", ElementValue: trueValue}},
		},
		chain,
	)
}

func TestZkDocumentRoundTrip(t *testing.T) {
	issuer, err := NewTestIssuer()
	require.NoError(t, err)
	chain := []*x509.Certificate{issuer.DSCert()}

	document := ZkDocument{
		DocumentData: zkTestDocumentData(t, chain),
		Proof:        []byte{0x01, 0x02, 0x03, 0x04},
	}

	encoded, err := cbor.Marshal(document)
	require.NoError(t, err)

	var decoded ZkDocument
	require.NoError(t, cbor.Unmarshal(encoded, &decoded))

	require.Equal(t, document.Proof, decoded.Proof)
	require.Equal(t, document.DocumentData.ZkSystemSpecID, decoded.DocumentData.ZkSystemSpecID)
	require.Equal(t, document.DocumentData.DocType, decoded.DocumentData.DocType)
	require.Equal(t, document.DocumentData.IssuerSigned, decoded.DocumentData.IssuerSigned)
	require.Empty(t, decoded.DocumentData.DeviceSigned["eu.europa.ec.av.1"])
	require.Len(t, decoded.DocumentData.MsoX5Chain, 1)
	require.Equal(t, issuer.DSCert().Raw, decoded.DocumentData.MsoX5Chain[0].Raw)
}

// TestZkDocumentDataTimestampIsWholeSecondsTdate covers both halves of the
// timestamp rule at once: the Longfellow prover formats the instant as a
// 20-character string with no fractional part, and 10.2.7 types the field as a
// tdate, which is CBOR tag 0 around an RFC 3339 string rather than the bare
// epoch integer the CBOR library would produce by default.
func TestZkDocumentDataTimestampIsWholeSecondsTdate(t *testing.T) {
	data := zkTestDocumentData(t, nil)
	require.Equal(t, 0, data.Timestamp.Nanosecond(), "constructor must truncate to whole seconds")

	encoded, err := cbor.Marshal(data)
	require.NoError(t, err)

	var generic map[string]any
	require.NoError(t, cbor.Unmarshal(encoded, &generic))

	timestamp, ok := generic["timestamp"].(time.Time)
	require.True(t, ok, "timestamp decoded as %T, so it is not a tagged date-time", generic["timestamp"])
	require.Equal(t, "2026-09-15T12:30:45Z", timestamp.UTC().Format(time.RFC3339))
}

// TestZkDocumentDataPreservesElementValueBytes is the reason ElementValue is
// cbor.RawMessage. A full-date is CBOR tag 1004 around a string; decoding that
// into `any` and re-encoding is not guaranteed to reproduce the tag, and the
// bytes are part of the statement the circuit proves, so a changed encoding is
// a verification failure with nothing naming the cause.
func TestZkDocumentDataPreservesElementValueBytes(t *testing.T) {
	fullDate, err := cbor.Marshal(cbor.Tag{Number: 1004, Content: "2001-09-01"})
	require.NoError(t, err)

	data := NewZkDocumentData(
		zkTestSpec().ID,
		"org.iso.18013.5.1.mDL",
		time.Now(),
		map[string][]ZkSignedItem{
			"org.iso.18013.5.1": {{ElementIdentifier: "birth_date", ElementValue: fullDate}},
		},
		nil,
	)

	encoded, err := cbor.Marshal(data)
	require.NoError(t, err)

	var decoded ZkDocumentData
	require.NoError(t, cbor.Unmarshal(encoded, &decoded))
	require.Equal(t,
		[]byte(fullDate),
		[]byte(decoded.IssuerSigned["org.iso.18013.5.1"][0].ElementValue),
		"element value bytes must survive the round trip unchanged")
}

// TestZkDocumentDataEncodingIsDeterministic guards the SortCanonical setting on
// zkEncMode. Without it the namespace maps serialize in Go's randomized map
// order and the same document produces different bytes on consecutive calls.
func TestZkDocumentDataEncodingIsDeterministic(t *testing.T) {
	value, err := cbor.Marshal(true)
	require.NoError(t, err)

	data := NewZkDocumentData(
		zkTestSpec().ID,
		"eu.europa.ec.av.1",
		time.Now(),
		map[string][]ZkSignedItem{
			"eu.europa.ec.av.1": {{ElementIdentifier: "age_over_18", ElementValue: value}},
			"org.iso.18013.5.1": {{ElementIdentifier: "age_over_18", ElementValue: value}},
			"com.example.other": {{ElementIdentifier: "age_over_21", ElementValue: value}},
		},
		nil,
	)

	first, err := cbor.Marshal(data)
	require.NoError(t, err)
	for range 20 {
		again, err := cbor.Marshal(data)
		require.NoError(t, err)
		require.Equal(t, first, again)
	}
}

// TestZkDocumentWrapsDocumentDataInTag24 pins the envelope shape: proof as a
// byte string, documentData as tag 24 around the encoded map. A verifier
// written against Multipaz reads exactly this and nothing else.
func TestZkDocumentWrapsDocumentDataInTag24(t *testing.T) {
	document := ZkDocument{
		DocumentData: zkTestDocumentData(t, nil),
		Proof:        []byte{0xde, 0xad, 0xbe, 0xef},
	}

	encoded, err := cbor.Marshal(document)
	require.NoError(t, err)

	var generic map[string]any
	require.NoError(t, cbor.Unmarshal(encoded, &generic))

	proof, ok := generic["proof"].([]byte)
	require.True(t, ok)
	require.Equal(t, document.Proof, proof)

	tagged, ok := generic["documentData"].(cbor.Tag)
	require.True(t, ok, "documentData decoded as %T, so it is not tagged", generic["documentData"])
	require.Equal(t, uint64(24), tagged.Number)
}

// TestZkDocumentDataCertChainShape covers the asymmetry Multipaz's
// X509CertChain imposes: one certificate encodes as a bare byte string, several
// as an array of them. A verifier that only understands the array form rejects
// every real AV presentation, which carries exactly one DS certificate.
func TestZkDocumentDataCertChainShape(t *testing.T) {
	issuer, err := NewTestIssuer()
	require.NoError(t, err)

	t.Run("single certificate is a bare byte string", func(t *testing.T) {
		data := zkTestDocumentData(t, []*x509.Certificate{issuer.DSCert()})
		encoded, err := cbor.Marshal(data)
		require.NoError(t, err)

		var generic map[string]any
		require.NoError(t, cbor.Unmarshal(encoded, &generic))
		chain, ok := generic["msoX5chain"].([]byte)
		require.True(t, ok, "msoX5chain decoded as %T", generic["msoX5chain"])
		require.Equal(t, issuer.DSCert().Raw, chain)

		var decoded ZkDocumentData
		require.NoError(t, cbor.Unmarshal(encoded, &decoded))
		require.Len(t, decoded.MsoX5Chain, 1)
	})

	t.Run("several certificates are an array", func(t *testing.T) {
		data := zkTestDocumentData(t, []*x509.Certificate{issuer.DSCert(), issuer.IACACert()})
		encoded, err := cbor.Marshal(data)
		require.NoError(t, err)

		var generic map[string]any
		require.NoError(t, cbor.Unmarshal(encoded, &generic))
		chain, ok := generic["msoX5chain"].([]any)
		require.True(t, ok, "msoX5chain decoded as %T", generic["msoX5chain"])
		require.Len(t, chain, 2)

		var decoded ZkDocumentData
		require.NoError(t, cbor.Unmarshal(encoded, &decoded))
		require.Len(t, decoded.MsoX5Chain, 2)
		require.Equal(t, issuer.DSCert().Raw, decoded.MsoX5Chain[0].Raw)
		require.Equal(t, issuer.IACACert().Raw, decoded.MsoX5Chain[1].Raw)
	})

	t.Run("no chain omits the key", func(t *testing.T) {
		encoded, err := cbor.Marshal(zkTestDocumentData(t, nil))
		require.NoError(t, err)

		var generic map[string]any
		require.NoError(t, cbor.Unmarshal(encoded, &generic))
		require.NotContains(t, generic, "msoX5chain")
	})
}

func TestZkDocumentRejectsMissingProof(t *testing.T) {
	inner, err := zkTestDocumentData(t, nil).MarshalCBOR()
	require.NoError(t, err)
	wrapped, err := tag24WrapBytes(inner)
	require.NoError(t, err)

	encoded, err := cbor.Marshal(zkDocumentWire{Proof: nil, DocumentData: wrapped})
	require.NoError(t, err)

	var decoded ZkDocument
	require.ErrorContains(t, cbor.Unmarshal(encoded, &decoded), "no proof")
}

// TestDeviceResponseCarriesZkDocuments checks that a proof-only response
// travels without an empty `documents` array beside it, and that a plain
// response is unchanged by the addition of the new field.
func TestDeviceResponseCarriesZkDocuments(t *testing.T) {
	response := NewZkDeviceResponse(ZkDocument{
		DocumentData: zkTestDocumentData(t, nil),
		Proof:        []byte{0x01},
	})

	encoded, err := cbor.Marshal(response)
	require.NoError(t, err)

	var generic map[string]any
	require.NoError(t, cbor.Unmarshal(encoded, &generic))
	require.Contains(t, generic, "zkDocuments")
	require.NotContains(t, generic, "documents")

	var decoded DeviceResponse
	require.NoError(t, Unmarshal(encoded, &decoded))
	require.Len(t, decoded.ZkDocuments, 1)
	require.Equal(t, "eu.europa.ec.av.1", decoded.ZkDocuments[0].DocumentData.DocType)
}
