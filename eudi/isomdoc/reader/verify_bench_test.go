package reader_test

import (
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/stretchr/testify/require"
)

// ============================================================
// WHAT THE RELYING PARTY PAYS AROUND THE PROOF
// ============================================================
//
// BenchmarkVerifyPlumbing measures Builder.Verify with the cryptography of the
// proof itself taken out: decoding a realistically sized DeviceResponse,
// validating its shape, establishing the issuer chain, and checking the docType.
//
// It deliberately does NOT measure proof verification, and cannot. irmago never
// compiles C++ — see the note in eudi/credentials/mdoc/zkp_irmago_vector_test.go
// — so the real longfellow verifier cannot be linked into this package at all.
// VerifyProof here is acceptingSystem's, which returns nil immediately. The real
// figure lives in longfellow-go's BenchmarkVerify, which links the native
// library.
//
// That split is the point rather than a limitation. The two costs sit on either
// side of the cgo boundary and are worth knowing separately: this benchmark
// answers "what does the relying party spend that is not cryptography", and the
// honest expectation is that it is a rounding error next to the proof check. A
// number that came out otherwise would be a finding.
//
// The proof payload is sized like a real one. A 4-byte stand-in, as the
// correctness tests use, would make the CBOR decode look free — and decoding
// ~360 KB is most of what this benchmark measures.

// benchProofSize is what the v7/1-attribute circuit actually produces: 360,756
// bytes for the fixture in eudi/credentials/mdoc/testdata. Rounded, because the
// exact value is a property of one circuit rather than of the encoding.
const benchProofSize = 360_000

// zkResponseSized is zkResponse with a proof of the given size, so the decode
// cost is the one a deployment would pay.
func zkResponseSized(
	tb testing.TB, specID, docType string, chain []*x509.Certificate, now time.Time, proofBytes int,
) []byte {
	tb.Helper()

	// Random rather than zeroes: CBOR does not compress, but a run of zeroes is
	// the kind of input that flatters a memcpy-heavy decoder.
	proof := make([]byte, proofBytes)
	_, err := rand.Read(proof)
	require.NoError(tb, err)

	document := mdoc.ZkDocument{
		DocumentData: mdoc.NewZkDocumentData(specID, docType, now, map[string][]mdoc.ZkSignedItem{
			docType: {{ElementIdentifier: "age_over_18", ElementValue: cbor.RawMessage{0xf5}}},
		}, chain),
		Proof: proof,
	}
	encoded, err := mdoc.NewDeviceResponse().WithZkDocuments(document).Encode()
	require.NoError(tb, err)
	return encoded
}

// BenchmarkVerifyPlumbing is the whole Verify path over one ZK document, with a
// realistically sized proof and a stand-in proof verifier.
func BenchmarkVerifyPlumbing(b *testing.B) {
	trusted := newIssuer(b, "trusted")
	builder := verifyingBuilder(b, []*x509.Certificate{trusted.root})

	request, err := builder.Build(testOrigin, testDocType, testElements())
	require.NoError(b, err)

	now := time.Now()
	response := zkResponseSized(b, testSpecs()[0].ID, testDocType, trusted.chain, now, benchProofSize)

	b.SetBytes(int64(len(response)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		verified, err := builder.Verify(request, response, testDocType, now)
		if err != nil {
			b.Fatal(err)
		}
		if len(verified) != 1 {
			b.Fatalf("expected one verified document, got %d", len(verified))
		}
	}
}

// BenchmarkVerifyDecodeOnly isolates the CBOR decode, so the issuer chain work
// can be read as the difference between this and BenchmarkVerifyPlumbing rather
// than guessed at.
func BenchmarkVerifyDecodeOnly(b *testing.B) {
	trusted := newIssuer(b, "trusted")
	response := zkResponseSized(
		b, testSpecs()[0].ID, testDocType, trusted.chain, time.Now(), benchProofSize)

	b.SetBytes(int64(len(response)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var decoded mdoc.DeviceResponse
		if err := cbor.Unmarshal(response, &decoded); err != nil {
			b.Fatal(err)
		}
		if len(decoded.ZkDocuments) != 1 {
			b.Fatalf("expected one zkDocument, got %d", len(decoded.ZkDocuments))
		}
	}
}
