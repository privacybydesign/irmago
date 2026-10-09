package integrationtest

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/isomdoc"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

// A zero-knowledge presentation must not spend a batch instance, where a plain
// one must. irmago#724 left this open as O4, on the grounds that a proof is
// already unlinkable so burning a scarce credential for it buys nothing; the AV
// technical specification settles it in the bullet that makes single use a
// SHALL:
//
//	Where a Proof of Age attestation is presented as a plain ISO mDoc, the Age
//	Verification App SHALL use a Proof of Age attestation only once and SHALL
//	then remove it from the batch of the issued attestations. An attestation
//	presented as a Zero-Knowledge Proof is not consumed and MAY be reused within
//	its validity period.
//
// This lives in the composition tests rather than beside the other ZK unit
// tests because the defect it guards is in the seam. Session knows which
// document became a proof and WalletDiscloser owns the instances, and neither
// can see the mistake alone: before this, Commit spent everything it had
// reserved and every layer's own tests still passed. What it costs a user is
// concrete — thirty age checks and a batch meant to last three months is empty,
// after which the wallet falls back to the plain disclosure the proof existed
// to avoid.
func TestZkPresentationDoesNotConsumeAnInstance(t *testing.T) {
	t.Run("a proof leaves the batch untouched", func(t *testing.T) {
		env := newEnv(t, 3)
		env.wireProver(zkProverFor(1))
		require.Equal(t, uint(3), env.remaining(t))

		response, err := env.respond(t, env.reader.zkRequest(t, avDocType, avNameSpace, "age_over_18"))
		require.NoError(t, err)

		opened := env.reader.open(t, response)
		require.Len(t, opened.ZkDocuments, 1, "the reader offered a circuit this build holds, so it must get a proof")
		require.Empty(t, opened.Documents, "a proved document must not also travel in the clear")

		require.Equal(t, uint(3), env.remaining(t),
			"an attestation presented as a Zero-Knowledge Proof is not consumed")
	})

	t.Run("the same instance proves again", func(t *testing.T) {
		// The point of not consuming: a batch of one still answers a second
		// request. Spending would have left nothing to prove with.
		env := newEnv(t, 1)
		env.wireProver(zkProverFor(1))

		for attempt := 1; attempt <= 3; attempt++ {
			response, err := env.respond(t, env.reader.zkRequest(t, avDocType, avNameSpace, "age_over_18"))
			require.NoError(t, err, "proof %d", attempt)
			require.Len(t, env.reader.open(t, response).ZkDocuments, 1, "proof %d", attempt)
		}

		require.Equal(t, uint(1), env.remaining(t))
	})

	t.Run("a plain disclosure still spends", func(t *testing.T) {
		// The asymmetry is the whole finding, so the other half is asserted in
		// the same place: a fix that stopped spending altogether would satisfy
		// the cases above and break the SHALL.
		env := newEnv(t, 3)
		env.wireProver(zkProverFor(1))

		_, err := env.respond(t, env.reader.request(t, true, avDocType, avNameSpace, "age_over_18"))
		require.NoError(t, err)

		require.Equal(t, uint(2), env.remaining(t),
			"a plain ISO mDoc presentation SHALL consume its attestation")
	})

	t.Run("a fallback to plain disclosure spends", func(t *testing.T) {
		// The reader asked for a proof and the build cannot make one, so A.8's
		// fallback runs and the document leaves in the clear. It is a plain
		// presentation whatever the reader asked for, and must be consumed as
		// one: deciding from the REQUEST rather than from what was sent would
		// keep an attestation that was disclosed.
		env := newEnv(t, 3)
		env.wireProver(nil) // no prover: this build cannot prove

		response, err := env.respond(t, env.reader.zkRequest(t, avDocType, avNameSpace, "age_over_18"))
		require.NoError(t, err)

		opened := env.reader.open(t, response)
		require.Empty(t, opened.ZkDocuments)
		require.Len(t, opened.Documents, 1, "A.8 falls back to a plain presentation")

		require.Equal(t, uint(2), env.remaining(t),
			"a document that left in the clear is consumed, whatever the reader asked for")
	})
}

// wireProver rebuilds the session with a zero-knowledge system, or without one
// when prover is nil, which is the ordinary build that must fall back.
func (e *env) wireProver(prover mdoc.ZkSystem) {
	e.wire(e.realBinder())
	if prover != nil {
		e.session.ZkSystems = mdoc.NewZkSystemRepository(prover)
	}
}

// zkRequest is reader.request with a zkRequest under requestInfo, the way
// Multipaz's DeviceRequestGenerator writes one.
//
// Signed, and that is not incidental: this env withholds everything from an
// unauthenticated reader, per 7.2.1 as ISO/IEC TS 18013-7 Clause 7 lifts it. An
// unsigned request here comes back with no documents at all — no proof, no
// plain disclosure, and no instance spent — which an instance-accounting test
// would happily read as "the proof did not consume anything".
func (r *reader) zkRequest(t *testing.T, docType, namespace string, elements ...string) []byte {
	t.Helper()

	wanted := mdoc.DataElements{}
	for _, element := range elements {
		wanted[element] = false
	}

	items := mdoc.ItemsRequest{
		DocType:    docType,
		NameSpaces: map[string]mdoc.DataElements{namespace: wanted},
	}
	encodedZk, err := mdoc.ZkRequest{
		SystemSpecs: []mdoc.ZkSystemSpec{zkSpecFor(len(elements))},
	}.MarshalCBOR()
	require.NoError(t, err)
	items.RequestInfo = map[string]cbor.RawMessage{mdoc.ZkRequestKey: encodedZk}

	docRequest, err := mdoc.NewDocRequest(items, nil)
	require.NoError(t, err)

	// Over the ItemsRequestBytes NewDocRequest just produced, never over a
	// re-encoding of them: 9.1.4.4 signs the bytes that travel.
	readerAuth, err := mdoc.SignReaderAuth(
		r.leafKey, cose.AlgorithmES256,
		[]*x509.Certificate{r.leafCert, r.rootCert},
		r.transcript(t), docRequest.ItemsRequest)
	require.NoError(t, err)
	docRequest.ReaderAuth = readerAuth

	encoded, err := mdoc.DeviceRequest{
		Version:     mdoc.DeviceRequestVersion,
		DocRequests: []mdoc.DocRequest{docRequest},
	}.Encode()
	require.NoError(t, err)

	data, err := json.Marshal(map[string]string{
		"deviceRequest":  base64.RawURLEncoding.EncodeToString(encoded),
		"encryptionInfo": r.encryptionInfo,
	})
	require.NoError(t, err)
	return data
}

// zkSpecFor is one circuit the reader offers and the prover below holds.
//
// The circuit hash is not decoration: SameCircuit refuses a match when either
// side lacks one, so a spec without it never matches anything and the session
// falls back to a plain disclosure — which these tests would then read as a
// proof that was never attempted.
func zkSpecFor(numAttributes int) mdoc.ZkSystemSpec {
	return mdoc.ZkSystemSpec{
		ID:     fmt.Sprintf("%s_6_%d_4096_2945_deadbeef", mdoc.ZkSystemLongfellowV1, numAttributes),
		System: mdoc.ZkSystemLongfellowV1,
		Params: map[string]any{
			mdoc.ZkParamVersion:       int64(6),
			mdoc.ZkParamNumAttributes: int64(numAttributes),
			mdoc.ZkParamCircuitHash:   "deadbeef",
		},
	}
}

// zkProver answers with a proof shaped like a real one and nothing else. What
// these tests assert is which instances were spent, and that does not depend on
// the proof's contents.
type zkProver struct {
	specs []mdoc.ZkSystemSpec
}

func zkProverFor(numAttributes int) *zkProver {
	return &zkProver{specs: []mdoc.ZkSystemSpec{zkSpecFor(numAttributes)}}
}

func (p *zkProver) Name() string { return mdoc.ZkSystemLongfellowV1 }

func (p *zkProver) SystemSpecs() []mdoc.ZkSystemSpec { return p.specs }

func (p *zkProver) MatchingSpec(offered []mdoc.ZkSystemSpec, numAttributes int) (mdoc.ZkSystemSpec, bool) {
	for _, mine := range p.specs {
		count, ok := mine.NumAttributes()
		if !ok || count != int64(numAttributes) {
			continue
		}
		if slices.ContainsFunc(offered, mine.SameCircuit) {
			return mine, true
		}
	}
	return mdoc.ZkSystemSpec{}, false
}

func (p *zkProver) GenerateProof(
	spec mdoc.ZkSystemSpec, document mdoc.MDoc, transcript mdoc.SessionTranscript, timestamp time.Time,
) (*mdoc.ZkDocument, error) {
	return &mdoc.ZkDocument{
		DocumentData: mdoc.NewZkDocumentData(spec.ID, document.DocType, timestamp, nil, nil),
		Proof:        []byte{0xde, 0xad},
	}, nil
}

func (p *zkProver) VerifyProof(mdoc.ZkDocument, mdoc.ZkSystemSpec, mdoc.SessionTranscript) error {
	return nil
}

var (
	_ mdoc.ZkSystem     = (*zkProver)(nil)
	_ isomdoc.Committer = (*isomdoc.WalletDiscloser)(nil)
)
