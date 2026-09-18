package mdocpresent

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/stretchr/testify/require"
)

// These exercise the branch A.8 turns on: a reader that will take a proof, and a
// build that may or may not be able to produce one.
//
// Until this file the ZK path had no caller at all. Every structure in
// eudi/credentials/mdoc existed and was tested against captured wire samples,
// and no session could reach any of it — so the wallet's observable behaviour
// was "always disclose in the clear", whatever the reader asked for. What is
// under test here is therefore the decision rather than the cryptography: when a
// proof replaces a disclosure, when absence falls back, and when falling back
// would be wrong.
//
// The prover is faked, because the real one lives in a module this one does not
// link. It is exercised for real by the vector pipeline instead — see
// eudi/credentials/mdoc/zkp_irmago_vector_test.go.

// zkTestSpecFor builds a spec for a circuit of numAttributes attributes.
func zkTestSpecFor(numAttributes int) mdoc.ZkSystemSpec {
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

// fakeProver stands in for the native library. It records what it was asked to
// prove, which is what the attribute-count test turns on.
type fakeProver struct {
	specs []mdoc.ZkSystemSpec
	err   error

	calls       int
	gotSpec     mdoc.ZkSystemSpec
	gotDocument mdoc.MDoc
	gotTime     time.Time
}

func (f *fakeProver) Name() string                     { return mdoc.ZkSystemLongfellowV1 }
func (f *fakeProver) SystemSpecs() []mdoc.ZkSystemSpec { return f.specs }

func (f *fakeProver) MatchingSpec(offered []mdoc.ZkSystemSpec, numAttributes int) (mdoc.ZkSystemSpec, bool) {
	for _, mine := range f.specs {
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

func (f *fakeProver) GenerateProof(
	spec mdoc.ZkSystemSpec, document mdoc.MDoc, transcript mdoc.SessionTranscript, timestamp time.Time,
) (*mdoc.ZkDocument, error) {
	f.calls++
	f.gotSpec, f.gotDocument, f.gotTime = spec, document, timestamp
	if f.err != nil {
		return nil, f.err
	}
	return &mdoc.ZkDocument{
		DocumentData: mdoc.NewZkDocumentData(spec.ID, document.DocType, timestamp, nil, nil),
		Proof:        []byte{0xde, 0xad},
	}, nil
}

func (f *fakeProver) VerifyProof(mdoc.ZkDocument, mdoc.ZkSystemSpec, mdoc.SessionTranscript) error {
	return nil
}

// zkItemsRequest is an itemsRequest carrying a zkRequest under requestInfo, the
// way Multipaz's DeviceRequestGenerator writes one.
func zkItemsRequest(
	t *testing.T,
	docType, namespace string,
	zkRequest mdoc.ZkRequest,
	elements ...string,
) mdoc.ItemsRequest {
	t.Helper()

	wanted := mdoc.DataElements{}
	for _, element := range elements {
		wanted[element] = false
	}
	encoded, err := zkRequest.MarshalCBOR()
	require.NoError(t, err)

	return mdoc.ItemsRequest{
		DocType:     docType,
		NameSpaces:  map[string]mdoc.DataElements{namespace: wanted},
		RequestInfo: map[string]cbor.RawMessage{mdoc.ZkRequestKey: encoded},
	}
}

// encodeRequest bundles itemsRequests into an unsigned DeviceRequest.
func encodeRequest(t *testing.T, items ...mdoc.ItemsRequest) []byte {
	t.Helper()

	docRequests := make([]mdoc.DocRequest, 0, len(items))
	for _, item := range items {
		docRequest, err := mdoc.NewDocRequest(item, nil)
		require.NoError(t, err)
		docRequests = append(docRequests, docRequest)
	}
	encoded, err := mdoc.DeviceRequest{
		Version:     mdoc.DeviceRequestVersion,
		DocRequests: docRequests,
	}.Encode()
	require.NoError(t, err)
	return encoded
}

// TestZkProofReplacesTheDisclosure is the headline: a reader that will take a
// proof and a build that can produce one get a zkDocument, and the cleartext
// document does NOT also travel. Sending both would disclose in the clear
// exactly what the proof exists to hide.
func TestZkProofReplacesTheDisclosure(t *testing.T) {
	reader := newReaderSide(t)
	document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})
	prover := &fakeProver{specs: []mdoc.ZkSystemSpec{zkTestSpecFor(1)}}

	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Holder: holder}}}
	session := &Session{
		Discloser: wallet,
		ZkSystems: mdoc.NewZkSystemRepository(prover),
		Now:       func() time.Time { return time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC) },
	}

	sealed, err := session.Respond(Request{
		DeviceRequest: encodeRequest(t, zkItemsRequest(t, avDocType, avNameSpace,
			mdoc.ZkRequest{SystemSpecs: []mdoc.ZkSystemSpec{zkTestSpecFor(1)}}, "age_over_18")),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.NoError(t, err)

	response := reader.open(t, sealed)
	require.Equal(t, mdoc.DeviceResponseVersionZk, response.Version,
		"a response carrying zkDocuments is a second-edition response")
	require.Len(t, response.ZkDocuments, 1)
	require.Empty(t, response.Documents, "the proof replaces the disclosure; it does not accompany it")
	require.Equal(t, 1, prover.calls)

	// The prover is handed a document that already carries its DeviceSigned. The
	// real longfellow prover refuses one that does not, with
	// MDOC_PROVER_DEVICE_SIGNED_MISSING, so this is an ordering that matters
	// rather than a detail of the fake.
	require.NotNil(t, prover.gotDocument.DeviceSigned,
		"the ordinary presentation path runs first: the proof covers the device signature")
	require.Equal(t, avDocType, prover.gotDocument.DocType)
}

// TestZkFallsBackWhenTheBuildCannotProve is A.8's own instruction: "where the
// User's device does not support Zero-Knowledge Proof generation, the AVI SHALL
// fall back to the plain ISO mDoc presentation defined in Section A.6." A nil
// repository is the ordinary state of a build without the native module, so it
// has to produce a session that succeeds, not one that fails.
func TestZkFallsBackWhenTheBuildCannotProve(t *testing.T) {
	reader := newReaderSide(t)
	document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})

	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Holder: holder}}}
	session := &Session{Discloser: wallet} // no ZkSystems at all

	sealed, err := session.Respond(Request{
		DeviceRequest: encodeRequest(t, zkItemsRequest(t, avDocType, avNameSpace,
			mdoc.ZkRequest{SystemSpecs: []mdoc.ZkSystemSpec{zkTestSpecFor(1)}}, "age_over_18")),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.NoError(t, err, "a build with no prover answers; it does not fail")

	response := reader.open(t, sealed)
	require.Equal(t, mdoc.DeviceResponseVersion, response.Version)
	require.Len(t, response.Documents, 1)
	require.Empty(t, response.ZkDocuments)
}

// TestZkRequiredRefusesBeforeAskingTheUser: a reader that set zkRequired has
// opted out of the fallback, so a build that cannot prove must fail rather than
// disclose in the clear — the one case where falling back hands over more than
// the user was asked to agree to.
//
// It must also fail BEFORE consent. Prompting first would collect agreement for
// a disclosure that then never happens, which is worse than refusing outright:
// the user has consented and has no way to learn it did not occur.
func TestZkRequiredRefusesBeforeAskingTheUser(t *testing.T) {
	reader := newReaderSide(t)
	document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})

	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Holder: holder}}}
	session := &Session{Discloser: wallet} // no prover

	_, err := session.Respond(Request{
		DeviceRequest: encodeRequest(t, zkItemsRequest(t, avDocType, avNameSpace,
			mdoc.ZkRequest{SystemSpecs: []mdoc.ZkSystemSpec{zkTestSpecFor(1)}, ZkRequired: true},
			"age_over_18")),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.ErrorContains(t, err, "requires a zero-knowledge proof")
	require.False(t, wallet.called,
		"the user must not be asked to consent to a disclosure that cannot happen")
}

// TestZkRequiredRefusesWhenNoCircuitFitsTheDisclosure is the other half of
// zkRequired, and the half a pre-consent check cannot reach: the build has the
// reader's system but no circuit for the number of elements finally disclosed.
// That is only knowable after the user has chosen.
func TestZkRequiredRefusesWhenNoCircuitFitsTheDisclosure(t *testing.T) {
	reader := newReaderSide(t)
	document, holder := credential(t, avDocType, avNameSpace,
		map[string]any{"age_over_18": true, "age_over_21": true})

	// The build holds only a one-attribute circuit; two elements are disclosed.
	prover := &fakeProver{specs: []mdoc.ZkSystemSpec{zkTestSpecFor(1)}}
	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Holder: holder}}}
	session := &Session{Discloser: wallet, ZkSystems: mdoc.NewZkSystemRepository(prover)}

	_, err := session.Respond(Request{
		DeviceRequest: encodeRequest(t, zkItemsRequest(t, avDocType, avNameSpace,
			mdoc.ZkRequest{
				SystemSpecs: []mdoc.ZkSystemSpec{zkTestSpecFor(1), zkTestSpecFor(2)},
				ZkRequired:  true,
			},
			"age_over_18", "age_over_21")),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.ErrorContains(t, err, "cannot produce one")
	require.True(t, wallet.called, "this one is only decidable after the user has chosen")
	require.Zero(t, prover.calls, "no circuit fits, so nothing should have been proved")
}

// TestZkCountsElementsDisclosedNotElementsRequested: a circuit is built for an
// exact number of attributes, and the number that matters is what the user
// actually agreed to disclose — which partial satisfaction may have made smaller
// than what the reader asked for. Counting the request would select a circuit
// the disclosure does not fit.
func TestZkCountsElementsDisclosedNotElementsRequested(t *testing.T) {
	reader := newReaderSide(t)

	// The reader asks for two elements; the wallet holds and discloses one.
	document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})
	prover := &fakeProver{specs: []mdoc.ZkSystemSpec{zkTestSpecFor(1), zkTestSpecFor(2)}}

	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Holder: holder}}}
	session := &Session{Discloser: wallet, ZkSystems: mdoc.NewZkSystemRepository(prover)}

	_, err := session.Respond(Request{
		DeviceRequest: encodeRequest(t, zkItemsRequest(t, avDocType, avNameSpace,
			mdoc.ZkRequest{SystemSpecs: []mdoc.ZkSystemSpec{zkTestSpecFor(1), zkTestSpecFor(2)}},
			"age_over_18", "age_over_21")),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.NoError(t, err)

	require.Equal(t, 1, prover.calls)
	count, ok := prover.gotSpec.NumAttributes()
	require.True(t, ok)
	require.Equal(t, int64(1), count,
		"one element was disclosed, so the one-attribute circuit is the one that fits")
}

// TestZkProverFailureIsNotAFallback: a prover that was selected and then broke
// is not a device that cannot prove. Treating it as one would turn a crash into
// an over-disclosure — the wallet would answer in the clear a request it had
// already decided to answer with a proof.
func TestZkProverFailureIsNotAFallback(t *testing.T) {
	reader := newReaderSide(t)
	document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})
	prover := &fakeProver{
		specs: []mdoc.ZkSystemSpec{zkTestSpecFor(1)},
		err:   fmt.Errorf("circuit did not load"),
	}

	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Holder: holder}}}
	session := &Session{Discloser: wallet, ZkSystems: mdoc.NewZkSystemRepository(prover)}

	_, err := session.Respond(Request{
		DeviceRequest: encodeRequest(t, zkItemsRequest(t, avDocType, avNameSpace,
			mdoc.ZkRequest{SystemSpecs: []mdoc.ZkSystemSpec{zkTestSpecFor(1)}}, "age_over_18")),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.ErrorContains(t, err, "circuit did not load")
	require.False(t, wallet.committed, "nothing may be spent on a response that was never produced")
	require.True(t, wallet.released)
}

// TestZkRequestIsPerDocumentNotPerSession: zkRequest lives inside itemsRequest,
// so a reader may ask for a proof of one document and a plain disclosure of
// another in the same request. The response then carries both lists, and its
// version is the second-edition one because it contains a second-edition member.
func TestZkRequestIsPerDocumentNotPerSession(t *testing.T) {
	reader := newReaderSide(t)
	avDocument, avHolder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})
	mdlDocument, mdlHolder := credential(t, mdlDocType, mdlNameSpace, map[string]any{"family_name": "Doe"})
	prover := &fakeProver{specs: []mdoc.ZkSystemSpec{zkTestSpecFor(1)}}

	request := encodeRequest(t,
		zkItemsRequest(t, avDocType, avNameSpace,
			mdoc.ZkRequest{SystemSpecs: []mdoc.ZkSystemSpec{zkTestSpecFor(1)}}, "age_over_18"),
		mdoc.ItemsRequest{
			DocType:    mdlDocType,
			NameSpaces: map[string]mdoc.DataElements{mdlNameSpace: {"family_name": false}},
		},
	)

	wallet := &fakeDiscloser{answer: []Selection{
		{DocType: avDocType, Document: avDocument, Holder: avHolder},
		{DocType: mdlDocType, Document: mdlDocument, Holder: mdlHolder},
	}}
	session := &Session{Discloser: wallet, ZkSystems: mdoc.NewZkSystemRepository(prover)}

	sealed, err := session.Respond(Request{
		DeviceRequest:  request,
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.NoError(t, err)

	response := reader.open(t, sealed)
	require.Len(t, response.ZkDocuments, 1, "the document whose request carried a zkRequest")
	require.Len(t, response.Documents, 1, "the one whose request did not")
	require.Equal(t, mdlDocType, response.Documents[0].DocType)
	require.Equal(t, mdoc.DeviceResponseVersionZk, response.Version,
		"a mixed response still contains a second-edition member")
	require.NoError(t, response.Validate())
}

// TestMalformedZkRequestIsNotTreatedAsAbsent: 8.1 tells an mdoc to ignore
// requestInfo entries it cannot interpret, but that is about keys with no
// meaning here, and zkRequest has one. Silently treating a broken one as absent
// would take the fallback — which is exactly what a reader setting zkRequired
// has refused, and a wallet cannot read zkRequired out of a map it could not
// decode.
func TestMalformedZkRequestIsNotTreatedAsAbsent(t *testing.T) {
	reader := newReaderSide(t)
	document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})

	request := encodeRequest(t, mdoc.ItemsRequest{
		DocType:    avDocType,
		NameSpaces: map[string]mdoc.DataElements{avNameSpace: {"age_over_18": false}},
		// A text string where a map belongs.
		RequestInfo: map[string]cbor.RawMessage{mdoc.ZkRequestKey: {0x63, 'b', 'a', 'd'}},
	})

	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Holder: holder}}}
	_, err := (&Session{Discloser: wallet}).Respond(Request{
		DeviceRequest:  request,
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.ErrorContains(t, err, mdoc.ZkRequestKey)
	require.False(t, wallet.called)
}

// TestUnknownRequestInfoKeysAreStillIgnored is the other side of that rule: a
// key this wallet has no meaning for must not break the session. 8.1: "An mdoc
// shall ignore any key-value pairs that it is not able to interpret."
func TestUnknownRequestInfoKeysAreStillIgnored(t *testing.T) {
	reader := newReaderSide(t)
	document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})

	request := encodeRequest(t, mdoc.ItemsRequest{
		DocType:     avDocType,
		NameSpaces:  map[string]mdoc.DataElements{avNameSpace: {"age_over_18": false}},
		RequestInfo: map[string]cbor.RawMessage{"somethingNewInTheNextEdition": {0xf5}},
	})

	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Holder: holder}}}
	sealed, err := (&Session{Discloser: wallet}).Respond(Request{
		DeviceRequest:  request,
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.NoError(t, err)
	require.Len(t, reader.open(t, sealed).Documents, 1)
}
