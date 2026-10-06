package isomdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/stretchr/testify/require"
)

// These exercise the session against a fake wallet. What is under test is the
// ordering — transcript before reader auth, seal before commit, release on every
// path — and the 7.2.1 decision, not candidate selection or consent, which live
// behind Discloser and are the real wallet's business.

const (
	testOrigin   = "https://verifier.example.com"
	avDocType    = "eu.europa.ec.av.1"
	avNameSpace  = "eu.europa.ec.av.1"
	mdlDocType   = "org.iso.18013.5.1.mDL"
	mdlNameSpace = "org.iso.18013.5.1"
)

// fakeDiscloser answers with whatever it was told to, and records what it saw.
type fakeDiscloser struct {
	answer    []Selection
	err       error
	seen      DisclosureRequest
	called    bool
	committed bool
	released  bool

	// commitErr makes Commit fail, to check the response is not returned when
	// the wallet could not record what it spent.
	commitErr error
}

func (f *fakeDiscloser) Disclose(request DisclosureRequest) ([]Selection, error) {
	f.called = true
	f.seen = request
	return f.answer, f.err
}
func (f *fakeDiscloser) Commit() error { f.committed = true; return f.commitErr }
func (f *fakeDiscloser) Release()      { f.released = true }

// credential issues a real mdoc bound to a fresh holder key.
func credential(t *testing.T, docType, namespace string, claims map[string]any) (mdoc.MDoc, mdoc.DeviceSigner) {
	t.Helper()

	issuer, err := mdoc.NewTestIssuer()
	require.NoError(t, err)
	holder, err := mdoc.GenerateDeviceSigner()
	require.NoError(t, err)

	document, err := issuer.Issue(docType, namespace, claims, holder.PublicKey())
	require.NoError(t, err)
	return *document, holder
}

// readerRequest builds an unsigned DeviceRequest asking for the given elements.
func readerRequest(t *testing.T, docType, namespace string, elements ...string) []byte {
	t.Helper()

	wanted := mdoc.DataElements{}
	for _, element := range elements {
		wanted[element] = false
	}
	items := mdoc.ItemsRequest{
		DocType:    docType,
		NameSpaces: map[string]mdoc.DataElements{namespace: wanted},
	}
	docRequest, err := mdoc.NewDocRequest(items, nil)
	require.NoError(t, err)

	encoded, err := mdoc.DeviceRequest{
		Version:     mdoc.DeviceRequestVersion,
		DocRequests: []mdoc.DocRequest{docRequest},
	}.Encode()
	require.NoError(t, err)
	return encoded
}

// readerSide is the verifier's half: the ephemeral key and the EncryptionInfo it
// advertises.
type readerSide struct {
	key            *ecdsa.PrivateKey
	encryptionInfo string
}

func newReaderSide(t *testing.T) readerSide {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	nonce := make([]byte, 16)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	info, err := NewDCAPIEncryptionInfo(nonce, &key.PublicKey)
	require.NoError(t, err)
	encoded, err := cbor.Marshal(info)
	require.NoError(t, err)

	return readerSide{key: key, encryptionInfo: base64.RawURLEncoding.EncodeToString(encoded)}
}

// open is what the reader does with the answer.
func (r readerSide) open(t *testing.T, sealed DCAPIEncryptedResponse) mdoc.DeviceResponse {
	t.Helper()

	transcript, err := mdoc.NewDCAPISessionTranscript(r.encryptionInfo, testOrigin)
	require.NoError(t, err)

	plaintext, err := OpenDCAPIResponse(sealed, r.key, transcript)
	require.NoError(t, err)

	var response mdoc.DeviceResponse
	require.NoError(t, cbor.Unmarshal(plaintext, &response))
	return response
}

// TestSessionRespondsEndToEnd is the whole exchange: a reader asks, the wallet
// agrees, and the reader opens what comes back and finds a signed document.
func TestSessionRespondsEndToEnd(t *testing.T) {
	reader := newReaderSide(t)
	document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})

	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Signer: holder}}}
	session := &Session{Discloser: wallet}

	sealed, err := session.Respond(Request{
		DeviceRequest:  readerRequest(t, avDocType, avNameSpace, "age_over_18"),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.NoError(t, err)

	response := reader.open(t, sealed)
	require.Equal(t, mdoc.DeviceResponseVersion, response.Version)
	require.Len(t, response.Documents, 1)
	require.NotNil(t, response.Documents[0].DeviceSigned, "the document must be signed for this session")
	require.NotEmpty(t, response.Documents[0].DeviceSigned.DeviceAuth.DeviceSignature)
	require.Empty(t, response.Documents[0].DeviceSigned.DeviceAuth.DeviceMac, "this wallet signs, never MACs")
}

// TestSessionShowsTheWalletWhatWasAsked checks the request reaching the wallet
// carries what a consent screen needs.
func TestSessionShowsTheWalletWhatWasAsked(t *testing.T) {
	reader := newReaderSide(t)
	wallet := &fakeDiscloser{}
	session := &Session{Discloser: wallet}

	_, err := session.Respond(Request{
		DeviceRequest:  readerRequest(t, mdlDocType, mdlNameSpace, "family_name", "birth_date"),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.NoError(t, err)

	require.True(t, wallet.called)
	require.Equal(t, testOrigin, wallet.seen.Origin)
	require.Len(t, wallet.seen.Documents, 1)

	asked := wallet.seen.Documents[0]
	require.Equal(t, mdlDocType, asked.DocType)
	require.False(t, asked.Authenticated(), "no readerAuth was sent")
	require.Contains(t, asked.Requested.NameSpaces[mdlNameSpace], "family_name")
}

// TestSessionReleasesNothingToAnUnauthenticatedReader is the wallet's policy at
// the session level: a reader that did not authenticate gets nothing, whatever
// docType it names.
//
// This replaced a test for 18013-5 7.2.1's mDL carve-out, which 18013-7 Clause 7
// lifts for the DC API -- "an mDL may require mdoc reader authentication as a
// precondition for the release of any of the mandatory data elements" -- and the
// DC API is the only transport here.
func TestSessionReleasesNothingToAnUnauthenticatedReader(t *testing.T) {
	t.Run("not even an mDL's Table 5 mandatory elements", func(t *testing.T) {
		reader := newReaderSide(t)
		wallet := &fakeDiscloser{}
		session := &Session{Discloser: wallet}

		_, err := session.Respond(Request{
			DeviceRequest:  readerRequest(t, mdlDocType, mdlNameSpace, "family_name"),
			EncryptionInfo: reader.encryptionInfo,
			Origin:         testOrigin,
		})
		require.NoError(t, err)

		asked := wallet.seen.Documents[0]
		require.False(t, asked.Servable(),
			"Clause 7 lifts 7.2.1 here, so family_name is gated on reader authentication like everything else")
		require.NotContains(t, asked.Permitted.NameSpaces[mdlNameSpace], "family_name")
	})

	t.Run("an age-verification credential releases nothing", func(t *testing.T) {
		reader := newReaderSide(t)
		wallet := &fakeDiscloser{}
		session := &Session{Discloser: wallet}

		_, err := session.Respond(Request{
			DeviceRequest:  readerRequest(t, avDocType, avNameSpace, "age_over_18"),
			EncryptionInfo: reader.encryptionInfo,
			Origin:         testOrigin,
		})
		require.NoError(t, err)

		asked := wallet.seen.Documents[0]
		require.False(t, asked.Servable(), "7.2.1's carve-out is for mDLs, not for every docType")
		require.Contains(t, asked.Withheld[avNameSpace], "age_over_18")
	})
}

// TestSessionRefusalIsAnEmptyResponse: a user declining produces a well-formed,
// sealed, empty response — not an error and not a non-zero status, which would
// claim the request could not be processed.
func TestSessionRefusalIsAnEmptyResponse(t *testing.T) {
	reader := newReaderSide(t)
	wallet := &fakeDiscloser{answer: nil}
	session := &Session{Discloser: wallet}

	sealed, err := session.Respond(Request{
		DeviceRequest:  readerRequest(t, avDocType, avNameSpace, "age_over_18"),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.NoError(t, err)

	response := reader.open(t, sealed)
	require.Empty(t, response.Documents)
	require.Equal(t, mdoc.ResponseStatusOK, response.Status,
		"a refusal is a successful exchange in which nothing was agreed")
}

// TestSessionCommitsOnlyAfterSealing is the single-use accounting rule: an
// instance must not be recorded as spent on a response that was never produced.
func TestSessionCommitsOnlyAfterSealing(t *testing.T) {
	t.Run("a successful exchange commits and releases", func(t *testing.T) {
		reader := newReaderSide(t)
		document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})
		wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Signer: holder}}}

		_, err := (&Session{Discloser: wallet}).Respond(Request{
			DeviceRequest:  readerRequest(t, avDocType, avNameSpace, "age_over_18"),
			EncryptionInfo: reader.encryptionInfo,
			Origin:         testOrigin,
		})
		require.NoError(t, err)
		require.True(t, wallet.committed)
		require.True(t, wallet.released)
	})

	t.Run("a signing failure releases without committing", func(t *testing.T) {
		reader := newReaderSide(t)
		document, _ := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})

		// A selection with no holder cannot be signed, which fails after the
		// wallet has reserved but before any response exists.
		wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document}}}

		_, err := (&Session{Discloser: wallet}).Respond(Request{
			DeviceRequest:  readerRequest(t, avDocType, avNameSpace, "age_over_18"),
			EncryptionInfo: reader.encryptionInfo,
			Origin:         testOrigin,
		})
		require.ErrorContains(t, err, "carries no holder")
		require.False(t, wallet.committed, "nothing may be spent for a response that was never built")
		require.True(t, wallet.released, "what was reserved must be given back")
	})

	t.Run("a failed commit fails the exchange", func(t *testing.T) {
		reader := newReaderSide(t)
		document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})
		wallet := &fakeDiscloser{
			answer:    []Selection{{DocType: avDocType, Document: document, Signer: holder}},
			commitErr: errFake,
		}

		_, err := (&Session{Discloser: wallet}).Respond(Request{
			DeviceRequest:  readerRequest(t, avDocType, avNameSpace, "age_over_18"),
			EncryptionInfo: reader.encryptionInfo,
			Origin:         testOrigin,
		})
		require.ErrorContains(t, err, "commit disclosure")
	})
}

var errFake = &fakeError{}

type fakeError struct{}

func (e *fakeError) Error() string { return "the wallet could not record the spend" }

// TestSessionRejectsIncompleteRequests. The origin case matters most: it is the
// one input that does not arrive in the request, so a wallet that defaulted it
// would sign over the wrong transcript and fail at the verifier instead of here.
func TestSessionRejectsIncompleteRequests(t *testing.T) {
	reader := newReaderSide(t)
	deviceRequest := readerRequest(t, avDocType, avNameSpace, "age_over_18")
	session := &Session{Discloser: &fakeDiscloser{}}

	for _, tc := range []struct {
		name    string
		request Request
		want    string
	}{
		{"no deviceRequest", Request{EncryptionInfo: reader.encryptionInfo, Origin: testOrigin}, "no deviceRequest"},
		{"no encryptionInfo", Request{DeviceRequest: deviceRequest, Origin: testOrigin}, "no encryptionInfo"},
		{"no origin", Request{DeviceRequest: deviceRequest, EncryptionInfo: reader.encryptionInfo}, "no origin"},
		{
			"encryptionInfo that is not base64",
			Request{DeviceRequest: deviceRequest, EncryptionInfo: "!!!not base64!!!", Origin: testOrigin},
			"not base64url",
		},
		{
			"deviceRequest that is not CBOR",
			Request{DeviceRequest: []byte("nope"), EncryptionInfo: reader.encryptionInfo, Origin: testOrigin},
			"decode deviceRequest",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := session.Respond(tc.request)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestSessionWithoutADiscloserRefuses(t *testing.T) {
	reader := newReaderSide(t)
	_, err := (&Session{}).Respond(Request{
		DeviceRequest:  readerRequest(t, avDocType, avNameSpace, "age_over_18"),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.ErrorContains(t, err, "no discloser")
}

// TestSessionBindsTheResponseToItsOwnOrigin: the response the session produces
// must not open under a transcript built for a different origin. This is the
// end-to-end form of the handover property — the same guarantee, but reached
// through the session rather than asserted on the transcript directly.
func TestSessionBindsTheResponseToItsOwnOrigin(t *testing.T) {
	reader := newReaderSide(t)
	document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})
	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Signer: holder}}}

	sealed, err := (&Session{Discloser: wallet}).Respond(Request{
		DeviceRequest:  readerRequest(t, avDocType, avNameSpace, "age_over_18"),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.NoError(t, err)

	elsewhere, err := mdoc.NewDCAPISessionTranscript(reader.encryptionInfo, "https://attacker.example.com")
	require.NoError(t, err)
	_, err = OpenDCAPIResponse(sealed, reader.key, elsewhere)
	require.Error(t, err, "a response sealed for one origin must not open under another")
}

// ============================================================
// REPORTING WHAT WAS NOT RETURNED — 8.3.2.1.2.2
// ============================================================
//
// The other half of partial satisfaction. WalletDiscloser.narrow answers with
// what the wallet has; these are the tests that it also says what it did not,
// which is what keeps narrowing from silently answering a smaller question.

// TestSessionReportsElementsItCouldNotReturn: a document is returned holding
// fewer elements than were asked for, and the missing ones come back as Table 9
// errors on that document rather than as silence.
func TestSessionReportsElementsItCouldNotReturn(t *testing.T) {
	reader := newReaderSide(t)

	// The wallet holds and discloses only age_over_18; the reader asked for both.
	document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})
	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Signer: holder}}}

	sealed, err := (&Session{Discloser: wallet}).Respond(Request{
		DeviceRequest:  readerRequest(t, avDocType, avNameSpace, "age_over_18", "age_over_65"),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.NoError(t, err)

	response := reader.open(t, sealed)
	require.Len(t, response.Documents, 1)
	require.Empty(t, response.DocumentErrors,
		"the document WAS returned, so this is an element-level failure, not a document-level one")

	errs := response.Documents[0].Errors
	require.NotNil(t, errs, "an element asked for and not returned is reported, not silently dropped")
	require.Equal(t, mdoc.ErrorCodeDataNotReturned, errs[avNameSpace]["age_over_65"])
	require.NotContains(t, errs[avNameSpace], "age_over_18", "what was returned is not an error")
}

// TestSessionReportsElementsWithheldByReaderAuth: an element the wallet kept
// back is reported with the same code as one it does not hold. Both were
// requested and neither is being returned, and telling the two apart would tell
// a reader what the wallet is holding back.
//
// The partial answer is built by the fake discloser rather than produced by a
// reader-authentication rule. It used to be the latter: 7.2.1 released an mDL's
// Table 5 mandatory family_name to an unauthenticated reader while withholding
// the optional issuing_jurisdiction, and this test drove that split. 18013-7
// Clause 7 lifts 7.2.1 for this transport, so the wallet now releases nothing to
// such a reader (TestSessionReleasesNothingToAnUnauthenticatedReader) and the
// split can no longer arise that way. What is under test is unchanged and worth
// keeping: assemble computes errors against what the reader ASKED for, not
// against what the wallet chose to return, whatever the reason for the choice.
func TestSessionReportsElementsWithheldByReaderAuth(t *testing.T) {
	reader := newReaderSide(t)

	// The wallet holds both and the discloser returns only family_name, so
	// issuing_jurisdiction takes the withheld path rather than the not-held one.
	document, holder := credential(t, mdlDocType, mdlNameSpace, map[string]any{
		"family_name":          "Doe",
		"issuing_jurisdiction": "NL-ZH",
	})
	// Disclosed as the discloser would have left it: only the permitted element.
	stripped, err := services.SelectiveDiscloseNamespaces(&document, map[string][]string{
		mdlNameSpace: {"family_name"},
	})
	require.NoError(t, err)
	wallet := &fakeDiscloser{answer: []Selection{{DocType: mdlDocType, Document: *stripped, Signer: holder}}}

	sealed, err := (&Session{Discloser: wallet}).Respond(Request{
		DeviceRequest:  readerRequest(t, mdlDocType, mdlNameSpace, "family_name", "issuing_jurisdiction"),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.NoError(t, err)

	response := reader.open(t, sealed)
	require.Len(t, response.Documents, 1)

	errs := response.Documents[0].Errors
	require.Equal(t, mdoc.ErrorCodeDataNotReturned, errs[mdlNameSpace]["issuing_jurisdiction"],
		"errors are computed against what the reader ASKED for, not against what it was permitted")
	require.NotContains(t, errs[mdlNameSpace], "family_name")
}

// TestSessionReportsDocumentsItDidNotReturn: a refusal is reported as a
// documentError per requested document, not as an empty response the reader has
// to interpret.
func TestSessionReportsDocumentsItDidNotReturn(t *testing.T) {
	reader := newReaderSide(t)
	wallet := &fakeDiscloser{answer: nil}

	sealed, err := (&Session{Discloser: wallet}).Respond(Request{
		DeviceRequest:  readerRequest(t, avDocType, avNameSpace, "age_over_18"),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.NoError(t, err)

	response := reader.open(t, sealed)
	require.Empty(t, response.Documents)
	require.Equal(t, mdoc.ResponseStatusOK, response.Status,
		"8.3.2.1.2.3 keeps the status for requests that could not be PROCESSED")
	require.Len(t, response.DocumentErrors, 1)
	require.Equal(t, mdoc.ErrorCodeDataNotReturned, response.DocumentErrors[0][avDocType])
}

// TestSessionRefusesASelectionItDidNotAskFor: a wallet answering with a document
// the reader never requested is a bug in the wallet, and one that would disclose
// a credential nobody asked for. It fails the exchange rather than transmitting.
func TestSessionRefusesASelectionItDidNotAskFor(t *testing.T) {
	reader := newReaderSide(t)
	document, holder := credential(t, mdlDocType, mdlNameSpace, map[string]any{"family_name": "Doe"})
	wallet := &fakeDiscloser{answer: []Selection{{DocType: mdlDocType, Document: document, Signer: holder}}}

	_, err := (&Session{Discloser: wallet}).Respond(Request{
		DeviceRequest:  readerRequest(t, avDocType, avNameSpace, "age_over_18"),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.ErrorContains(t, err, "did not ask for")
}

// TestSessionRefusesAMislabelledSelection: deviceAuth signs the docType the
// selection is labelled with, and a verifier reads it off the document. If the
// two disagree the response transmits, decrypts, and fails only at the reader's
// signature check with nothing naming the cause.
func TestSessionRefusesAMislabelledSelection(t *testing.T) {
	reader := newReaderSide(t)
	document, holder := credential(t, mdlDocType, mdlNameSpace, map[string]any{"family_name": "Doe"})

	// Labelled as the docType that was requested, carrying a different one.
	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Signer: holder}}}

	_, err := (&Session{Discloser: wallet}).Respond(Request{
		DeviceRequest:  readerRequest(t, avDocType, avNameSpace, "age_over_18"),
		EncryptionInfo: reader.encryptionInfo,
		Origin:         testOrigin,
	})
	require.ErrorContains(t, err, "deviceAuth would sign a docType the document does not have")
}

// plainItemsRequest builds one docRequest's ItemsRequest with no zkRequest.
func plainItemsRequest(docType, namespace string, elements ...string) mdoc.ItemsRequest {
	wanted := mdoc.DataElements{}
	for _, element := range elements {
		wanted[element] = false
	}
	return mdoc.ItemsRequest{
		DocType:    docType,
		NameSpaces: map[string]mdoc.DataElements{namespace: wanted},
	}
}

// TestAskedForDistinguishesTwoDocRequestsOfOneDocType: a reader may send two
// docRequests for the same docType -- request.go says as much, one wanting two
// documents asks twice -- and they can carry different element sets and
// different zkRequests. Each selection has to be judged against ITS docRequest.
//
// Matching on docType alone returned the first match for both, so a reader
// asking age_over_18 in one request and age_over_65 in the other had the first
// request's elements applied twice, and a zkRequired request could be answered
// with a plain disclosure because the policy consulted belonged to the other one.
func TestAskedForDistinguishesTwoDocRequestsOfOneDocType(t *testing.T) {
	// Both servable, because only servable documents reach a generated query and
	// the ids are numbered over that subset.
	servable := func(elements ...string) RequestedDocument {
		items := plainItemsRequest(avDocType, avNameSpace, elements...)
		return RequestedDocument{DocType: avDocType, Requested: items, Permitted: items}
	}
	requested := []RequestedDocument{servable("age_over_18"), servable("age_over_65")}
	require.True(t, requested[0].Servable() && requested[1].Servable(), "precondition")

	t.Run("each query id resolves to its own docRequest", func(t *testing.T) {
		first, ok := askedFor(requested, Selection{DocType: avDocType, QueryId: "doc0"})
		require.True(t, ok)
		require.Contains(t, first.Requested.NameSpaces[avNameSpace], "age_over_18")

		second, ok := askedFor(requested, Selection{DocType: avDocType, QueryId: "doc1"})
		require.True(t, ok)
		require.Contains(t, second.Requested.NameSpaces[avNameSpace], "age_over_65",
			"the second selection must not be judged against the first docRequest")
	})

	t.Run("an unservable document is not numbered", func(t *testing.T) {
		// Only servable documents reach the query, so doc0 is the first SERVABLE
		// one, not the first requested one.
		withUnservable := []RequestedDocument{
			{DocType: avDocType, Requested: plainItemsRequest(avDocType, avNameSpace, "age_over_18")},
			requested[1],
		}
		require.False(t, withUnservable[0].Servable(), "precondition: nothing permitted")

		resolved, ok := askedFor(withUnservable, Selection{DocType: avDocType, QueryId: "doc0"})
		require.True(t, ok)
		require.Contains(t, resolved.Requested.NameSpaces[avNameSpace], "age_over_65")
	})

	t.Run("no query id falls back to the docType", func(t *testing.T) {
		// A Discloser that does not build selections from a generated query.
		resolved, ok := askedFor(requested, Selection{DocType: avDocType})
		require.True(t, ok)
		require.Contains(t, resolved.Requested.NameSpaces[avNameSpace], "age_over_18")
	})

	t.Run("an unknown docType is still refused", func(t *testing.T) {
		_, ok := askedFor(requested, Selection{DocType: "org.iso.18013.5.1.mDL", QueryId: "doc0"})
		require.False(t, ok)
	})
}
