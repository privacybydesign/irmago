package mdocpresent

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/stretchr/testify/require"
)

// TestDcApiProtocolIdentifierMatchesOpenID4VP pins the duplicated constant.
//
// The value is ISO/IEC 18013-7's and is declared in both packages so that
// neither has to import the other for it. Duplicated constants drift, and this
// one drifting means requests route to the wrong session with nothing failing
// until a verifier gets an OpenID4VP parse error for an ISO request.
func TestDcApiProtocolIdentifierMatchesOpenID4VP(t *testing.T) {
	require.Equal(t, openid4vp.DcApiProtocolIsoMdoc, DcApiProtocolIsoMdoc)
	require.Equal(t, "org-iso-mdoc", DcApiProtocolIsoMdoc)
}

func dcApiData(t *testing.T, deviceRequest []byte, encryptionInfo string) []byte {
	t.Helper()
	return []byte(fmt.Sprintf(`{"deviceRequest":%q,"encryptionInfo":%q}`,
		base64.RawURLEncoding.EncodeToString(deviceRequest), encryptionInfo))
}

// TestRequestFromDcApi is the shape ISO/IEC 18013-7 Annex C delivers.
func TestRequestFromDcApi(t *testing.T) {
	deviceRequest := readerRequest(t, avDocType, avNameSpace, "age_over_18")
	reader := newReaderSide(t)

	request, err := RequestFromDcApi(dcApiData(t, deviceRequest, reader.encryptionInfo), testOrigin)
	require.NoError(t, err)

	require.Equal(t, deviceRequest, request.DeviceRequest, "the deviceRequest is decoded to bytes")
	require.Equal(t, reader.encryptionInfo, request.EncryptionInfo,
		"the encryptionInfo is kept as the text received: the session transcript hashes it")
	require.Equal(t, testOrigin, request.Origin)
}

// TestRequestFromDcApiAcceptsPaddedBase64: RFC 4648 §5 makes the padding
// optional, so both spellings are conformant and refusing one would refuse a
// verifier over a choice the standard leaves open.
func TestRequestFromDcApiAcceptsPaddedBase64(t *testing.T) {
	deviceRequest := readerRequest(t, avDocType, avNameSpace, "age_over_18")
	reader := newReaderSide(t)

	padded := base64.URLEncoding.EncodeToString(deviceRequest)
	data := []byte(fmt.Sprintf(`{"deviceRequest":%q,"encryptionInfo":%q}`, padded, reader.encryptionInfo))

	request, err := RequestFromDcApi(data, testOrigin)
	require.NoError(t, err)
	require.Equal(t, deviceRequest, request.DeviceRequest)
}

// TestRequestFromDcApiRefusesWhatCannotBeAnswered checks every input the exchange
// cannot proceed without, each named rather than left to fail later as a decode
// error or, worse, as a signature the verifier rejects for no stated reason.
func TestRequestFromDcApiRefusesWhatCannotBeAnswered(t *testing.T) {
	deviceRequest := readerRequest(t, avDocType, avNameSpace, "age_over_18")
	reader := newReaderSide(t)
	good := dcApiData(t, deviceRequest, reader.encryptionInfo)

	for _, test := range []struct {
		name   string
		data   []byte
		origin string
		want   string
	}{
		{"no data member", nil, testOrigin, "carries no data member"},
		{"not json", []byte("{"), testOrigin, "parse org-iso-mdoc request data"},
		{
			"no deviceRequest",
			[]byte(fmt.Sprintf(`{"encryptionInfo":%q}`, reader.encryptionInfo)),
			testOrigin,
			"carries no deviceRequest",
		},
		{
			"no encryptionInfo",
			[]byte(fmt.Sprintf(`{"deviceRequest":%q}`, base64.RawURLEncoding.EncodeToString(deviceRequest))),
			testOrigin,
			"always encrypted",
		},
		{
			"deviceRequest is not base64url",
			[]byte(fmt.Sprintf(`{"deviceRequest":"not base64!","encryptionInfo":%q}`, reader.encryptionInfo)),
			testOrigin,
			"not base64url",
		},
		// The origin is not in the request and cannot be recovered from one. The
		// transcript binds to it, so a wallet that did not receive it cannot
		// produce a response the reader will accept.
		{"no origin", good, "", "carries no origin"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := RequestFromDcApi(test.data, test.origin)
			require.ErrorContains(t, err, test.want)
		})
	}
}

// TestRequestFromDcApiRoundTripsIntoASession is the join: a request in the shape
// the browser delivers is answered by the same session the unit tests drive, and
// the reader can open the result.
func TestRequestFromDcApiRoundTripsIntoASession(t *testing.T) {
	reader := newReaderSide(t)
	document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})
	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Holder: holder}}}

	data := dcApiData(t, readerRequest(t, avDocType, avNameSpace, "age_over_18"), reader.encryptionInfo)
	request, err := RequestFromDcApi(data, testOrigin)
	require.NoError(t, err)

	sealed, err := (&Session{Discloser: wallet}).Respond(request)
	require.NoError(t, err)

	response := reader.open(t, sealed)
	require.Len(t, response.Documents, 1)
	require.NotNil(t, response.Documents[0].DeviceSigned)
}
