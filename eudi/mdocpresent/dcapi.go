package mdocpresent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ============================================================
// THE org-iso-mdoc REQUEST AS THE BROWSER DELIVERS IT
// ============================================================
//
// One protocol identifier of the W3C Digital Credentials API carries ISO/IEC
// 18013-5 itself rather than OpenID4VP, per ISO/IEC 18013-7 Annex C:
//
//	protocol = "org-iso-mdoc"
//	data     = {"deviceRequest": base64url, "encryptionInfo": base64url}
//
// That is the whole request. There is no client_id, no nonce, no DCQL query and
// no response_mode — which is why it cannot be a branch of the OpenID4VP DC API
// parser and answers to Session instead. See eudi/openid4vp/dc_api.go.

// DcApiProtocolIsoMdoc is the protocol identifier this package answers to.
//
// Duplicated from eudi/openid4vp rather than imported: the value is ISO/IEC
// 18013-7's, not OpenID4VP's, and an import would make this package depend on
// the one it exists to be independent of. The two are pinned together by a test.
const DcApiProtocolIsoMdoc = "org-iso-mdoc"

// dcApiRequestData is the `data` member of an org-iso-mdoc request.
type dcApiRequestData struct {
	DeviceRequest  string `json:"deviceRequest"`
	EncryptionInfo string `json:"encryptionInfo"`
}

// RequestFromDcApi builds a Request from the `data` member the platform
// delivered and the origin it authenticated for the caller.
//
// # What is decoded and what is not
//
// deviceRequest is decoded to bytes: it is CBOR that this package parses.
//
// encryptionInfo is kept as the base64url TEXT exactly as received, and that is
// deliberate rather than lazy. The session transcript hashes that text (see
// mdoc.NewDCAPISessionTranscript), so decoding it here and re-encoding it later
// would produce a transcript the reader does not share whenever the two encodings
// differ by so much as padding — and the failure surfaces only as a device
// signature the verifier rejects, with nothing naming the cause. The key inside
// it is recovered separately, from a decode that is thrown away.
//
// # Origin
//
// Not a field of the request and not recoverable from one. The platform
// authenticates the caller and reports its origin out of band; a wallet that does
// not receive it cannot answer at all, because the transcript binds to it. Passed
// in rather than defaulted for that reason.
func RequestFromDcApi(data []byte, origin string) (Request, error) {
	var empty Request

	if len(data) == 0 {
		return empty, fmt.Errorf("org-iso-mdoc request carries no data member")
	}

	var parsed dcApiRequestData
	if err := json.Unmarshal(data, &parsed); err != nil {
		return empty, fmt.Errorf("parse org-iso-mdoc request data: %w", err)
	}
	if parsed.DeviceRequest == "" {
		return empty, fmt.Errorf("org-iso-mdoc request data carries no deviceRequest")
	}
	if parsed.EncryptionInfo == "" {
		return empty, fmt.Errorf(
			"org-iso-mdoc request data carries no encryptionInfo: responses on this protocol are always encrypted")
	}

	deviceRequest, err := decodeBase64Url(parsed.DeviceRequest)
	if err != nil {
		return empty, fmt.Errorf("deviceRequest is not base64url: %w", err)
	}

	request := Request{
		DeviceRequest:  deviceRequest,
		EncryptionInfo: parsed.EncryptionInfo,
		Origin:         origin,
	}
	if err := request.validate(); err != nil {
		return empty, err
	}
	return request, nil
}

// decodeBase64Url decodes base64url whether or not the sender padded it.
//
// 18013-7 Annex C says base64url and RFC 4648 §5 makes the padding optional, so
// both spellings are conformant and a wallet that accepts only one would refuse a
// verifier for a choice the standard leaves open. Matches how the encryptionInfo
// key is recovered in session.go.
func decodeBase64Url(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(encoded, "="))
}
