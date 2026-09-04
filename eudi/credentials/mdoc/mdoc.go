package mdoc

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// CORE WIRE FORMAT — the mdoc envelope itself
// ============================================================

// MDoc is the top-level credential container
//
// DeviceSigned is a pointer and omitted from CBOR when nil: it doesn't
// exist right after issuance, only once a holder has signed deviceAuth
// for a specific presentation and attached it via AttachDeviceSigned.
type MDoc struct {
	DocType      string        `cbor:"docType"`
	IssuerSigned IssuerSigned  `cbor:"issuerSigned"`
	DeviceSigned *DeviceSigned `cbor:"deviceSigned,omitempty"`
}

// IssuerSignedItem is the 4-field envelope for each claim
// All 4 fields together get Tag-24 wrapped and SHA-256 hashed → the digest
// stored in MSO.ValueDigests
type IssuerSignedItem struct {
	DigestID          uint64 `cbor:"digestID"`          // index into ValueDigests map
	Random            []byte `cbor:"random"`            // ≥16 byte salt — prevents brute force
	ElementIdentifier string `cbor:"elementIdentifier"` // attribute name e.g. "age_over_18"
	ElementValue      any    `cbor:"elementValue"`      // attribute value e.g. true
}

// DeviceKeyInfo wraps the holder's device public key inside the MSO
// The issuer embeds this at issuance — locks in which device can present this credential
//
// KeyAuthorizations and KeyInfo are optional in ISO/IEC 18013-5 9.1.2.4 and are
// carried here so a document that has them can be verified, not so this issuer
// can emit them: both are omitempty and left nil by Issue, which keeps the
// encoded — and therefore signed — DeviceKeyInfo byte-identical to before they
// were modelled. Dropping them from the struct instead meant the verifier
// silently discarded keyAuthorizations at decode and then had nothing to check
// holder-asserted elements against, which is half of why those elements were
// refused for every docType.
type DeviceKeyInfo struct {
	DeviceKey         COSEKey            `cbor:"deviceKey"`
	KeyAuthorizations *KeyAuthorizations `cbor:"keyAuthorizations,omitempty"`
	KeyInfo           map[int64]any      `cbor:"keyInfo,omitempty"`
}

// KeyAuthorizations names what the device key is allowed to assert on the
// holder's behalf, per ISO/IEC 18013-5 9.1.2.4:
//
//	KeyAuthorizations = { ? "nameSpaces" : AuthorizedNameSpaces,
//	                      ? "dataElements" : AuthorizedDataElements }
//
// A namespace listed in NameSpaces authorizes everything under it, and the
// clause forbids that namespace also appearing in DataElements.
type KeyAuthorizations struct {
	NameSpaces   []string            `cbor:"nameSpaces,omitempty"`
	DataElements map[string][]string `cbor:"dataElements,omitempty"`
}

// isEmpty reports the case 9.1.2.4 forbids an issuer from producing ("If the
// KeyAuthorizations map is present, it shall not be empty") and which a verifier
// therefore has to treat as authorizing nothing.
func (k *KeyAuthorizations) isEmpty() bool {
	return k == nil || (len(k.NameSpaces) == 0 && len(k.DataElements) == 0)
}

// MSO (Mobile Security Object) is the signed data structure inside issuerAuth
// It commits to all claim digests + device key + validity — signed by DS cert
type MSO struct {
	Version         string                       `cbor:"version"`
	DigestAlgorithm string                       `cbor:"digestAlgorithm"`
	ValueDigests    map[string]map[uint64][]byte `cbor:"valueDigests"` // namespace → digestID → SHA-256 hash
	DocType         string                       `cbor:"docType"`
	ValidityInfo    ValidityInfo                 `cbor:"validityInfo"`
	DeviceKeyInfo   DeviceKeyInfo                `cbor:"deviceKeyInfo"` // holder's device public key
}

type ValidityInfo struct {
	Signed     time.Time `cbor:"signed"`
	ValidFrom  time.Time `cbor:"validFrom"`
	ValidUntil time.Time `cbor:"validUntil"`
}

// IssuerSigned bundles the revealed claim items + the issuer's COSE_Sign1 signature
//
// IssuerAuth is cbor.RawMessage, not []byte: ISO 18013-5 has
// `IssuerAuth = COSE_Sign1`, so the four-element COSE array must sit inline at
// this position. A []byte field would encode it as a CBOR byte string wrapping
// those bytes, which no conformant verifier can read — Multipaz, for one, does
// `issuerSigned["issuerAuth"].asCoseSign1` on a structured item. Same reasoning
// as DeviceAuth.DeviceSignature, which already had it.
type IssuerSigned struct {
	NameSpaces map[string][]Tag24Item `cbor:"nameSpaces"` // only DISCLOSED items travel here
	IssuerAuth cbor.RawMessage        `cbor:"issuerAuth"` // COSE_Sign1 over MSO — unchanged across presentations
}

// Tag24Item holds the raw Tag-24 wrapped bytes of one IssuerSignedItem
// "frozen" bytes — must not be re-encoded, otherwise digest won't match
//
// The custom marshalling is load-bearing rather than cosmetic. ISO 18013-5 has
// `IssuerNameSpaces = {+ NameSpace => [+ IssuerSignedItemBytes]}` with
// `IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)`, so each array
// element is the tag-24 value itself. Left to fxamacker/cbor's struct default
// this one-field struct encodes as the map {"EncodedItem": <bstr>} — a Go field
// name on the wire, wrapping the tag-24 value in a second byte-string layer.
// That round-trips against this package and against nothing else.
//
// EncodedItem already holds the complete tag-24 encoding (see tag24Wrap), so
// marshalling emits it verbatim and unmarshalling captures it verbatim; the
// digest is taken over exactly these bytes either way, which is why fixing the
// transport shape does not disturb any signature or digest.
type Tag24Item struct {
	EncodedItem []byte
}

// MarshalCBOR emits the pre-encoded tag-24 item as-is.
func (t Tag24Item) MarshalCBOR() ([]byte, error) {
	if len(t.EncodedItem) == 0 {
		return nil, fmt.Errorf("mdoc: Tag24Item has no encoded item to marshal")
	}
	return t.EncodedItem, nil
}

// UnmarshalCBOR captures the tag-24 item's raw bytes without re-encoding them,
// verifying only that this really is a tag 24 wrapping a byte string.
func (t *Tag24Item) UnmarshalCBOR(data []byte) error {
	var rawTag cbor.RawTag
	if err := mdocDecMode.Unmarshal(data, &rawTag); err != nil {
		return fmt.Errorf("mdoc: issuerSignedItem is not tag-24 embedded CBOR: %w", err)
	}
	if rawTag.Number != 24 {
		return fmt.Errorf("mdoc: issuerSignedItem has CBOR tag %d, want 24", rawTag.Number)
	}
	var inner []byte
	if err := mdocDecMode.Unmarshal(rawTag.Content, &inner); err != nil {
		return fmt.Errorf("mdoc: tag-24 issuerSignedItem does not wrap a byte string: %w", err)
	}
	t.EncodedItem = append([]byte(nil), data...)
	return nil
}

// DeviceAuthentication is the CBOR array that deviceAuth signs over
// It is a CBOR array (not map) — hence the toarray tag on the blank field
// This structure is built fresh every presentation — ties deviceAuth to one session
//
// DeviceNameSpaces is cbor.RawMessage for the reason given on
// IssuerSigned.IssuerAuth: ISO 18013-5's DeviceNameSpacesBytes is
// `#6.24(bstr .cbor DeviceNameSpaces)`, and the field already holds that
// complete tag-24 encoding, so it must go on the wire inline rather than inside
// another byte string.
//
// The holder puts tag24(empty map) here — the AV profile has no holder-asserted
// claims — and transmits those same bytes at deviceSigned.nameSpaces. The
// verifier rebuilds this structure from the transmitted bytes rather than
// assuming them, so the two sides agree without depending on a shared encoding
// choice; see deviceNameSpacesForVerification.
type DeviceAuthentication struct {
	_                 struct{}          `cbor:",toarray"`
	Context           string            // always "DeviceAuthentication"
	SessionTranscript SessionTranscript // fresh per session — defeats replay attacks
	DocType           string
	DeviceNameSpaces  cbor.RawMessage // Tag24(empty map) for AV — no holder-added claims
}

// SessionTranscript binds a presentation to a specific verifier session
// Contains the verifier's engagement bytes + ephemeral key + handover info
// Also a CBOR array — toarray tag required
//
// Handover is `any` because its shape depends on the transport: a bare
// string in most tests (via testhelpers_test.go's buildHappyPathMDoc
// stub, where no real session exists), or a real structured value for an
// actual OpenID4VP presentation — built by newOpenID4VPSessionTranscript
// in eudi/openid4vp/mdoc_dcql as
// ["OpenID4VPHandover", SHA-256(CBOR([clientId, nonce, null, responseUri]))].
// That construction lives there, not here, because this package holds no
// OpenID4VP knowledge of its own — hence the open type.
type SessionTranscript struct {
	_                     struct{} `cbor:",toarray"`
	DeviceEngagementBytes []byte   // from QR code / NFC tap
	EReaderKeyBytes       []byte   // verifier's ephemeral public key
	Handover              any      // session-specific binding data
}

// SelectiveDisclose filters the credential to only include the requested attributes
// issuerAuth is reused unchanged — the issuer's signature covers all digests regardless
// of which subset the holder chooses to reveal at any given presentation
func SelectiveDisclose(mdoc *MDoc, namespace string, reveal []string) (*MDoc, error) {
	revealSet := make(map[string]bool)
	for _, r := range reveal {
		revealSet[r] = true
	}

	allItems := mdoc.IssuerSigned.NameSpaces[namespace]
	var disclosed []Tag24Item

	for _, tag24item := range allItems {
		// decode Tag-24 wrapped item to peek at the elementIdentifier
		var rawTag cbor.RawTag
		if err := mdocDecMode.Unmarshal(tag24item.EncodedItem, &rawTag); err != nil {
			return nil, fmt.Errorf("unwrap tag24: %w", err)
		}
		var innerBytes []byte
		if err := mdocDecMode.Unmarshal(rawTag.Content, &innerBytes); err != nil {
			return nil, fmt.Errorf("unwrap inner bytes: %w", err)
		}
		var item IssuerSignedItem
		if err := mdocDecMode.Unmarshal(innerBytes, &item); err != nil {
			return nil, fmt.Errorf("decode item: %w", err)
		}

		if revealSet[item.ElementIdentifier] {
			disclosed = append(disclosed, tag24item)
		}
	}

	// ISO 18013-5 has `IssuerNameSpaces = {+ NameSpace => [+ IssuerSignedItemBytes]}`
	// — a namespace key must map to at least one item. A nil slice here encodes as
	// CBOR null under a present namespace key, which is neither an array nor an
	// absent namespace, and no conformant verifier can read it.
	//
	// Erroring rather than dropping the namespace, for the reason
	// selectiveDiscloseByPaths gives: a presentation quietly missing what the user
	// consented to disclose is indistinguishable downstream from a verifier that
	// asked for less. Unreachable through the DCQL handler, which refuses an empty
	// claim set up front — this is the guard for direct callers of the exported
	// function.
	if len(disclosed) == 0 {
		return nil, fmt.Errorf(
			"selective disclosure of namespace %q revealed no elements: none of %v is present in the credential",
			namespace, reveal)
	}

	return &MDoc{
		DocType: mdoc.DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{namespace: disclosed},
			IssuerAuth: mdoc.IssuerSigned.IssuerAuth, // reused unchanged
		},
	}, nil
}
