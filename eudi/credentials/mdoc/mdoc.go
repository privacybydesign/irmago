// Package mdoc implements the ISO/IEC 18013-5:2021 mdoc credential data model.
//
// Scope: wallet-side receipt and storage of an mdoc credential obtained via
// OpenID4VCI (the `mso_mdoc` credential format). Proximity transport
// (BLE/NFC), device authentication, and verifier logic are out of scope for
// this package.
package mdoc

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// DocType is an mdoc document type identifier, e.g. "org.iso.18013.5.1.mDL".
type DocType = string

// NamespaceName is an mdoc namespace identifier, e.g. "org.iso.18013.5.1".
type NamespaceName = string

// MDLDocType is the mDL document type defined by ISO/IEC 18013-5.
const MDLDocType DocType = "org.iso.18013.5.1.mDL"

// MDLNamespace is the default namespace for mDL data elements.
const MDLNamespace NamespaceName = "org.iso.18013.5.1"

// DigestAlgorithm names the hash algorithm used to compute value digests
// in the MobileSecurityObject. ISO 18013-5 §9.1.2.5 lists SHA-256, SHA-384,
// and SHA-512.
type DigestAlgorithm string

const (
	SHA256 DigestAlgorithm = "SHA-256"
	SHA384 DigestAlgorithm = "SHA-384"
	SHA512 DigestAlgorithm = "SHA-512"
)

// tagEncodedCBOR is CBOR tag 24 — "Encoded CBOR data item" (RFC 8949 §3.4.5).
// ISO 18013-5 wraps IssuerSignedItem and MobileSecurityObject in this tag so
// the signed/hashed bytes are unambiguously the bstr contents.
const tagEncodedCBOR uint64 = 24

// IssuerSigned is the CBOR structure delivered by the issuer to the wallet
// (ISO/IEC 18013-5 §8.3.2.1.2.2). Via OpenID4VCI it arrives as the value of
// the `credential` field in a credential response.
type IssuerSigned struct {
	Namespaces IssuerNamespaces
	IssuerAuth IssuerAuth
}

// IssuerNamespaces maps each namespace to its ordered list of IssuerSignedItems.
type IssuerNamespaces map[NamespaceName][]IssuerSignedItem

// IssuerSignedItem is a single disclosed data element (ISO 18013-5 §8.3.2.1.2.2).
type IssuerSignedItem struct {
	DigestID          uint64
	Random            []byte
	ElementIdentifier string
	// ElementValue is the raw CBOR encoding of the element value, preserving
	// any tags / encoding choices made by the issuer.
	ElementValue []byte

	// taggedBytes is the raw encoded #6.24(bstr .cbor IssuerSignedItem) as it
	// appeared on the wire. It is what the MSO digest is computed over — see
	// ISO 18013-5 §9.1.2.5. Populated by the parser.
	taggedBytes []byte
}

// Digest returns the digest of this item as stored in MSO.ValueDigests:
// H( CBOR( #6.24( bstr( CBOR(item) ) ) ) ) where H is the named algorithm.
// The implementation hashes the raw on-wire bytes so re-encoding ambiguity
// cannot break the comparison.
func (i IssuerSignedItem) Digest(alg DigestAlgorithm) ([]byte, error) {
	if len(i.taggedBytes) == 0 {
		return nil, errors.New("mdoc: item is missing raw bytes; was it created by the parser?")
	}
	h, err := newHash(alg)
	if err != nil {
		return nil, err
	}
	h.Write(i.taggedBytes)
	return h.Sum(nil), nil
}

func newHash(alg DigestAlgorithm) (hash.Hash, error) {
	switch alg {
	case SHA256:
		return sha256.New(), nil
	case SHA384:
		return sha512.New384(), nil
	case SHA512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("mdoc: unsupported digest algorithm %q", alg)
	}
}

// IssuerAuth is the untagged COSE_Sign1 structure wrapping the MSO
// (ISO 18013-5 §9.1.2.4). Signature verification is the responsibility of a
// higher-level trust component; this type just carries the parts.
type IssuerAuth struct {
	ProtectedHeader   []byte
	UnprotectedHeader map[any]any
	Payload           []byte // the bstr contents; decodes to tag(24, bstr(MSO))
	Signature         []byte
}

// coseHeaderX5Chain is the COSE header parameter that carries the X.509
// certificate chain (RFC 9360). In ISO 18013-5 mdoc the DS certificate
// chaining up to the IACA root lives in the IssuerAuth unprotected header.
const coseHeaderX5Chain = 33

// X5Chain returns the DER-encoded X.509 certificates carried in the
// IssuerAuth unprotected header (RFC 9360). The first element is the
// Document Signer certificate; further elements chain up toward IACA.
// Returns an empty slice when no x5chain is present.
func (a IssuerAuth) X5Chain() ([]*x509.Certificate, error) {
	raw, ok := findHeaderInt(a.UnprotectedHeader, coseHeaderX5Chain)
	if !ok {
		return nil, nil
	}
	var ders [][]byte
	switch v := raw.(type) {
	case []byte:
		ders = [][]byte{v}
	case []any:
		for i, e := range v {
			b, ok := e.([]byte)
			if !ok {
				return nil, fmt.Errorf("mdoc: x5chain[%d] is %T, want bstr", i, e)
			}
			ders = append(ders, b)
		}
	default:
		return nil, fmt.Errorf("mdoc: x5chain header is %T, want bstr or array", raw)
	}
	out := make([]*x509.Certificate, 0, len(ders))
	for i, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("mdoc: x5chain[%d]: %w", i, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// findHeaderInt looks up a COSE header parameter with numeric key `want`,
// accommodating the assorted integer types fxamacker/cbor may decode into.
func findHeaderInt(h map[any]any, want int64) (any, bool) {
	for k, v := range h {
		switch n := k.(type) {
		case int64:
			if n == want {
				return v, true
			}
		case uint64:
			if int64(n) == want {
				return v, true
			}
		case int:
			if int64(n) == want {
				return v, true
			}
		}
	}
	return nil, false
}

// MobileSecurityObject parses and returns the MSO contained in the
// IssuerAuth payload (ISO 18013-5 §9.1.2.4).
func (a IssuerAuth) MobileSecurityObject() (*MobileSecurityObject, error) {
	if len(a.Payload) == 0 {
		return nil, errors.New("mdoc: issuerAuth has empty payload")
	}
	var wrapped cbor.Tag
	if err := cbor.Unmarshal(a.Payload, &wrapped); err != nil {
		return nil, fmt.Errorf("mdoc: decode MSO tag: %w", err)
	}
	if wrapped.Number != tagEncodedCBOR {
		return nil, fmt.Errorf("mdoc: MSO payload has tag %d, want 24", wrapped.Number)
	}
	inner, ok := wrapped.Content.([]byte)
	if !ok {
		return nil, fmt.Errorf("mdoc: MSO tag content is %T, want bstr", wrapped.Content)
	}

	var raw rawMSO
	if err := msoDecMode.Unmarshal(inner, &raw); err != nil {
		return nil, fmt.Errorf("mdoc: decode MSO: %w", err)
	}
	return raw.toMSO()
}

// MobileSecurityObject is the issuer-signed core of an mdoc credential
// (ISO 18013-5 §9.1.2.4).
type MobileSecurityObject struct {
	Version                         string
	DigestAlgorithm                 DigestAlgorithm
	DocType                         DocType
	ValueDigests                    map[NamespaceName]map[uint64][]byte
	DeviceKey                       *DeviceKey
	DeviceKeyAuthorizedNamespaces   []NamespaceName
	DeviceKeyAuthorizedDataElements map[NamespaceName][]string
	ValidityInfo                    ValidityInfo
}

// ValidityInfo is the validity information in the MSO (ISO 18013-5 §9.1.2.4).
type ValidityInfo struct {
	Signed         time.Time
	ValidFrom      time.Time
	ValidUntil     time.Time
	ExpectedUpdate *time.Time
}

// DeviceKey is the mdoc holder's key-binding key (a COSE_Key EC2 key).
type DeviceKey struct {
	Kty   int
	Curve int
	X     []byte
	Y     []byte
}

// ParseIssuerSigned decodes a CBOR-encoded IssuerSigned structure — the value
// delivered by an OpenID4VCI credential response for the `mso_mdoc` format.
func ParseIssuerSigned(data []byte) (*IssuerSigned, error) {
	var raw rawIssuerSigned
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("mdoc: decode IssuerSigned: %w", err)
	}
	return raw.toIssuerSigned()
}

// ExtractIssuerSignedFromDeviceResponse pulls the first document's IssuerSigned
// out of an ISO 18013-5 §8.3.2.1.2.1 DeviceResponse. Primarily a helper for
// exercising the Annex D test vectors against the wallet-side parsing code.
func ExtractIssuerSignedFromDeviceResponse(deviceResponse []byte) (*IssuerSigned, error) {
	var raw rawDeviceResponse
	if err := cbor.Unmarshal(deviceResponse, &raw); err != nil {
		return nil, fmt.Errorf("mdoc: decode DeviceResponse: %w", err)
	}
	if len(raw.Documents) == 0 {
		return nil, errors.New("mdoc: DeviceResponse has no documents")
	}
	return raw.Documents[0].IssuerSigned.toIssuerSigned()
}

// ---- CBOR-level types ------------------------------------------------------

// msoDecMode decodes time-tagged (#6.0 tdate) values into time.Time and
// accepts the extra fields ISO 18013-5 may add to core maps.
var msoDecMode = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		TimeTag: cbor.DecTagRequired,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

type rawDeviceResponse struct {
	Version   string        `cbor:"version"`
	Documents []rawDocument `cbor:"documents"`
	Status    uint          `cbor:"status"`
}

type rawDocument struct {
	DocType      string           `cbor:"docType"`
	IssuerSigned rawIssuerSigned  `cbor:"issuerSigned"`
	DeviceSigned cbor.RawMessage  `cbor:"deviceSigned,omitempty"`
	Errors       cbor.RawMessage  `cbor:"errors,omitempty"`
}

type rawIssuerSigned struct {
	// Each element is the raw CBOR encoding of #6.24(bstr .cbor IssuerSignedItem).
	// We keep it raw so we can hash the exact on-wire bytes.
	NameSpaces map[string][]cbor.RawMessage `cbor:"nameSpaces"`
	IssuerAuth rawCOSESign1                 `cbor:"issuerAuth"`
}

func (r *rawIssuerSigned) toIssuerSigned() (*IssuerSigned, error) {
	nss := make(IssuerNamespaces, len(r.NameSpaces))
	for ns, rawItems := range r.NameSpaces {
		items := make([]IssuerSignedItem, 0, len(rawItems))
		for idx, rawItem := range rawItems {
			item, err := decodeIssuerSignedItem(rawItem)
			if err != nil {
				return nil, fmt.Errorf("mdoc: namespace %q item %d: %w", ns, idx, err)
			}
			items = append(items, item)
		}
		nss[ns] = items
	}
	return &IssuerSigned{
		Namespaces: nss,
		IssuerAuth: IssuerAuth{
			ProtectedHeader:   r.IssuerAuth.Protected,
			UnprotectedHeader: r.IssuerAuth.Unprotected,
			Payload:           r.IssuerAuth.Payload,
			Signature:         r.IssuerAuth.Signature,
		},
	}, nil
}

func decodeIssuerSignedItem(taggedBytes cbor.RawMessage) (IssuerSignedItem, error) {
	var tagged cbor.Tag
	if err := cbor.Unmarshal(taggedBytes, &tagged); err != nil {
		return IssuerSignedItem{}, fmt.Errorf("decode tag: %w", err)
	}
	if tagged.Number != tagEncodedCBOR {
		return IssuerSignedItem{}, fmt.Errorf("item has tag %d, want 24", tagged.Number)
	}
	inner, ok := tagged.Content.([]byte)
	if !ok {
		return IssuerSignedItem{}, fmt.Errorf("item tag content is %T, want bstr", tagged.Content)
	}

	var m rawIssuerSignedItem
	if err := cbor.Unmarshal(inner, &m); err != nil {
		return IssuerSignedItem{}, fmt.Errorf("decode item map: %w", err)
	}

	return IssuerSignedItem{
		DigestID:          m.DigestID,
		Random:            m.Random,
		ElementIdentifier: m.ElementIdentifier,
		ElementValue:      []byte(m.ElementValue),
		taggedBytes:       append([]byte(nil), taggedBytes...),
	}, nil
}

type rawIssuerSignedItem struct {
	DigestID          uint64          `cbor:"digestID"`
	Random            []byte          `cbor:"random"`
	ElementIdentifier string          `cbor:"elementIdentifier"`
	ElementValue      cbor.RawMessage `cbor:"elementValue"`
}

// rawCOSESign1 is the untagged 4-element array form of COSE_Sign1 (RFC 9052 §4.2).
type rawCOSESign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[any]any
	Payload     []byte
	Signature   []byte
}

type rawMSO struct {
	Version         string                       `cbor:"version"`
	DigestAlgorithm string                       `cbor:"digestAlgorithm"`
	ValueDigests    map[string]map[uint64][]byte `cbor:"valueDigests"`
	DeviceKeyInfo   rawDeviceKeyInfo             `cbor:"deviceKeyInfo"`
	DocType         string                       `cbor:"docType"`
	ValidityInfo    rawValidityInfo              `cbor:"validityInfo"`
}

func (r *rawMSO) toMSO() (*MobileSecurityObject, error) {
	dk, err := r.DeviceKeyInfo.DeviceKey.toDeviceKey()
	if err != nil {
		return nil, err
	}

	var authNS []string
	var authDE map[string][]string
	if r.DeviceKeyInfo.KeyAuthorizations != nil {
		authNS = r.DeviceKeyInfo.KeyAuthorizations.NameSpaces
		authDE = r.DeviceKeyInfo.KeyAuthorizations.DataElements
	}

	return &MobileSecurityObject{
		Version:                         r.Version,
		DigestAlgorithm:                 DigestAlgorithm(r.DigestAlgorithm),
		DocType:                         r.DocType,
		ValueDigests:                    r.ValueDigests,
		DeviceKey:                       dk,
		DeviceKeyAuthorizedNamespaces:   authNS,
		DeviceKeyAuthorizedDataElements: authDE,
		ValidityInfo: ValidityInfo{
			Signed:         r.ValidityInfo.Signed,
			ValidFrom:      r.ValidityInfo.ValidFrom,
			ValidUntil:     r.ValidityInfo.ValidUntil,
			ExpectedUpdate: r.ValidityInfo.ExpectedUpdate,
		},
	}, nil
}

type rawDeviceKeyInfo struct {
	DeviceKey         rawCOSEKey             `cbor:"deviceKey"`
	KeyAuthorizations *rawKeyAuthorizations  `cbor:"keyAuthorizations,omitempty"`
	KeyInfo           map[int]cbor.RawMessage `cbor:"keyInfo,omitempty"`
}

type rawKeyAuthorizations struct {
	NameSpaces   []string            `cbor:"nameSpaces,omitempty"`
	DataElements map[string][]string `cbor:"dataElements,omitempty"`
}

// rawCOSEKey captures the subset of COSE_Key fields ISO 18013-5 uses for
// mdoc DeviceKey: EC2 key with kty/crv/x/y.
type rawCOSEKey struct {
	Kty int    `cbor:"1,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

func (k rawCOSEKey) toDeviceKey() (*DeviceKey, error) {
	return &DeviceKey{
		Kty:   k.Kty,
		Curve: k.Crv,
		X:     k.X,
		Y:     k.Y,
	}, nil
}

type rawValidityInfo struct {
	Signed         time.Time  `cbor:"signed"`
	ValidFrom      time.Time  `cbor:"validFrom"`
	ValidUntil     time.Time  `cbor:"validUntil"`
	ExpectedUpdate *time.Time `cbor:"expectedUpdate,omitempty"`
}

// ---- small helpers used by the tests ---------------------------------------

// decodeTstr decodes a CBOR major-type-3 (text string) value.
func decodeTstr(raw []byte) (string, error) {
	var s string
	if err := cbor.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("mdoc: decode tstr: %w", err)
	}
	return s, nil
}

// decodeBstr decodes a CBOR major-type-2 (byte string) value.
func decodeBstr(raw []byte) ([]byte, error) {
	var b []byte
	if err := cbor.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("mdoc: decode bstr: %w", err)
	}
	return b, nil
}
