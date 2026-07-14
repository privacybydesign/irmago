package mdoc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// DEVICE RESPONSE — the top-level container a holder actually
// transmits to a verifier, per ISO 18013-5
// ============================================================

// DeviceSigned bundles the holder-signed portion of a presented document:
// NameSpaces (any holder-asserted claims — always empty for this profile,
// since eu.europa.ec.av.1 has no holder-added attributes) and DeviceAuth
// (the COSE_Sign1 proving device possession).
type DeviceSigned struct {
	NameSpaces []byte     `cbor:"nameSpaces"` // Tag24(empty map) — see holder.go's SignDeviceAuth
	DeviceAuth DeviceAuth `cbor:"deviceAuth"`
}

// DeviceAuth holds the holder's device signature. ISO 18013-5 defines this
// as a choice between deviceSignature (COSE_Sign1) and deviceMac
// (COSE_Mac0) — only deviceSignature is modeled here, matching the rest of
// this package (SignDeviceAuth only ever produces an ECDSA signature).
//
// DeviceSignature is cbor.RawMessage, not []byte: the COSE_Sign1 array
// must be embedded inline as CBOR (matching the real ISO 18013-5 shape),
// not wrapped in an extra byte-string layer the way a plain []byte field
// would encode it.
type DeviceAuth struct {
	DeviceSignature cbor.RawMessage `cbor:"deviceSignature"`
}

// AttachDeviceSigned returns a copy of mdoc with DeviceSigned populated
// from a deviceAuth signature already produced by Holder.SignDeviceAuth.
// Kept separate from SignDeviceAuth itself so existing callers that just
// want the raw deviceAuth bytes (e.g. Verifier.VerifyWithDeviceAuth, which
// takes them as a parameter rather than reading mdoc.DeviceSigned) don't
// need to change — this is purely additive, for building a real
// DeviceResponse to bundle up and transmit.
func AttachDeviceSigned(mdoc *MDoc, deviceAuthBytes []byte) (*MDoc, error) {
	emptyNS, err := tag24Wrap(map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("wrap empty deviceNameSpaces: %w", err)
	}

	attached := *mdoc
	attached.DeviceSigned = &DeviceSigned{
		NameSpaces: emptyNS,
		DeviceAuth: DeviceAuth{DeviceSignature: cbor.RawMessage(deviceAuthBytes)},
	}
	return &attached, nil
}

// DeviceResponse is the top-level container ISO 18013-5 actually transmits
// to the verifier — as opposed to a bare MDoc, which is what this
// package's issuer/holder/verifier functions work with directly. Real
// ISO 18013-5 also allows documentErrors (whole documents that failed)
// and per-document errors; neither is modeled here since this profile
// only ever presents a single document with no partial-failure cases.
type DeviceResponse struct {
	Version   string `cbor:"version"`
	Documents []MDoc `cbor:"documents"`
	Status    uint64 `cbor:"status"` // 0 = OK, per ISO 18013-5 Table 8
}

// NewDeviceResponse bundles one or more presented documents (each already
// carrying DeviceSigned via AttachDeviceSigned) into a DeviceResponse.
func NewDeviceResponse(documents ...MDoc) DeviceResponse {
	return DeviceResponse{
		Version:   "1.0",
		Documents: documents,
		Status:    0,
	}
}
