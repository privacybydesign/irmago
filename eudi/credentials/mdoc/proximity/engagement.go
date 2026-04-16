package proximity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

// tagEncodedCBOR is CBOR tag 24 — "Encoded CBOR data item" (RFC 8949 §3.4.5).
const tagEncodedCBOR uint64 = 24

// DeviceEngagement is the CBOR structure emitted by the mdoc holder as the
// QR-code (or NFC) payload that bootstraps a proximity session. See
// ISO/IEC 18013-5:2021 §8.2.1.
type DeviceEngagement struct {
	Version           string
	EDeviceKey        *ecdsa.PublicKey
	EDeviceKeyBytes   []byte
	ConnectionMethods []ConnectionMethod
}

// ConnectionMethod is the mdoc-side description of a transport (BLE, NFC,
// Wi-Fi Aware, HTTP server) encoded as a 3-element CBOR array
// [type, version, retrievalOptions].
type ConnectionMethod interface {
	connectionMethod()
}

// BLEConnectionMethod is the BLE retrieval method (type=2, version=1) from
// ISO/IEC 18013-5 §8.2.2.3.
type BLEConnectionMethod struct {
	SupportsPeripheralServerMode bool
	SupportsCentralClientMode    bool
	PeripheralServerModeUUID     *uuid.UUID
	CentralClientModeUUID        *uuid.UUID
}

func (BLEConnectionMethod) connectionMethod() {}

// ConnectionMethod constants (ISO/IEC 18013-5 §8.2.2).
const (
	connectionMethodBLE = 2

	bleOptSupportsPeripheralServer = 0
	bleOptSupportsCentralClient    = 1
	bleOptPeripheralServerUUID     = 10
	bleOptCentralClientUUID        = 11

	bleMethodMaxVersion = 1
)

// coseKeyEC2 is the subset of COSE_Key used for P-256 session-encryption keys.
type coseKeyEC2 struct {
	Kty int    `cbor:"1,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

const (
	coseKtyEC2  = 2
	coseCrvP256 = 1
)

// ParseDeviceEngagement decodes a DeviceEngagement CBOR payload.
func ParseDeviceEngagement(data []byte) (*DeviceEngagement, error) {
	var m map[int]cbor.RawMessage
	if err := cbor.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("proximity: decode DeviceEngagement: %w", err)
	}

	var version string
	if err := cbor.Unmarshal(m[0], &version); err != nil {
		return nil, fmt.Errorf("proximity: decode version: %w", err)
	}

	var security []cbor.RawMessage
	if err := cbor.Unmarshal(m[1], &security); err != nil {
		return nil, fmt.Errorf("proximity: decode security: %w", err)
	}
	if len(security) < 2 {
		return nil, errors.New("proximity: security array too short")
	}
	var cipherSuite int
	if err := cbor.Unmarshal(security[0], &cipherSuite); err != nil {
		return nil, fmt.Errorf("proximity: decode cipher suite: %w", err)
	}
	if cipherSuite != 1 {
		return nil, fmt.Errorf("proximity: unsupported cipher suite %d", cipherSuite)
	}
	eDeviceKey, err := decodeTag24CoseKey(security[1])
	if err != nil {
		return nil, fmt.Errorf("proximity: decode eDeviceKey: %w", err)
	}

	out := &DeviceEngagement{
		Version:         version,
		EDeviceKey:      eDeviceKey,
		EDeviceKeyBytes: append([]byte(nil), security[1]...),
	}

	if raw, ok := m[2]; ok {
		var arr []cbor.RawMessage
		if err := cbor.Unmarshal(raw, &arr); err != nil {
			return nil, fmt.Errorf("proximity: decode connection methods: %w", err)
		}
		for i, rawMethod := range arr {
			cm, err := parseConnectionMethod(rawMethod)
			if err != nil {
				return nil, fmt.Errorf("proximity: connection method %d: %w", i, err)
			}
			if cm != nil {
				out.ConnectionMethods = append(out.ConnectionMethods, cm)
			}
		}
	}
	return out, nil
}

// EncodeDeviceEngagement encodes a DeviceEngagement to CBOR suitable for a QR
// payload.
func EncodeDeviceEngagement(e *DeviceEngagement) ([]byte, error) {
	if e == nil || e.EDeviceKey == nil {
		return nil, errors.New("proximity: DeviceEngagement and EDeviceKey required")
	}
	version := e.Version
	if version == "" {
		version = "1.0"
	}

	coseKey := ecPubToCoseKey(e.EDeviceKey)
	coseKeyBytes, err := cbor.Marshal(coseKey)
	if err != nil {
		return nil, err
	}
	eDeviceKeyBytes, err := cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: coseKeyBytes})
	if err != nil {
		return nil, err
	}
	security, err := cbor.Marshal([]any{1, cbor.RawMessage(eDeviceKeyBytes)})
	if err != nil {
		return nil, err
	}

	m := make(map[int]cbor.RawMessage, 3)
	m[0] = mustMarshal(version)
	m[1] = security
	if len(e.ConnectionMethods) > 0 {
		encMethods := make([]cbor.RawMessage, len(e.ConnectionMethods))
		for i, cm := range e.ConnectionMethods {
			enc, err := encodeConnectionMethod(cm)
			if err != nil {
				return nil, fmt.Errorf("proximity: encode connection method %d: %w", i, err)
			}
			encMethods[i] = enc
		}
		raw, err := cbor.Marshal(encMethods)
		if err != nil {
			return nil, err
		}
		m[2] = raw
	}

	return cbor.Marshal(m)
}

func parseConnectionMethod(data []byte) (ConnectionMethod, error) {
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(data, &arr); err != nil {
		return nil, err
	}
	if len(arr) < 3 {
		return nil, errors.New("connection method array too short")
	}
	var typ, ver uint64
	if err := cbor.Unmarshal(arr[0], &typ); err != nil {
		return nil, err
	}
	if err := cbor.Unmarshal(arr[1], &ver); err != nil {
		return nil, err
	}
	switch typ {
	case connectionMethodBLE:
		if ver > bleMethodMaxVersion {
			// Unknown newer version; skip rather than fail.
			return nil, nil
		}
		return parseBLEMethod(arr[2])
	default:
		// Silently skip transports we do not model (NFC, Wi-Fi Aware).
		return nil, nil
	}
}

func parseBLEMethod(optsRaw cbor.RawMessage) (BLEConnectionMethod, error) {
	var opts map[int]cbor.RawMessage
	if err := cbor.Unmarshal(optsRaw, &opts); err != nil {
		return BLEConnectionMethod{}, err
	}
	var b BLEConnectionMethod
	if err := cbor.Unmarshal(opts[bleOptSupportsPeripheralServer], &b.SupportsPeripheralServerMode); err != nil {
		return b, fmt.Errorf("decode supportsPeripheralServerMode: %w", err)
	}
	if err := cbor.Unmarshal(opts[bleOptSupportsCentralClient], &b.SupportsCentralClientMode); err != nil {
		return b, fmt.Errorf("decode supportsCentralClientMode: %w", err)
	}
	if raw, ok := opts[bleOptPeripheralServerUUID]; ok {
		u, err := uuidFromCBORBstr(raw)
		if err != nil {
			return b, err
		}
		b.PeripheralServerModeUUID = &u
	}
	if raw, ok := opts[bleOptCentralClientUUID]; ok {
		u, err := uuidFromCBORBstr(raw)
		if err != nil {
			return b, err
		}
		b.CentralClientModeUUID = &u
	}
	return b, nil
}

func encodeConnectionMethod(cm ConnectionMethod) ([]byte, error) {
	switch v := cm.(type) {
	case BLEConnectionMethod:
		opts := make(map[int]any, 4)
		opts[bleOptSupportsPeripheralServer] = v.SupportsPeripheralServerMode
		opts[bleOptSupportsCentralClient] = v.SupportsCentralClientMode
		if v.PeripheralServerModeUUID != nil {
			opts[bleOptPeripheralServerUUID] = v.PeripheralServerModeUUID[:]
		}
		if v.CentralClientModeUUID != nil {
			opts[bleOptCentralClientUUID] = v.CentralClientModeUUID[:]
		}
		return cbor.Marshal([]any{connectionMethodBLE, bleMethodMaxVersion, opts})
	default:
		return nil, fmt.Errorf("proximity: encode unsupported connection method %T", cm)
	}
}

// decodeTag24CoseKey unwraps #6.24(bstr .cbor COSE_Key) and returns the parsed
// EC public key.
func decodeTag24CoseKey(data []byte) (*ecdsa.PublicKey, error) {
	var tagged cbor.Tag
	if err := cbor.Unmarshal(data, &tagged); err != nil {
		return nil, err
	}
	if tagged.Number != tagEncodedCBOR {
		return nil, fmt.Errorf("expected tag 24, got %d", tagged.Number)
	}
	inner, ok := tagged.Content.([]byte)
	if !ok {
		return nil, fmt.Errorf("tag 24 content is %T, want bstr", tagged.Content)
	}
	var ck coseKeyEC2
	if err := cbor.Unmarshal(inner, &ck); err != nil {
		return nil, fmt.Errorf("decode COSE_Key: %w", err)
	}
	if ck.Kty != coseKtyEC2 || ck.Crv != coseCrvP256 {
		return nil, fmt.Errorf("unsupported COSE_Key (kty=%d crv=%d)", ck.Kty, ck.Crv)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(ck.X),
		Y:     new(big.Int).SetBytes(ck.Y),
	}, nil
}

func ecPubToCoseKey(pub *ecdsa.PublicKey) coseKeyEC2 {
	return coseKeyEC2{
		Kty: coseKtyEC2,
		Crv: coseCrvP256,
		X:   padLeft(pub.X.Bytes(), 32),
		Y:   padLeft(pub.Y.Bytes(), 32),
	}
}

func uuidFromCBORBstr(data []byte) (uuid.UUID, error) {
	var b []byte
	if err := cbor.Unmarshal(data, &b); err != nil {
		return uuid.UUID{}, fmt.Errorf("decode uuid bstr: %w", err)
	}
	return uuid.FromBytes(b)
}

func mustMarshal(v any) []byte {
	b, err := cbor.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
