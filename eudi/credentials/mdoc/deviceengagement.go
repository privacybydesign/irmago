package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

// ============================================================
// DEVICE ENGAGEMENT — ISO/IEC 18013-5 8.2.1.1, 8.2.2.3
// ============================================================
//
// 8.2.1.1, verbatim:
//
//	DeviceEngagement = {
//	    0: tstr,                     ; Version
//	    1: Security,
//	    ? 2: DeviceRetrievalMethods, ; Is absent if NFC is used for device engagement
//	    ? 3: ServerRetrievalMethods,
//	    ? 4: ProtocolInfo,
//	    * int => any
//	}
//
//	Security = [ int, EDeviceKeyBytes ]   ; cipher suite identifier, then the key
//
//	DeviceRetrievalMethods = [ + DeviceRetrievalMethod ]
//
//	DeviceRetrievalMethod = [ uint, uint, RetrievalOptions ]  ; type, version, options
//
// Keys 3 (ServerRetrievalMethods) and 4 (ProtocolInfo) are deliberately not
// modelled. Server retrieval is the online transport, which this wallet does not
// offer — 6.3.2.5 makes it optional — and ProtocolInfo is RFU. Both are optional
// in the CDDL, so omitting them produces a conformant structure; a reader that
// receives no key 3 simply has no server retrieval to choose.
//
// The `* int => any` extension slot is likewise not carried. This package only
// ever *produces* a DeviceEngagement, so there is nothing inbound whose unknown
// keys would be lost — with the exception of test vectors, where a re-encode
// would drop them. No vector in use has any.

const (
	// DeviceEngagementVersion is key 0. 8.2.1.1: "the version of the device
	// engagement structure, in the current version of this document its value
	// shall be '1.0'".
	DeviceEngagementVersion = "1.0"

	// CipherSuiteIdentifier is the first element of Security. 9.1.5.2: "This
	// document only describes the algorithms and operations for one cipher suite,
	// which is identified by the value 1." Choosing it is what fixes the EDeviceKey
	// curve set to Table 22 and the session AEAD to AES-256-GCM (9.1.1.4).
	CipherSuiteIdentifier = 1

	// Device retrieval method types and version, from Table 7. The table gives
	// every method version 1.
	//
	// RetrievalMethodNFC is present for completeness of the table rather than for
	// use: this wallet retrieves over BLE. Wi-Fi Aware is omitted entirely, having
	// neither a use here nor an options structure this package builds.
	RetrievalMethodNFC = 1
	RetrievalMethodBLE = 2

	RetrievalMethodVersion = 1
)

// DeviceEngagement is the structure of 8.2.1.1 that the mdoc offers the reader to
// start a session: which cipher suite, which ephemeral key, and which transports
// it will accept.
//
// It is transmitted by QR code (8.2.2.3) or NFC (8.2.2.1) and, either way, ends up
// in the first slot of the SessionTranscript, so the exact bytes matter — see
// DeviceEngagementBytes.
type DeviceEngagement struct {
	Version                string                  `cbor:"0,keyasint"`
	Security               Security                `cbor:"1,keyasint"`
	DeviceRetrievalMethods []DeviceRetrievalMethod `cbor:"2,keyasint,omitempty"`
}

// Security is the two-element array of 8.2.1.1: the cipher suite identifier
// defined in 9.1.5.2, then EDeviceKeyBytes as defined in 9.1.1.4.
//
// EDeviceKeyBytes is cbor.RawMessage for the reason given on
// SessionTranscript.DeviceEngagementBytes: 9.1.1.4 defines it as
// `#6.24(bstr .cbor EDeviceKey)`, so the field holds a complete tag-24 encoding
// that must go on the wire inline rather than inside a second byte string.
type Security struct {
	_               struct{} `cbor:",toarray"`
	CipherSuite     int
	EDeviceKeyBytes cbor.RawMessage
}

// DeviceRetrievalMethod is one entry of 8.2.1.1's DeviceRetrievalMethods: a
// transport the mdoc will accept, with the options specific to it.
//
// Options is cbor.RawMessage rather than `any` so a decoded method re-encodes to
// the bytes it arrived as. `RetrievalOptions` is a choice of three map types plus
// an RFU `any`; decoding one into an interface produces a Go map whose key order
// on re-encode is not the order it was received in, which is enough to change
// DeviceEngagementBytes and so every session key derived from it.
type DeviceRetrievalMethod struct {
	_       struct{} `cbor:",toarray"`
	Type    uint
	Version uint
	Options cbor.RawMessage
}

// BleOptions is the RetrievalOptions structure for retrieval method type 2,
// defined in 8.2.2.3:
//
//	BleOptions = {
//	       0 : bool,     ; Indicates support for mdoc peripheral server mode
//	       1 : bool,     ; Indicates support for mdoc central client mode
//	       ? 10 : bstr,  ; UUID for mdoc peripheral server mode
//	       ? 11 : bstr,  ; UUID for mdoc client central mode
//	       ? 20 : bstr   ; mdoc BLE Device Address for mdoc peripheral server mode
//	}
//
// Both booleans are mandatory and are therefore written even when false, which is
// what the D.3.1 example does with key 0.
//
// # The two modes, and which to advertise
//
// 8.3.3.1.1.1 defines them by BLE role: "If the mdoc supports the Central role, it
// shall act as a GATT client. This mode is called mdoc central client mode. If the
// mdoc supports the Peripheral role, it shall act as a GATT server. This mode is
// called mdoc peripheral server mode."
//
// So in central client mode the *reader* advertises and hosts the GATT service,
// and the mdoc scans and connects; in peripheral server mode it is the other way
// round. Either way the UUID is chosen by the mdoc and carried in this structure —
// 8.3.3.1.1.3: "The Peripheral device shall broadcast the service with the UUID as
// received or sent during device engagement".
//
// The clause states a preference: "If the mdoc indicates during device engagement
// that it supports both modes, the mdoc reader should select the mdoc central
// client mode." An mdoc has to support at least one and a reader must support
// both (6.3.2.5, Table 2), so advertising either alone is conformant.
//
// The service definitions differ too. 8.3.3.1.1.4 Table 11 gives the mdoc-as-GATT-
// server service three characteristics — State, Client2Server, Server2Client — and
// Table 12 gives the reader-as-GATT-server service a fourth, Ident, which the mdoc
// may read to confirm it connected to the intended reader. **Ident exists only in
// central client mode**; there is nothing for the mdoc to publish in peripheral
// server mode.
type BleOptions struct {
	PeripheralServerModeSupported bool   `cbor:"0,keyasint"`
	CentralClientModeSupported    bool   `cbor:"1,keyasint"`
	PeripheralServerModeUUID      []byte `cbor:"10,keyasint,omitempty"`
	CentralClientModeUUID         []byte `cbor:"11,keyasint,omitempty"`
	PeripheralServerModeAddress   []byte `cbor:"20,keyasint,omitempty"`
}

// GenerateEDeviceKey returns a fresh ephemeral key pair for one session.
//
// EDeviceKey exists to agree the session keys — 9.1.1.4 runs ECKA-DH between it
// and EReaderKey — and never to sign anything, so it has nothing to do with the
// mdoc authentication key held in the MSO and must not be reused across sessions:
// the transcript binds a session, and a repeated ephemeral key unbinds it.
//
// It is returned as an *ecdsa.PrivateKey rather than an *ecdh.PrivateKey so it
// converts with coseKeyFromECDSA, which already carries this package's curve
// table and the coordinate-width handling that a hand-rolled conversion got wrong
// once. Call ECDH() on it for the agreement step; Go provides that bridge exactly
// for this case.
//
// P-256 because it is the curve the AV Blueprint and every reader in practice
// use; Table 22 permits more, and coseKeyFromECDSA accepts P-384 and P-521 for a
// caller that builds its own key.
func GenerateEDeviceKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate EDeviceKey: %w", err)
	}
	return key, nil
}

// EncodeEDeviceKeyBytes renders a public key as the `EDeviceKeyBytes` of 9.1.1.4:
// `#6.24(bstr .cbor EDeviceKey)`, where EDeviceKey is a COSE_Key.
//
// The same encoding serves EReaderKeyBytes, which 9.1.1.4 defines identically —
// the reader's ephemeral key is the mirror of this one.
func EncodeEDeviceKeyBytes(pub *ecdsa.PublicKey) (cbor.RawMessage, error) {
	// coseKeyFromECDSA reaches straight for pub.Curve.Params(), which panics on a
	// zero-valued key. That was unreachable while every caller was inside this
	// package and held a key it had just decoded or generated; this function is
	// exported and takes whatever the caller has.
	if pub == nil || pub.Curve == nil {
		return nil, fmt.Errorf("EDeviceKey has no curve: not an EC2 key on any of Table 22's curves")
	}
	coseKey, err := coseKeyFromECDSA(pub)
	if err != nil {
		return nil, fmt.Errorf("encode EDeviceKey: %w", err)
	}
	wrapped, err := tag24Wrap(coseKey)
	if err != nil {
		return nil, fmt.Errorf("wrap EDeviceKeyBytes: %w", err)
	}
	return wrapped, nil
}

// NewTransactionUUID returns a fresh 16-byte service UUID for one session.
//
// 8.3.3.1.1.3: "The UUIDs used shall be 16-byte UUIDs that are unique for the
// transaction." A UUID reused across sessions is a stable identifier broadcast in
// the clear to everyone in radio range, which is precisely the correlation the
// per-transaction rule exists to prevent.
//
// 8.3.3.1.1.2 additionally requires variant 1 encoding per RFC 4122 4.1.2, which a
// random (version 4) UUID satisfies.
func NewTransactionUUID() ([]byte, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("generate transaction UUID: %w", err)
	}
	return id[:], nil
}

// validate enforces the presence rules 8.3.3.1.1.2 places on BleOptions for QR
// engagement:
//
//   - "The UUID for peripheral server mode shall be present if mdoc peripheral
//     server mode is supported and shall not be present if peripheral server mode
//     is not supported."
//   - the same, for client central mode.
//   - "The BLE Device Address field may be present if mdoc peripheral server mode
//     is supported and it shall not be present if peripheral server mode is not
//     supported."
//
// These are `shall`s in both directions, so a UUID left over from a mode that was
// switched off is as non-conformant as a missing one. Neither is caught later: the
// engagement is carried into the transcript and the session fails, if at all, as a
// connection that never opens.
func (o BleOptions) validate() error {
	if err := validateModeUUID(
		"peripheral server mode", o.PeripheralServerModeSupported, o.PeripheralServerModeUUID); err != nil {
		return err
	}
	if err := validateModeUUID(
		"central client mode", o.CentralClientModeSupported, o.CentralClientModeUUID); err != nil {
		return err
	}
	if len(o.PeripheralServerModeAddress) > 0 && !o.PeripheralServerModeSupported {
		return fmt.Errorf(
			"BleOptions carries a BLE Device Address without advertising peripheral server mode: 8.3.3.1.1.2 forbids it")
	}
	return nil
}

// validateModeUUID applies 8.3.3.1.1.2's present-if-and-only-if-supported rule to
// one BLE mode, and 8.3.3.1.1.3's 16-byte width.
func validateModeUUID(mode string, supported bool, id []byte) error {
	switch {
	case supported && len(id) == 0:
		return fmt.Errorf(
			"BleOptions advertises %s without a UUID: 8.3.3.1.1.2 requires one when the mode is supported", mode)
	case !supported && len(id) > 0:
		return fmt.Errorf(
			"BleOptions carries a %s UUID without advertising the mode: 8.3.3.1.1.2 requires it to be absent", mode)
	case supported && len(id) != 16:
		return fmt.Errorf(
			"BleOptions %s UUID is %d bytes, want the 16 of 8.3.3.1.1.3", mode, len(id))
	}
	return nil
}

// NewBLEDeviceRetrievalMethod builds the `[2, 1, BleOptions]` entry of Table 7.
func NewBLEDeviceRetrievalMethod(options BleOptions) (DeviceRetrievalMethod, error) {
	if !options.PeripheralServerModeSupported && !options.CentralClientModeSupported {
		return DeviceRetrievalMethod{}, fmt.Errorf(
			"BleOptions advertises neither BLE mode: 8.3.3.1.1 requires an mdoc to support at least one")
	}
	if err := options.validate(); err != nil {
		return DeviceRetrievalMethod{}, err
	}
	encoded, err := cbor.Marshal(options)
	if err != nil {
		return DeviceRetrievalMethod{}, fmt.Errorf("encode BleOptions: %w", err)
	}
	return DeviceRetrievalMethod{
		Type:    RetrievalMethodBLE,
		Version: RetrievalMethodVersion,
		Options: encoded,
	}, nil
}

// NewBLECentralClientEngagement builds an engagement offering mdoc central client
// mode on serviceUUID: the reader advertises and hosts the GATT service, and the
// mdoc scans for the UUID and connects as GATT client (8.3.3.1.1.1).
//
// This is the mode 8.3.3.1.1.1 tells a reader to prefer when offered both, and the
// one the D.3.1 example advertises. It also keeps the wallet off the air — it
// never advertises — and needs only the BLE central role from the platform, which
// is the better-supported of the two on both Android and iOS.
//
// serviceUUID is chosen by the mdoc even though the reader is the one that
// broadcasts it (8.3.3.1.1.3), and must be unique to the transaction.
func NewBLECentralClientEngagement(eDeviceKey *ecdsa.PublicKey, serviceUUID []byte) (DeviceEngagement, error) {
	return newBLEEngagement(eDeviceKey, BleOptions{
		CentralClientModeSupported: true,
		CentralClientModeUUID:      serviceUUID,
	}, serviceUUID)
}

// NewBLEPeripheralServerEngagement builds the engagement this wallet offers: a
// single BLE retrieval method in mdoc peripheral server mode, on serviceUUID.
//
// serviceUUID is the 16-byte BLE service UUID the mdoc will advertise and the
// reader will connect to, and belongs to this session alone — 8.3.3.1.1.3
// requires a UUID that is not reused, since a fixed one is a persistent
// identifier that anyone in radio range can correlate.
func NewBLEPeripheralServerEngagement(eDeviceKey *ecdsa.PublicKey, serviceUUID []byte) (DeviceEngagement, error) {
	return newBLEEngagement(eDeviceKey, BleOptions{
		PeripheralServerModeSupported: true,
		PeripheralServerModeUUID:      serviceUUID,
	}, serviceUUID)
}

// newBLEEngagement is the shared body of the two single-mode BLE constructors.
func newBLEEngagement(eDeviceKey *ecdsa.PublicKey, options BleOptions, serviceUUID []byte) (DeviceEngagement, error) {
	if len(serviceUUID) != 16 {
		return DeviceEngagement{}, fmt.Errorf("BLE service UUID is %d bytes, want the 16 of 8.3.3.1.1.3", len(serviceUUID))
	}
	eDeviceKeyBytes, err := EncodeEDeviceKeyBytes(eDeviceKey)
	if err != nil {
		return DeviceEngagement{}, err
	}
	method, err := NewBLEDeviceRetrievalMethod(options)
	if err != nil {
		return DeviceEngagement{}, err
	}
	return NewDeviceEngagement(eDeviceKeyBytes, method)
}

// NewDeviceEngagement assembles 8.2.1.1 from an already-encoded EDeviceKeyBytes
// and the retrieval methods the mdoc will accept.
//
// methods may be empty only for NFC engagement, where 8.2.1.1 says the array
// "shall be absent, because the data retrieval methods supported by the mdoc are
// specified in the Alternative Carrier Records". QRCodeURI refuses that case,
// since for QR the same clause requires one or more.
func NewDeviceEngagement(eDeviceKeyBytes cbor.RawMessage, methods ...DeviceRetrievalMethod) (DeviceEngagement, error) {
	if err := validateTag24Slot("EDeviceKeyBytes", eDeviceKeyBytes); err != nil {
		return DeviceEngagement{}, err
	}
	return DeviceEngagement{
		Version: DeviceEngagementVersion,
		Security: Security{
			CipherSuite:     CipherSuiteIdentifier,
			EDeviceKeyBytes: eDeviceKeyBytes,
		},
		DeviceRetrievalMethods: methods,
	}, nil
}

// Encode returns the bare CBOR of the DeviceEngagement structure — what 8.2.2.3
// base64url-encodes into the QR code, and what DeviceEngagementBytes wraps.
func (e DeviceEngagement) Encode() ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	encoded, err := cbor.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("encode DeviceEngagement: %w", err)
	}
	return encoded, nil
}

// DeviceEngagementBytes returns `#6.24(bstr .cbor DeviceEngagement)`, the first
// slot of the SessionTranscript (9.1.5.1).
//
// The mdoc may build this from its own structure, as here. The *reader* must not:
// it has to wrap the bytes it actually received, because re-encoding a decoded
// structure can differ from the original and the transcript is byte-compared by
// nobody and hashed by everybody. ParseQRCodeURI returns those received bytes
// already wrapped for exactly this reason.
func (e DeviceEngagement) DeviceEngagementBytes() (cbor.RawMessage, error) {
	encoded, err := e.Encode()
	if err != nil {
		return nil, err
	}
	return wrapDeviceEngagementBytes(encoded)
}

// QRCodeURI renders the engagement for 8.2.2.3: "The QR code shall contain a URI
// with 'mdoc:' as scheme and the DeviceEngagement structure specified in 8.2.1.1
// encoded using base64url-without-padding, according to RFC 4648, as path."
//
// The QR carries the *bare* structure, not the tag-24 DeviceEngagementBytes. A
// reader reconstructs the transcript slot by wrapping what it decodes.
func (e DeviceEngagement) QRCodeURI() (string, error) {
	if len(e.DeviceRetrievalMethods) == 0 {
		return "", fmt.Errorf(
			"DeviceEngagement has no retrieval methods: 8.2.1.1 requires one or more when engaging by QR code (they are absent only for NFC engagement)")
	}
	encoded, err := e.Encode()
	if err != nil {
		return "", err
	}
	return qrCodeScheme + base64.RawURLEncoding.EncodeToString(encoded), nil
}

// qrCodeScheme is the URI scheme of 8.2.2.3, registered with IANA in Annex F.
const qrCodeScheme = "mdoc:"

// ParseQRCodeURI is the reader side of 8.2.2.3. It returns the decoded structure
// together with the DeviceEngagementBytes for the SessionTranscript, the latter
// built by wrapping the bytes as received rather than by re-encoding the
// structure — see DeviceEngagementBytes.
func ParseQRCodeURI(uri string) (DeviceEngagement, cbor.RawMessage, error) {
	if !strings.HasPrefix(uri, qrCodeScheme) {
		return DeviceEngagement{}, nil, fmt.Errorf(
			"not an mdoc engagement URI: 8.2.2.3 requires the %q scheme", qrCodeScheme)
	}
	encoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(uri, qrCodeScheme))
	if err != nil {
		return DeviceEngagement{}, nil, fmt.Errorf(
			"decode base64url-without-padding engagement: %w", err)
	}

	var engagement DeviceEngagement
	if err := mdocDecMode.Unmarshal(encoded, &engagement); err != nil {
		return DeviceEngagement{}, nil, fmt.Errorf("decode DeviceEngagement: %w", err)
	}
	if err := engagement.validate(); err != nil {
		return DeviceEngagement{}, nil, err
	}

	deviceEngagementBytes, err := wrapDeviceEngagementBytes(encoded)
	if err != nil {
		return DeviceEngagement{}, nil, err
	}
	return engagement, deviceEngagementBytes, nil
}

// wrapDeviceEngagementBytes applies the `#6.24(bstr .cbor ...)` of 9.1.5.1 to an
// encoded DeviceEngagement.
func wrapDeviceEngagementBytes(encoded []byte) (cbor.RawMessage, error) {
	wrapped, err := tag24WrapBytes(encoded)
	if err != nil {
		return nil, fmt.Errorf("wrap DeviceEngagementBytes: %w", err)
	}
	return wrapped, nil
}

// validate checks what 8.2.1.1 fixes rather than leaves to the mdoc: the version
// string, the cipher suite, and that the key slot holds a tag-24 item.
//
// Run on the way out as well as on the way in. A malformed engagement is not
// rejected by anything downstream — it is carried into the transcript and shows
// up as a session that cannot be decrypted.
func (e DeviceEngagement) validate() error {
	if e.Version != DeviceEngagementVersion {
		return fmt.Errorf(
			"DeviceEngagement version is %q, want %q: 8.2.1.1 fixes the value for this edition",
			e.Version, DeviceEngagementVersion)
	}
	if e.Security.CipherSuite != CipherSuiteIdentifier {
		return fmt.Errorf(
			"DeviceEngagement names cipher suite %d, want %d: 9.1.5.2 defines no other",
			e.Security.CipherSuite, CipherSuiteIdentifier)
	}
	return validateTag24Slot("EDeviceKeyBytes", e.Security.EDeviceKeyBytes)
}

// EDeviceKey decodes the ephemeral public key out of Security.EDeviceKeyBytes.
//
// The reader needs it for the ECKA-DH of 9.1.1.4; the mdoc already holds the
// private half. Curves outside this package's Table 22 subset are refused by
// ecdsaPublicKeyFromCOSE by name rather than mishandled.
func (e DeviceEngagement) EDeviceKey() (*ecdsa.PublicKey, error) {
	if err := validateTag24Slot("EDeviceKeyBytes", e.Security.EDeviceKeyBytes); err != nil {
		return nil, err
	}
	coseKey, err := tag24Unwrap[COSEKey](e.Security.EDeviceKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("decode EDeviceKey: %w", err)
	}
	return ecdsaPublicKeyFromCOSE(coseKey)
}

// SelectRetrievalMethod is the reader-side obligation of 8.2.2.3: "An mdoc reader
// shall select one of the transmission technologies from the ones provided in the
// device engagement structure." (1986's Alternative Carrier Record wording is the
// same requirement on the NFC path.)
//
// preferences are retrieval method types in the reader's own order of preference,
// most preferred first. The reader's order is what decides, because the standard
// assigns no meaning to the order of DeviceRetrievalMethods — it is a set of what
// the mdoc will accept, not a ranking. A reader that can only do BLE passes
// RetrievalMethodBLE alone and gets an error if the mdoc offered nothing else.
//
// The selection is silent. For QR engagement there is no message back to the mdoc
// saying which carrier was chosen; the reader simply connects on it. That is also
// why the choice must be one the reader can actually act on, so a method whose
// options do not decode, or do not satisfy the rules for their transport, is
// treated as not on offer rather than returned and failed later.
func (e DeviceEngagement) SelectRetrievalMethod(preferences ...uint) (DeviceRetrievalMethod, error) {
	if len(preferences) == 0 {
		return DeviceRetrievalMethod{}, fmt.Errorf(
			"no retrieval method preferences given: the reader has to say what it supports")
	}
	if len(e.DeviceRetrievalMethods) == 0 {
		return DeviceRetrievalMethod{}, fmt.Errorf(
			"DeviceEngagement offers no retrieval methods: for NFC engagement they are carried in the Alternative Carrier Records instead (8.2.1.1)")
	}

	var unusable error
	for _, preferred := range preferences {
		for _, method := range e.DeviceRetrievalMethods {
			if method.Type != preferred {
				continue
			}
			if err := method.validate(); err != nil {
				// Keep looking: another entry of the same type, or a
				// less-preferred type, may still be usable. Remember the first
				// reason so an all-unusable engagement says why rather than
				// reporting the offer as empty.
				if unusable == nil {
					unusable = err
				}
				continue
			}
			return method, nil
		}
	}

	if unusable != nil {
		return DeviceRetrievalMethod{}, fmt.Errorf(
			"no usable retrieval method among %s for a reader supporting %s: %w",
			e.offeredTypes(), retrievalTypeNames(preferences), unusable)
	}
	return DeviceRetrievalMethod{}, fmt.Errorf(
		"mdoc offers %s, reader supports %s: no transmission technology in common",
		e.offeredTypes(), retrievalTypeNames(preferences))
}

// validate checks that a retrieval method can actually be acted on, which for the
// transports this package builds means its RetrievalOptions decode and satisfy
// their own clause. An unrecognised type is left alone: Table 7 marks other types
// RFU, and a method this package cannot read is not thereby malformed.
func (m DeviceRetrievalMethod) validate() error {
	if m.Version != RetrievalMethodVersion {
		return fmt.Errorf("retrieval method %s has version %d, want the %d of Table 7",
			retrievalTypeName(m.Type), m.Version, RetrievalMethodVersion)
	}
	options, isBLE, err := m.BleOptions()
	if err != nil {
		return err
	}
	if isBLE {
		return options.validate()
	}
	return nil
}

// offeredTypes names what the engagement put on the table, for error messages
// that say what went wrong rather than only that something did.
func (e DeviceEngagement) offeredTypes() string {
	types := make([]uint, 0, len(e.DeviceRetrievalMethods))
	for _, method := range e.DeviceRetrievalMethods {
		types = append(types, method.Type)
	}
	return retrievalTypeNames(types)
}

func retrievalTypeNames(types []uint) string {
	names := make([]string, 0, len(types))
	for _, t := range types {
		names = append(names, retrievalTypeName(t))
	}
	if len(names) == 0 {
		return "nothing"
	}
	return strings.Join(names, ", ")
}

// retrievalTypeName renders a Table 7 type, including the two this package does
// not build — an mdoc may legitimately offer them, and "type 3" in an error is
// less use than "Wi-Fi Aware".
func retrievalTypeName(t uint) string {
	switch t {
	case RetrievalMethodNFC:
		return "NFC"
	case RetrievalMethodBLE:
		return "BLE"
	case retrievalMethodWifiAware:
		return "Wi-Fi Aware"
	default:
		return fmt.Sprintf("type %d (RFU)", t)
	}
}

// retrievalMethodWifiAware is Table 7's third type. Unexported because this
// package neither offers nor selects it — it exists so an engagement that does
// offer it is named correctly rather than reported as RFU.
const retrievalMethodWifiAware = 3

// BleOptions decodes the RetrievalOptions of a BLE retrieval method, and reports
// whether m is one.
func (m DeviceRetrievalMethod) BleOptions() (BleOptions, bool, error) {
	if m.Type != RetrievalMethodBLE {
		return BleOptions{}, false, nil
	}
	var options BleOptions
	if err := mdocDecMode.Unmarshal(m.Options, &options); err != nil {
		return BleOptions{}, true, fmt.Errorf("decode BleOptions: %w", err)
	}
	return options, true, nil
}
