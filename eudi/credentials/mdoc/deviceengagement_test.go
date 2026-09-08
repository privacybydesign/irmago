package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// isoAnnexDDeviceEngagement is the QR device engagement example published in
// ISO/IEC 18013-5:2021 D.3.1. Its diagnostic notation in the standard is:
//
//	{
//	   0: "1.0",
//	   1: [1, 24(<< {1: 2, -1: 1, -2: h'5A88…', -3: h'B16E…'} >>)],
//	   2: [[2, 1, {0: false, 1: true, 11: h'45EFEF742B2C4837A9A3B0E1D05A6917'}]]
//	}
//
// Note which BLE mode it advertises: central client (key 1 true, its UUID at key
// 11), not the peripheral server mode this wallet offers. That makes it a useful
// vector precisely because it is not the shape our own constructor produces — it
// exercises the structure rather than our defaults.
//
// The same EDeviceKey appears inside the D.5.1 session transcript vector used in
// sessiontranscript_test.go, since Annex D describes one continuous session.
const isoAnnexDDeviceEngagement = "" +
	"a30063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b6" +
	"24343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc670281830201a300f4" +
	"01f50b5045efef742b2c4837a9a3b0e1d05a6917"

// isoAnnexDCentralClientUUID is key 11 of the D.3.1 BleOptions.
const isoAnnexDCentralClientUUID = "45efef742b2c4837a9a3b0e1d05a6917"

// TestDeviceEngagement_DecodesISOAnnexDVector checks the decoded structure field
// by field against the diagnostic notation ISO prints beside the bytes, so a
// mis-mapped CBOR key is caught as a wrong value rather than surviving as a
// round-trip that is merely self-consistent.
//
// The BleOptions mapping is the reason this test is explicit: pdftotext renders
// 8.2.2.3's CDDL with every comment shifted one line up from the key it belongs
// to, which reads as key 0 meaning central client mode. D.3.1 settles it — key 1
// is true and the UUID sits at key 11, which pairs central client mode with the
// client central UUID.
func TestDeviceEngagement_DecodesISOAnnexDVector(t *testing.T) {
	var engagement DeviceEngagement
	if err := mdocDecMode.Unmarshal(mustHex(t, isoAnnexDDeviceEngagement), &engagement); err != nil {
		t.Fatalf("decode D.3.1 DeviceEngagement: %v", err)
	}

	if engagement.Version != "1.0" {
		t.Errorf("Version = %q, want %q", engagement.Version, "1.0")
	}
	if engagement.Security.CipherSuite != 1 {
		t.Errorf("cipher suite = %d, want 1", engagement.Security.CipherSuite)
	}
	if len(engagement.DeviceRetrievalMethods) != 1 {
		t.Fatalf("got %d retrieval methods, want 1", len(engagement.DeviceRetrievalMethods))
	}

	method := engagement.DeviceRetrievalMethods[0]
	if method.Type != RetrievalMethodBLE || method.Version != RetrievalMethodVersion {
		t.Errorf("retrieval method = [%d, %d], want [%d, %d] (Table 7: BLE)",
			method.Type, method.Version, RetrievalMethodBLE, RetrievalMethodVersion)
	}

	options, isBLE, err := method.BleOptions()
	if err != nil || !isBLE {
		t.Fatalf("BleOptions: isBLE=%v err=%v", isBLE, err)
	}
	if options.PeripheralServerModeSupported {
		t.Error("key 0 decoded as true; D.3.1 has peripheral server mode false")
	}
	if !options.CentralClientModeSupported {
		t.Error("key 1 decoded as false; D.3.1 has central client mode true")
	}
	if !bytes.Equal(options.CentralClientModeUUID, mustHex(t, isoAnnexDCentralClientUUID)) {
		t.Errorf("central client UUID = %x, want %s", options.CentralClientModeUUID, isoAnnexDCentralClientUUID)
	}
	if len(options.PeripheralServerModeUUID) != 0 {
		t.Errorf("peripheral server UUID present (%x) but the mode is not advertised", options.PeripheralServerModeUUID)
	}

	// The key is the one the D.5.1 transcript agrees against, so it has to come
	// back out as a usable point rather than merely as bytes.
	if _, err := engagement.EDeviceKey(); err != nil {
		t.Errorf("EDeviceKey: %v", err)
	}
}

// TestDeviceEngagement_ReEncodesToISOAnnexDVector requires a decoded engagement to
// go back out as the bytes it came in as.
//
// Byte equality is the requirement, not structural equality: the encoding is what
// the QR carries and what DeviceEngagementBytes wraps into the transcript, so a
// re-encode that differs anywhere — map key order, integer width, a dropped
// optional — silently changes every session key derived from it.
func TestDeviceEngagement_ReEncodesToISOAnnexDVector(t *testing.T) {
	golden := mustHex(t, isoAnnexDDeviceEngagement)

	var engagement DeviceEngagement
	if err := mdocDecMode.Unmarshal(golden, &engagement); err != nil {
		t.Fatalf("decode D.3.1 DeviceEngagement: %v", err)
	}
	got, err := engagement.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("re-encode does not match ISO D.3.1\n got: %x\nwant: %x", got, golden)
	}
}

// TestDeviceEngagement_ConstructorsRebuildISOAnnexDVector builds D.3.1 from its
// parts through the exported constructors, rather than by decoding it, and
// requires the same bytes.
//
// Decoding and re-encoding only proves the struct tags round-trip. This proves the
// constructors put the same things in the same places — Table 7's [2, 1, options],
// the version string, the cipher suite, and BleOptions' key numbering.
func TestDeviceEngagement_ConstructorsRebuildISOAnnexDVector(t *testing.T) {
	golden := mustHex(t, isoAnnexDDeviceEngagement)

	var decoded DeviceEngagement
	if err := mdocDecMode.Unmarshal(golden, &decoded); err != nil {
		t.Fatalf("decode D.3.1 DeviceEngagement: %v", err)
	}

	method, err := NewBLEDeviceRetrievalMethod(BleOptions{
		CentralClientModeSupported: true,
		CentralClientModeUUID:      mustHex(t, isoAnnexDCentralClientUUID),
	})
	if err != nil {
		t.Fatalf("NewBLEDeviceRetrievalMethod: %v", err)
	}
	rebuilt, err := NewDeviceEngagement(decoded.Security.EDeviceKeyBytes, method)
	if err != nil {
		t.Fatalf("NewDeviceEngagement: %v", err)
	}

	got, err := rebuilt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("constructed engagement does not match ISO D.3.1\n got: %x\nwant: %x", got, golden)
	}
}

// TestQRCodeURI_MatchesClause822 pins the two things 8.2.2.3 states: the "mdoc:"
// scheme, and base64url-without-padding of the DeviceEngagement structure itself —
// the bare structure, not the tag-24 DeviceEngagementBytes.
func TestQRCodeURI_MatchesClause822(t *testing.T) {
	golden := mustHex(t, isoAnnexDDeviceEngagement)

	var engagement DeviceEngagement
	if err := mdocDecMode.Unmarshal(golden, &engagement); err != nil {
		t.Fatalf("decode D.3.1 DeviceEngagement: %v", err)
	}
	uri, err := engagement.QRCodeURI()
	if err != nil {
		t.Fatalf("QRCodeURI: %v", err)
	}

	if !strings.HasPrefix(uri, "mdoc:") {
		t.Fatalf("QR URI %q does not use the mdoc: scheme", uri)
	}
	if strings.Contains(uri, "=") {
		t.Errorf("QR URI is padded; 8.2.2.3 requires base64url-without-padding: %q", uri)
	}
	if want := "mdoc:" + base64.RawURLEncoding.EncodeToString(golden); uri != want {
		t.Fatalf("QR URI\n got: %q\nwant: %q", uri, want)
	}
}

// TestParseQRCodeURI_RoundTripsAndWrapsReceivedBytes covers the reader side, and
// the specific trap in it: DeviceEngagementBytes must wrap the bytes as received,
// never a re-encoding of the parsed structure, because the transcript is hashed
// rather than compared.
func TestParseQRCodeURI_RoundTripsAndWrapsReceivedBytes(t *testing.T) {
	golden := mustHex(t, isoAnnexDDeviceEngagement)
	uri := "mdoc:" + base64.RawURLEncoding.EncodeToString(golden)

	engagement, deviceEngagementBytes, err := ParseQRCodeURI(uri)
	if err != nil {
		t.Fatalf("ParseQRCodeURI: %v", err)
	}

	reEncoded, err := engagement.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(reEncoded, golden) {
		t.Errorf("parsed engagement re-encodes differently\n got: %x\nwant: %x", reEncoded, golden)
	}

	wantWrapped, err := tag24WrapBytes(golden)
	if err != nil {
		t.Fatalf("tag24WrapBytes: %v", err)
	}
	if !bytes.Equal(deviceEngagementBytes, wantWrapped) {
		t.Fatalf("DeviceEngagementBytes\n got: %x\nwant: %x", deviceEngagementBytes, wantWrapped)
	}

	// And it has to be accepted by the transcript slot it exists to fill.
	if _, err := NewQRSessionTranscript(deviceEngagementBytes, testTag24("e-reader-key")); err != nil {
		t.Fatalf("DeviceEngagementBytes rejected by NewQRSessionTranscript: %v", err)
	}
}

// TestParseQRCodeURI_Rejects covers the inputs a reader can actually be handed.
func TestParseQRCodeURI_Rejects(t *testing.T) {
	valid := base64.RawURLEncoding.EncodeToString(mustHex(t, isoAnnexDDeviceEngagement))

	for name, uri := range map[string]string{
		"wrong scheme":     "https:" + valid,
		"no scheme":        valid,
		"not base64url":    "mdoc:!!!!",
		"padded base64":    "mdoc:" + base64.URLEncoding.EncodeToString(mustHex(t, isoAnnexDDeviceEngagement)),
		"not CBOR":         "mdoc:" + base64.RawURLEncoding.EncodeToString([]byte{0xff, 0xff, 0xff}),
		"empty engagement": "mdoc:",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseQRCodeURI(uri); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}

// TestEphemeralEDeviceKeyRoundTrips checks the generated key survives the
// COSE_Key encoding of 9.1.1.4 unchanged, and that two sessions do not share one.
func TestEphemeralEDeviceKeyRoundTrips(t *testing.T) {
	key, err := GenerateEDeviceKey()
	if err != nil {
		t.Fatalf("GenerateEDeviceKey: %v", err)
	}
	uuid, err := NewTransactionUUID()
	if err != nil {
		t.Fatalf("NewTransactionUUID: %v", err)
	}
	engagement, err := NewBLEPeripheralServerEngagement(&key.PublicKey, uuid)
	if err != nil {
		t.Fatalf("NewBLEPeripheralServerEngagement: %v", err)
	}

	recovered, err := engagement.EDeviceKey()
	if err != nil {
		t.Fatalf("EDeviceKey: %v", err)
	}
	if !recovered.Equal(&key.PublicKey) {
		t.Fatal("EDeviceKey did not survive the COSE_Key round trip")
	}

	// 9.1.5.1 binds a session through the transcript; an ephemeral key reused
	// across sessions would unbind it, so this must never repeat.
	other, err := GenerateEDeviceKey()
	if err != nil {
		t.Fatalf("GenerateEDeviceKey: %v", err)
	}
	if other.PublicKey.Equal(&key.PublicKey) {
		t.Fatal("two calls to GenerateEDeviceKey produced the same key")
	}
}

// TestPeripheralServerEngagementShape checks what this wallet actually puts on
// screen: one BLE method, peripheral server mode, its UUID at key 10 and nothing
// at key 11.
func TestPeripheralServerEngagementShape(t *testing.T) {
	key, err := GenerateEDeviceKey()
	if err != nil {
		t.Fatalf("GenerateEDeviceKey: %v", err)
	}
	serviceUUID, err := NewTransactionUUID()
	if err != nil {
		t.Fatalf("NewTransactionUUID: %v", err)
	}
	engagement, err := NewBLEPeripheralServerEngagement(&key.PublicKey, serviceUUID)
	if err != nil {
		t.Fatalf("NewBLEPeripheralServerEngagement: %v", err)
	}

	if len(engagement.DeviceRetrievalMethods) != 1 {
		t.Fatalf("got %d retrieval methods, want 1", len(engagement.DeviceRetrievalMethods))
	}
	options, isBLE, err := engagement.DeviceRetrievalMethods[0].BleOptions()
	if err != nil || !isBLE {
		t.Fatalf("BleOptions: isBLE=%v err=%v", isBLE, err)
	}
	if !options.PeripheralServerModeSupported || options.CentralClientModeSupported {
		t.Errorf("modes = peripheral:%v central:%v, want peripheral only",
			options.PeripheralServerModeSupported, options.CentralClientModeSupported)
	}
	if !bytes.Equal(options.PeripheralServerModeUUID, serviceUUID) {
		t.Errorf("peripheral server UUID = %x, want %x", options.PeripheralServerModeUUID, serviceUUID)
	}
	if len(options.CentralClientModeUUID) != 0 {
		t.Errorf("central client UUID present (%x) for a peripheral-server-only engagement",
			options.CentralClientModeUUID)
	}

	if _, err := engagement.QRCodeURI(); err != nil {
		t.Errorf("QRCodeURI: %v", err)
	}
}

// TestBleOptionsPresenceRules covers 8.3.3.1.1.2's iff-supported rules, which are
// `shall`s in both directions.
func TestBleOptionsPresenceRules(t *testing.T) {
	id := mustHex(t, isoAnnexDCentralClientUUID)

	for name, options := range map[string]BleOptions{
		"neither mode":               {},
		"peripheral mode, no UUID":   {PeripheralServerModeSupported: true},
		"central mode, no UUID":      {CentralClientModeSupported: true},
		"UUID without peripheral":    {CentralClientModeSupported: true, CentralClientModeUUID: id, PeripheralServerModeUUID: id},
		"UUID without central":       {PeripheralServerModeSupported: true, PeripheralServerModeUUID: id, CentralClientModeUUID: id},
		"address without peripheral": {CentralClientModeSupported: true, CentralClientModeUUID: id, PeripheralServerModeAddress: []byte{1, 2, 3, 4, 5, 6}},
		"UUID not 16 bytes":          {PeripheralServerModeSupported: true, PeripheralServerModeUUID: []byte{1, 2, 3}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewBLEDeviceRetrievalMethod(options); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}

	// The address is permitted ("may be present") alongside peripheral server mode.
	if _, err := NewBLEDeviceRetrievalMethod(BleOptions{
		PeripheralServerModeSupported: true,
		PeripheralServerModeUUID:      id,
		PeripheralServerModeAddress:   []byte{1, 2, 3, 4, 5, 6},
	}); err != nil {
		t.Errorf("BLE device address with peripheral server mode should be allowed: %v", err)
	}
}

// TestDeviceEngagementValidation covers what 8.2.1.1 and 9.1.5.2 fix rather than
// leave to the mdoc, on the way out as well as on the way in.
func TestDeviceEngagementValidation(t *testing.T) {
	key, err := GenerateEDeviceKey()
	if err != nil {
		t.Fatalf("GenerateEDeviceKey: %v", err)
	}
	eDeviceKeyBytes, err := EncodeEDeviceKeyBytes(&key.PublicKey)
	if err != nil {
		t.Fatalf("EncodeEDeviceKeyBytes: %v", err)
	}
	method, err := NewBLEDeviceRetrievalMethod(BleOptions{
		PeripheralServerModeSupported: true,
		PeripheralServerModeUUID:      mustHex(t, isoAnnexDCentralClientUUID),
	})
	if err != nil {
		t.Fatalf("NewBLEDeviceRetrievalMethod: %v", err)
	}
	valid := func() DeviceEngagement {
		e, err := NewDeviceEngagement(eDeviceKeyBytes, method)
		if err != nil {
			t.Fatalf("NewDeviceEngagement: %v", err)
		}
		return e
	}

	t.Run("wrong version is refused", func(t *testing.T) {
		e := valid()
		e.Version = "1.1"
		if _, err := e.Encode(); err == nil {
			t.Fatal("expected an error for a version other than 1.0")
		}
	})

	t.Run("unknown cipher suite is refused", func(t *testing.T) {
		e := valid()
		e.Security.CipherSuite = 2
		if _, err := e.Encode(); err == nil {
			t.Fatal("expected an error for a cipher suite other than 1")
		}
	})

	t.Run("EDeviceKeyBytes must be tag-24", func(t *testing.T) {
		if _, err := NewDeviceEngagement(cbor.RawMessage(mustHex(t, "63646566")), method); err == nil {
			t.Fatal("expected an error for an EDeviceKeyBytes that is not a tag-24 item")
		}
	})

	t.Run("QR engagement needs a retrieval method", func(t *testing.T) {
		e, err := NewDeviceEngagement(eDeviceKeyBytes)
		if err != nil {
			t.Fatalf("NewDeviceEngagement: %v", err)
		}
		if _, err := e.QRCodeURI(); err == nil {
			t.Fatal("expected an error: 8.2.1.1 requires one or more methods for QR engagement")
		}
	})
}

// TestEncodeEDeviceKeyBytesRejectsUnsupportedCurve confirms the Table 22 subset is
// enforced where the key enters the engagement, not later.
//
// P-224 is the honest case: a real, well-formed ECDSA key on a curve Table 22 does
// not list. The zero-valued key is the other one, and it used to panic rather than
// error -- coseKeyFromECDSA dereferences pub.Curve.Params() unguarded, which was
// unreachable until this function was exported.
func TestEncodeEDeviceKeyBytesRejectsUnsupportedCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-224 key: %v", err)
	}
	if _, err := EncodeEDeviceKeyBytes(&key.PublicKey); err == nil {
		t.Error("expected an error for a P-224 key, which Table 22 does not list")
	}
	if _, err := EncodeEDeviceKeyBytes(&ecdsa.PublicKey{}); err == nil {
		t.Error("expected an error for a key with no curve")
	}
	if _, err := EncodeEDeviceKeyBytes(nil); err == nil {
		t.Error("expected an error for a nil key")
	}
}

// TestSelectRetrievalMethod covers the reader-side obligation of 8.2.2.3, with the
// reader's preference order deciding rather than the mdoc's offer order — the
// standard assigns no meaning to the latter.
func TestSelectRetrievalMethod(t *testing.T) {
	id := mustHex(t, isoAnnexDCentralClientUUID)
	ble, err := NewBLEDeviceRetrievalMethod(BleOptions{
		PeripheralServerModeSupported: true,
		PeripheralServerModeUUID:      id,
	})
	if err != nil {
		t.Fatalf("NewBLEDeviceRetrievalMethod: %v", err)
	}
	// An NFC method built by hand: this package does not offer NFC retrieval, but
	// selection has to cope with an mdoc that does.
	nfc := DeviceRetrievalMethod{
		Type:    RetrievalMethodNFC,
		Version: RetrievalMethodVersion,
		Options: mustHex(t, "a2000a010a"), // NfcOptions {0: 10, 1: 10}
	}

	key, err := GenerateEDeviceKey()
	if err != nil {
		t.Fatalf("GenerateEDeviceKey: %v", err)
	}
	eDeviceKeyBytes, err := EncodeEDeviceKeyBytes(&key.PublicKey)
	if err != nil {
		t.Fatalf("EncodeEDeviceKeyBytes: %v", err)
	}
	engagementWith := func(methods ...DeviceRetrievalMethod) DeviceEngagement {
		e, err := NewDeviceEngagement(eDeviceKeyBytes, methods...)
		if err != nil {
			t.Fatalf("NewDeviceEngagement: %v", err)
		}
		return e
	}

	t.Run("picks the only offer", func(t *testing.T) {
		got, err := engagementWith(ble).SelectRetrievalMethod(RetrievalMethodBLE)
		if err != nil {
			t.Fatalf("SelectRetrievalMethod: %v", err)
		}
		if got.Type != RetrievalMethodBLE {
			t.Fatalf("selected type %d, want BLE", got.Type)
		}
	})

	t.Run("reader preference decides, not offer order", func(t *testing.T) {
		// NFC is listed first by the mdoc; a BLE-first reader must still get BLE.
		got, err := engagementWith(nfc, ble).SelectRetrievalMethod(RetrievalMethodBLE, RetrievalMethodNFC)
		if err != nil {
			t.Fatalf("SelectRetrievalMethod: %v", err)
		}
		if got.Type != RetrievalMethodBLE {
			t.Fatalf("selected type %d, want BLE — reader preference must win", got.Type)
		}

		// And the same engagement with the opposite reader yields NFC.
		got, err = engagementWith(nfc, ble).SelectRetrievalMethod(RetrievalMethodNFC, RetrievalMethodBLE)
		if err != nil {
			t.Fatalf("SelectRetrievalMethod: %v", err)
		}
		if got.Type != RetrievalMethodNFC {
			t.Fatalf("selected type %d, want NFC", got.Type)
		}
	})

	t.Run("no technology in common", func(t *testing.T) {
		if _, err := engagementWith(nfc).SelectRetrievalMethod(RetrievalMethodBLE); err == nil {
			t.Fatal("expected an error when the mdoc offers nothing the reader supports")
		}
	})

	t.Run("reader must state its support", func(t *testing.T) {
		if _, err := engagementWith(ble).SelectRetrievalMethod(); err == nil {
			t.Fatal("expected an error when no preferences are given")
		}
	})

	t.Run("no methods offered", func(t *testing.T) {
		if _, err := engagementWith().SelectRetrievalMethod(RetrievalMethodBLE); err == nil {
			t.Fatal("expected an error when the engagement offers no retrieval methods")
		}
	})

	t.Run("unusable offer is not selected", func(t *testing.T) {
		// A BLE method advertising peripheral server mode with no UUID: conformant
		// CBOR, but 8.3.3.1.1.2 makes it unusable, and a reader cannot connect to
		// a service it has no UUID for. Constructed directly, since
		// NewBLEDeviceRetrievalMethod refuses to build it.
		broken := DeviceRetrievalMethod{
			Type:    RetrievalMethodBLE,
			Version: RetrievalMethodVersion,
			Options: mustHex(t, "a200f501f4"), // {0: true, 1: false}, no UUID
		}
		if _, err := engagementWith(broken).SelectRetrievalMethod(RetrievalMethodBLE); err == nil {
			t.Fatal("expected an error: the only BLE offer carries no UUID")
		}

		// ...but a usable entry alongside it is still found.
		got, err := engagementWith(broken, ble).SelectRetrievalMethod(RetrievalMethodBLE)
		if err != nil {
			t.Fatalf("SelectRetrievalMethod: %v", err)
		}
		if opts, _, err := got.BleOptions(); err != nil || len(opts.PeripheralServerModeUUID) != 16 {
			t.Fatalf("selected the unusable offer: opts=%+v err=%v", opts, err)
		}
	})

	t.Run("wrong Table 7 version is not selected", func(t *testing.T) {
		wrongVersion := ble
		wrongVersion.Version = 2
		if _, err := engagementWith(wrongVersion).SelectRetrievalMethod(RetrievalMethodBLE); err == nil {
			t.Fatal("expected an error for a retrieval method with a version other than 1")
		}
	})
}

// TestCentralClientEngagementShape covers the other single-mode constructor: the
// UUID belongs at key 11, key 10 stays absent, and only central client mode is
// advertised.
func TestCentralClientEngagementShape(t *testing.T) {
	key, err := GenerateEDeviceKey()
	if err != nil {
		t.Fatalf("GenerateEDeviceKey: %v", err)
	}
	serviceUUID, err := NewTransactionUUID()
	if err != nil {
		t.Fatalf("NewTransactionUUID: %v", err)
	}
	engagement, err := NewBLECentralClientEngagement(&key.PublicKey, serviceUUID)
	if err != nil {
		t.Fatalf("NewBLECentralClientEngagement: %v", err)
	}

	options, isBLE, err := engagement.DeviceRetrievalMethods[0].BleOptions()
	if err != nil || !isBLE {
		t.Fatalf("BleOptions: isBLE=%v err=%v", isBLE, err)
	}
	if options.PeripheralServerModeSupported || !options.CentralClientModeSupported {
		t.Errorf("modes = peripheral:%v central:%v, want central only",
			options.PeripheralServerModeSupported, options.CentralClientModeSupported)
	}
	if !bytes.Equal(options.CentralClientModeUUID, serviceUUID) {
		t.Errorf("central client UUID = %x, want %x", options.CentralClientModeUUID, serviceUUID)
	}
	if len(options.PeripheralServerModeUUID) != 0 {
		t.Errorf("peripheral server UUID present (%x) on a central-client-only engagement",
			options.PeripheralServerModeUUID)
	}

	// Both constructors must reject a UUID that is not the 16 bytes of 8.3.3.1.1.3.
	for name, build := range map[string]func(*ecdsa.PublicKey, []byte) (DeviceEngagement, error){
		"central client":    NewBLECentralClientEngagement,
		"peripheral server": NewBLEPeripheralServerEngagement,
	} {
		if _, err := build(&key.PublicKey, []byte{1, 2, 3}); err == nil {
			t.Errorf("%s: expected an error for a UUID that is not 16 bytes", name)
		}
	}
}
