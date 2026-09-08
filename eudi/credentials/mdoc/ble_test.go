package mdoc

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestCharacteristicUUIDs pins the two service definitions of 8.3.3.1.1.4. They
// are constants a native layer is handed, so a typo would surface as a reader that
// never responds rather than as a build failure.
func TestCharacteristicUUIDs(t *testing.T) {
	// Table 11 — mdoc service (mdoc is GATT server). Three characteristics, no Ident.
	for name, tc := range map[string]struct{ got, want string }{
		"Table 11 State":         {PeripheralServerStateCharacteristic.String(), "00000001-a123-48ce-896b-4c76973373e6"},
		"Table 11 Client2Server": {PeripheralServerClient2ServerCharacteristic.String(), "00000002-a123-48ce-896b-4c76973373e6"},
		"Table 11 Server2Client": {PeripheralServerServer2ClientCharacteristic.String(), "00000003-a123-48ce-896b-4c76973373e6"},
		// Table 12 — mdoc reader service (reader is GATT server), the set central
		// client mode uses. Four characteristics: this one has Ident.
		"Table 12 State":         {CentralClientStateCharacteristic.String(), "00000005-a123-48ce-896b-4c76973373e6"},
		"Table 12 Client2Server": {CentralClientClient2ServerCharacteristic.String(), "00000006-a123-48ce-896b-4c76973373e6"},
		"Table 12 Server2Client": {CentralClientServer2ClientCharacteristic.String(), "00000007-a123-48ce-896b-4c76973373e6"},
		"Table 12 Ident":         {CentralClientIdentCharacteristic.String(), "00000008-a123-48ce-896b-4c76973373e6"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %s, want %s", name, tc.got, tc.want)
		}
	}
}

// TestConnectionStateValues pins Table 13.
func TestConnectionStateValues(t *testing.T) {
	if StateStart != 0x01 {
		t.Errorf("StateStart = %#x, want 0x01", StateStart)
	}
	if StateEnd != 0x02 {
		t.Errorf("StateEnd = %#x, want 0x02", StateEnd)
	}
}

// TestMaxCharacteristicSize pins 8.3.3.1.1.6's "3 bytes less than the MTU size",
// and the 512-byte attribute-value ceiling the Bluetooth Core Specification
// imposes regardless of MTU.
func TestMaxCharacteristicSize(t *testing.T) {
	for name, tc := range map[string]struct {
		mtu            int
		characteristic int
		payload        int
		wantErr        bool
	}{
		"BLE minimum MTU 23":    {mtu: 23, characteristic: 20, payload: 19},
		"typical iOS MTU 185":   {mtu: 185, characteristic: 182, payload: 181},
		"capped at 512":         {mtu: 600, characteristic: 512, payload: 511},
		"exactly at the cap":    {mtu: 515, characteristic: 512, payload: 511},
		"one below the cap":     {mtu: 514, characteristic: 511, payload: 510},
		"below the BLE minimum": {mtu: 22, wantErr: true},
		"nonsense MTU":          {mtu: 0, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			size, err := MaxCharacteristicSize(tc.mtu)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("MTU %d: expected an error, got size %d", tc.mtu, size)
				}
				return
			}
			if err != nil {
				t.Fatalf("MaxCharacteristicSize: %v", err)
			}
			if size != tc.characteristic {
				t.Errorf("characteristic size = %d, want %d", size, tc.characteristic)
			}
			payload, err := MaxChunkPayload(tc.mtu)
			if err != nil {
				t.Fatalf("MaxChunkPayload: %v", err)
			}
			if payload != tc.payload {
				t.Errorf("chunk payload = %d, want %d", payload, tc.payload)
			}
		})
	}
}

// TestChunkMessageFraming checks the parts against 8.3.3.1.1.6 directly: every
// part is at most MTU-3 bytes, every part but the last carries 0x01, the last
// carries 0x00, and the payloads concatenate back to the message.
func TestChunkMessageFraming(t *testing.T) {
	const mtu = 23 // the BLE minimum, so even a small message needs several parts
	characteristicSize, err := MaxCharacteristicSize(mtu)
	if err != nil {
		t.Fatalf("MaxCharacteristicSize: %v", err)
	}

	for _, size := range []int{1, 18, 19, 20, 38, 500} {
		message := make([]byte, size)
		if _, err := rand.Read(message); err != nil {
			t.Fatalf("rand: %v", err)
		}

		parts, err := ChunkMessage(message, mtu)
		if err != nil {
			t.Fatalf("ChunkMessage(%d bytes): %v", size, err)
		}

		var reassembled []byte
		for i, part := range parts {
			if len(part) > characteristicSize {
				t.Fatalf("%d bytes: part %d is %d bytes, over the %d-byte characteristic limit",
					size, i, len(part), characteristicSize)
			}
			wantFlag := byte(chunkMore)
			if i == len(parts)-1 {
				wantFlag = chunkLast
			}
			if part[0] != wantFlag {
				t.Fatalf("%d bytes: part %d has flag %#x, want %#x", size, i, part[0], wantFlag)
			}
			reassembled = append(reassembled, part[1:]...)
		}
		if !bytes.Equal(reassembled, message) {
			t.Fatalf("%d bytes: payloads do not concatenate back to the message", size)
		}
	}
}

// TestChunkMessageBoundaries: a message that exactly fills its parts must not
// produce a trailing empty part, and one that fits in a single part must be one
// part flagged last.
func TestChunkMessageBoundaries(t *testing.T) {
	const mtu = 23
	payload, err := MaxChunkPayload(mtu) // 19
	if err != nil {
		t.Fatalf("MaxChunkPayload: %v", err)
	}

	t.Run("exact multiple", func(t *testing.T) {
		parts, err := ChunkMessage(make([]byte, payload*2), mtu)
		if err != nil {
			t.Fatalf("ChunkMessage: %v", err)
		}
		if len(parts) != 2 {
			t.Fatalf("got %d parts for an exact multiple, want 2", len(parts))
		}
		if parts[1][0] != chunkLast {
			t.Error("the final part of an exact multiple is not flagged last")
		}
	})

	t.Run("single part", func(t *testing.T) {
		parts, err := ChunkMessage(make([]byte, payload), mtu)
		if err != nil {
			t.Fatalf("ChunkMessage: %v", err)
		}
		if len(parts) != 1 || parts[0][0] != chunkLast {
			t.Fatalf("got %d parts, first flag %#x; want 1 part flagged last", len(parts), parts[0][0])
		}
	})

	t.Run("empty message still frames", func(t *testing.T) {
		parts, err := ChunkMessage(nil, mtu)
		if err != nil {
			t.Fatalf("ChunkMessage: %v", err)
		}
		if len(parts) != 1 || !bytes.Equal(parts[0], []byte{chunkLast}) {
			t.Fatalf("got %v, want a single last-chunk marker", parts)
		}
	})
}

// TestMessageAssemblerRoundTrip runs chunk-then-assemble over a range of sizes and
// MTUs, which is the property that actually matters: what one side frames, the
// other reconstitutes exactly.
func TestMessageAssemblerRoundTrip(t *testing.T) {
	for _, mtu := range []int{23, 185, 517} {
		for _, size := range []int{0, 1, 19, 100, 5000} {
			message := make([]byte, size)
			if _, err := rand.Read(message); err != nil {
				t.Fatalf("rand: %v", err)
			}
			parts, err := ChunkMessage(message, mtu)
			if err != nil {
				t.Fatalf("ChunkMessage: %v", err)
			}

			var assembler MessageAssembler
			var got []byte
			var done bool
			for i, part := range parts {
				got, done, err = assembler.Add(part)
				if err != nil {
					t.Fatalf("mtu %d size %d: Add part %d: %v", mtu, size, i, err)
				}
				if done != (i == len(parts)-1) {
					t.Fatalf("mtu %d size %d: part %d reported done=%v", mtu, size, i, done)
				}
			}
			if !bytes.Equal(got, message) {
				t.Fatalf("mtu %d size %d: reassembled message differs", mtu, size)
			}
			if assembler.Pending() {
				t.Errorf("mtu %d size %d: assembler still pending after a complete message", mtu, size)
			}
		}
	}
}

// TestMessageAssemblerHandlesConsecutiveMessages: one assembler serves a whole
// session, so it has to reset itself after each message.
func TestMessageAssemblerHandlesConsecutiveMessages(t *testing.T) {
	var assembler MessageAssembler
	for _, message := range [][]byte{[]byte("first"), []byte("second"), []byte("third")} {
		parts, err := ChunkMessage(message, 23)
		if err != nil {
			t.Fatalf("ChunkMessage: %v", err)
		}
		var got []byte
		for _, part := range parts {
			got, _, err = assembler.Add(part)
			if err != nil {
				t.Fatalf("Add: %v", err)
			}
		}
		if !bytes.Equal(got, message) {
			t.Fatalf("got %q, want %q", got, message)
		}
	}
}

// TestMessageAssemblerRejects covers what a peer can send that must not be
// accepted or must not be allowed to grow without bound.
func TestMessageAssemblerRejects(t *testing.T) {
	t.Run("empty part", func(t *testing.T) {
		var assembler MessageAssembler
		if _, _, err := assembler.Add(nil); err == nil {
			t.Fatal("expected an error for a part with no continuation flag")
		}
	})

	t.Run("unknown continuation flag", func(t *testing.T) {
		var assembler MessageAssembler
		if _, _, err := assembler.Add([]byte{0x02, 'x'}); err == nil {
			t.Fatal("expected an error for a flag other than 0x00 or 0x01")
		}
	})

	t.Run("oversized message", func(t *testing.T) {
		assembler := MessageAssembler{MaxMessageSize: 32}
		part := append([]byte{chunkMore}, make([]byte, 20)...)
		if _, _, err := assembler.Add(part); err != nil {
			t.Fatalf("first part: %v", err)
		}
		if _, _, err := assembler.Add(part); err == nil {
			t.Fatal("expected an error once the message exceeded MaxMessageSize")
		}
		if assembler.Pending() {
			t.Error("assembler kept a partial message after refusing it")
		}
	})
}

// TestMessageAssemblerIsLenientAboutPartSize: the flag byte, not the length, says
// whether more is coming, so a conservative peer sending short parts must still be
// understood.
func TestMessageAssemblerIsLenientAboutPartSize(t *testing.T) {
	var assembler MessageAssembler
	for _, part := range [][]byte{{chunkMore, 'a'}, {chunkMore, 'b', 'c'}, {chunkLast, 'd'}} {
		message, done, err := assembler.Add(part)
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
		if done {
			if !bytes.Equal(message, []byte("abcd")) {
				t.Fatalf("got %q, want %q", message, "abcd")
			}
			return
		}
	}
	t.Fatal("assembler never completed the message")
}

// TestPendingReportsLostData: 8.3.3.1.1.8 forbids re-establishing a connection
// once transmission has started, so a caller needs to know a drop cost it data.
func TestPendingReportsLostData(t *testing.T) {
	var assembler MessageAssembler
	if assembler.Pending() {
		t.Error("a fresh assembler reports pending data")
	}
	if _, _, err := assembler.Add([]byte{chunkMore, 'x'}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !assembler.Pending() {
		t.Error("assembler does not report a partly assembled message")
	}
	assembler.Reset()
	if assembler.Pending() {
		t.Error("Reset did not discard the partial message")
	}
}

// TestBLEIdent covers the derivation of 8.3.3.1.1.3. ISO publishes no vector for
// it, so the properties the clause fixes are what can be asserted: 16 octets,
// deterministic, and bound to this engagement's EDeviceKey.
func TestBLEIdent(t *testing.T) {
	key, err := GenerateEDeviceKey()
	if err != nil {
		t.Fatalf("GenerateEDeviceKey: %v", err)
	}
	eDeviceKeyBytes, err := EncodeEDeviceKeyBytes(&key.PublicKey)
	if err != nil {
		t.Fatalf("EncodeEDeviceKeyBytes: %v", err)
	}

	ident, err := BLEIdent(eDeviceKeyBytes)
	if err != nil {
		t.Fatalf("BLEIdent: %v", err)
	}
	if len(ident) != BLEIdentLength {
		t.Fatalf("Ident is %d bytes, want the %d of 8.3.3.1.1.3", len(ident), BLEIdentLength)
	}

	again, err := BLEIdent(eDeviceKeyBytes)
	if err != nil {
		t.Fatalf("BLEIdent: %v", err)
	}
	if !bytes.Equal(ident, again) {
		t.Fatal("BLEIdent is not deterministic")
	}

	// A different ephemeral key is a different transaction and must not produce
	// the same Ident, or the check would accept a reader from another session.
	otherKey, err := GenerateEDeviceKey()
	if err != nil {
		t.Fatalf("GenerateEDeviceKey: %v", err)
	}
	otherBytes, err := EncodeEDeviceKeyBytes(&otherKey.PublicKey)
	if err != nil {
		t.Fatalf("EncodeEDeviceKeyBytes: %v", err)
	}
	otherIdent, err := BLEIdent(otherBytes)
	if err != nil {
		t.Fatalf("BLEIdent: %v", err)
	}
	if bytes.Equal(ident, otherIdent) {
		t.Fatal("two ephemeral keys produced the same Ident")
	}

	// The IKM is EDeviceKeyBytes, the tag-24 wrapping, not the COSE_Key inside it.
	// Passing the contents must be refused rather than silently derive a value no
	// reader will match.
	unwrapped, err := tag24Unwrap[cbor.RawMessage](eDeviceKeyBytes)
	if err == nil {
		if _, err := BLEIdent(unwrapped); err == nil {
			t.Error("BLEIdent accepted the contents of the tag-24 wrapper as IKM")
		}
	}
}

// TestVerifyBLEIdent covers "If the Ident characteristic received from the mdoc
// reader does not match the expected value, the mdoc shall terminate the
// connection."
func TestVerifyBLEIdent(t *testing.T) {
	key, err := GenerateEDeviceKey()
	if err != nil {
		t.Fatalf("GenerateEDeviceKey: %v", err)
	}
	eDeviceKeyBytes, err := EncodeEDeviceKeyBytes(&key.PublicKey)
	if err != nil {
		t.Fatalf("EncodeEDeviceKeyBytes: %v", err)
	}
	ident, err := BLEIdent(eDeviceKeyBytes)
	if err != nil {
		t.Fatalf("BLEIdent: %v", err)
	}

	if err := VerifyBLEIdent(eDeviceKeyBytes, ident); err != nil {
		t.Errorf("the correct Ident was rejected: %v", err)
	}

	wrong := bytes.Clone(ident)
	wrong[0] ^= 0xff
	if err := VerifyBLEIdent(eDeviceKeyBytes, wrong); err == nil {
		t.Error("a mismatched Ident was accepted")
	}
	if err := VerifyBLEIdent(eDeviceKeyBytes, ident[:8]); err == nil {
		t.Error("a truncated Ident was accepted")
	}
	if err := VerifyBLEIdent(eDeviceKeyBytes, nil); err == nil {
		t.Error("an absent Ident was accepted")
	}
}
