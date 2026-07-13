package mdoc

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestDeviceAuthPayloadIsDetached confirms the transmitted deviceAuth
// COSE_Sign1 has payload = null (detached content), matching the exact
// wire format shown in the spec's deviceSignature example:
//
//	"deviceSignature": [ h'a10126', {}, null, h'...' ]
//
// Detached payload means the actual DeviceAuthentication bytes are
// signed but never sent — the verifier reconstructs them itself and
// supplies them before verifying (see VerifyWithDeviceAuth).
func TestDeviceAuthPayloadIsDetached(t *testing.T) {
	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	transcript := SessionTranscript{
		DeviceEngagementBytes: []byte("test-engagement"),
		EReaderKeyBytes:       []byte("test-reader-key"),
		Handover:              "test-handover",
	}
	deviceAuthBytes, err := holder.SignDeviceAuth("eu.europa.ec.av.1", transcript)
	if err != nil {
		t.Fatalf("SignDeviceAuth: %v", err)
	}

	var arr []any
	if err := cbor.Unmarshal(deviceAuthBytes, &arr); err != nil {
		t.Fatalf("decode deviceAuth generic: %v", err)
	}
	if len(arr) != 4 {
		t.Fatalf("expected 4-element COSE_Sign1 array, got %d elements", len(arr))
	}
	if arr[2] != nil {
		t.Fatalf("expected detached payload (nil/null), got %T: %v", arr[2], arr[2])
	}
}
