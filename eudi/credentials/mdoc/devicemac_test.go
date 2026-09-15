package mdoc

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// testEphemeralKey and testEDeviceKeyBytes stand in for GenerateEDeviceKey and
// EncodeEDeviceKeyBytes, which live in the device engagement code this branch
// does not carry. Neither is doing anything engagement-specific here: 9.1.3.5's
// ECKA-DH takes an ordinary P-256 ephemeral and does not care how the peer
// learned of it, and EReaderKeyBytes is just 9.1.1.4's tag-24 COSE_Key.
func testEphemeralKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ephemeral key: %v", err)
	}
	return key
}

func testEDeviceKeyBytes(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	key, err := coseKeyFromECDSA(pub)
	if err != nil {
		t.Fatalf("encode COSE_Key: %v", err)
	}
	encoded, err := tag24Wrap(key)
	if err != nil {
		t.Fatalf("wrap EDeviceKeyBytes: %v", err)
	}
	return encoded
}

// macFixture is one session's worth of the pieces 9.1.3.5 needs: a holder with a
// static device key, the reader's ephemeral key, and the transcript both sides
// derive EMacKey over.
type macFixture struct {
	holder     *DefaultHolder
	eReaderKey *ecdsa.PrivateKey
	transcript SessionTranscript
	docType    string
}

func newMacFixture(t *testing.T) macFixture {
	t.Helper()
	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	eReaderKey := testEphemeralKey(t)
	eReaderKeyBytes := testEDeviceKeyBytes(t, &eReaderKey.PublicKey)
	transcript, err := NewQRSessionTranscript(testTag24("device-engagement"), eReaderKeyBytes)
	if err != nil {
		t.Fatalf("NewQRSessionTranscript: %v", err)
	}
	return macFixture{holder: holder, eReaderKey: eReaderKey, transcript: transcript, docType: "eu.europa.ec.av.1"}
}

// TestEMacKeyAgreesOnBothSides pins the mirrored ECKA-DH inputs of 9.1.3.5:
// SDeviceKey.Priv with EReaderKey.Pub for the mdoc, EReaderKey.Priv with
// SDeviceKey.Pub for the reader. Both must reach the same EMacKey or nothing
// verifies.
func TestEMacKeyAgreesOnBothSides(t *testing.T) {
	f := newMacFixture(t)

	mdocSide, err := DeriveEMacKeyAsMdoc(f.holder, &f.eReaderKey.PublicKey, f.transcript)
	if err != nil {
		t.Fatalf("DeriveEMacKeyAsMdoc: %v", err)
	}
	readerSide, err := DeriveEMacKeyAsReader(f.eReaderKey, f.holder.PublicKey(), f.transcript)
	if err != nil {
		t.Fatalf("DeriveEMacKeyAsReader: %v", err)
	}

	if !bytes.Equal(mdocSide, readerSide) {
		t.Fatal("mdoc and reader derived different EMacKeys")
	}
	if len(mdocSide) != EMacKeyLength {
		t.Errorf("EMacKey is %d bytes, want %d", len(mdocSide), EMacKeyLength)
	}
}

// TestEMacKeyUsesTheStaticDeviceKey is the distinction that makes deviceMac reach
// back into issuance: the agreement is with SDeviceKey, the MSO's static device
// key, not with the session's ephemeral EDeviceKey.
func TestEMacKeyUsesTheStaticDeviceKey(t *testing.T) {
	f := newMacFixture(t)

	fromStatic, err := DeriveEMacKeyAsReader(f.eReaderKey, f.holder.PublicKey(), f.transcript)
	if err != nil {
		t.Fatalf("DeriveEMacKeyAsReader: %v", err)
	}

	ephemeral := testEphemeralKey(t)
	fromEphemeral, err := DeriveEMacKeyAsReader(f.eReaderKey, &ephemeral.PublicKey, f.transcript)
	if err != nil {
		t.Fatalf("DeriveEMacKeyAsReader: %v", err)
	}
	if bytes.Equal(fromStatic, fromEphemeral) {
		t.Fatal("EMacKey does not depend on which device key it agreed with")
	}
}

// TestEMacKeyMatchesTheClauseDerivation recomputes EMacKey independently and
// pins it to the HKDF 9.1.3.5 states.
//
// It used to also assert EMacKey differs from SKReader and SKDevice, which share
// its salt and are separated from it only by the info string — a copy-paste of
// the wrong one being a live risk. That half went with the session layer this
// branch does not carry; the info string is still pinned here, just against the
// clause rather than against its neighbours.
func TestEMacKeyMatchesTheClauseDerivation(t *testing.T) {
	f := newMacFixture(t)

	zab := []byte("a fixed ZAB for comparing derivations")
	emacKey, err := emacKeyFromZAB(zab, f.transcript)
	if err != nil {
		t.Fatalf("emacKeyFromZAB: %v", err)
	}

	salt, err := f.transcript.KeyDerivationSalt()
	if err != nil {
		t.Fatalf("KeyDerivationSalt: %v", err)
	}
	want, err := hkdf.Key(sha256.New, zab, salt, "EMacKey", 32)
	if err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	if !bytes.Equal(emacKey, want) {
		t.Fatalf("EMacKey\n got: %x\nwant: %x", emacKey, want)
	}
}

// TestMacDeviceAuthRoundTrip: what the mdoc produces, a reader deriving EMacKey
// from its own side verifies.
func TestMacDeviceAuthRoundTrip(t *testing.T) {
	f := newMacFixture(t)

	deviceMac, err := MacDeviceAuth(f.holder, f.docType, f.transcript, &f.eReaderKey.PublicKey)
	if err != nil {
		t.Fatalf("MacDeviceAuth: %v", err)
	}
	emacKey, err := DeriveEMacKeyAsReader(f.eReaderKey, f.holder.PublicKey(), f.transcript)
	if err != nil {
		t.Fatalf("DeriveEMacKeyAsReader: %v", err)
	}
	if err := VerifyDeviceMac(deviceMac, emacKey, f.docType, f.transcript); err != nil {
		t.Fatalf("VerifyDeviceMac: %v", err)
	}
}

// TestDeviceMacStructure pins the COSE_Mac0 shape of 9.1.3.5: untagged, four
// elements, alg HMAC 256/256 in the protected header, a null payload because the
// content is detached, and a full 32-byte tag.
func TestDeviceMacStructure(t *testing.T) {
	f := newMacFixture(t)
	deviceMac, err := MacDeviceAuth(f.holder, f.docType, f.transcript, &f.eReaderKey.PublicKey)
	if err != nil {
		t.Fatalf("MacDeviceAuth: %v", err)
	}

	var generic []any
	if err := cbor.Unmarshal(deviceMac, &generic); err != nil {
		t.Fatalf("deviceMac is not an untagged CBOR array: %v", err)
	}
	if len(generic) != 4 {
		t.Fatalf("COSE_Mac0 has %d elements, want 4", len(generic))
	}
	if generic[2] != nil {
		t.Errorf("payload is %v, want null (the content is detached)", generic[2])
	}
	tag, ok := generic[3].([]byte)
	if !ok || len(tag) != 32 {
		t.Errorf("tag is %T of %d bytes, want 32 (HMAC 256/256 is untruncated)", generic[3], len(tag))
	}
	unprotected, ok := generic[1].(map[any]any)
	if !ok || len(unprotected) != 0 {
		t.Errorf("unprotected header = %v, want empty", generic[1])
	}

	protected, ok := generic[0].([]byte)
	if !ok {
		t.Fatalf("protected header is %T, want a byte string", generic[0])
	}
	var header map[int]any
	if err := cbor.Unmarshal(protected, &header); err != nil {
		t.Fatalf("decode protected header: %v", err)
	}
	if len(header) != 1 {
		t.Errorf("protected header has %d entries, want only alg", len(header))
	}
	if header[1] != uint64(coseAlgorithmHMAC256) {
		t.Errorf("alg = %v, want %d (HMAC 256/256)", header[1], coseAlgorithmHMAC256)
	}
}

// TestVerifyDeviceMacRejects covers what must not verify.
func TestVerifyDeviceMacRejects(t *testing.T) {
	f := newMacFixture(t)
	deviceMac, err := MacDeviceAuth(f.holder, f.docType, f.transcript, &f.eReaderKey.PublicKey)
	if err != nil {
		t.Fatalf("MacDeviceAuth: %v", err)
	}
	emacKey, err := DeriveEMacKeyAsReader(f.eReaderKey, f.holder.PublicKey(), f.transcript)
	if err != nil {
		t.Fatalf("DeriveEMacKeyAsReader: %v", err)
	}

	t.Run("tampered tag", func(t *testing.T) {
		tampered := bytes.Clone(deviceMac)
		tampered[len(tampered)-1] ^= 0xff
		if err := VerifyDeviceMac(tampered, emacKey, f.docType, f.transcript); err == nil {
			t.Fatal("a tampered tag verified")
		}
	})

	t.Run("wrong EMacKey", func(t *testing.T) {
		wrong := bytes.Clone(emacKey)
		wrong[0] ^= 0xff
		if err := VerifyDeviceMac(deviceMac, wrong, f.docType, f.transcript); err == nil {
			t.Fatal("a MAC verified under the wrong EMacKey")
		}
	})

	t.Run("wrong docType", func(t *testing.T) {
		if err := VerifyDeviceMac(deviceMac, emacKey, "org.iso.18013.5.1.mDL", f.transcript); err == nil {
			t.Fatal("a MAC verified against a different docType")
		}
	})

	t.Run("different session", func(t *testing.T) {
		other := newMacFixture(t)
		if err := VerifyDeviceMac(deviceMac, emacKey, f.docType, other.transcript); err == nil {
			t.Fatal("a MAC verified against a different session transcript")
		}
	})

	t.Run("wrong algorithm in the protected header", func(t *testing.T) {
		protected, err := cbor.Marshal(map[int]any{1: -7}) // ES256, not HMAC 256/256
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		payload, err := deviceAuthenticationBytes(f.docType, f.transcript)
		if err != nil {
			t.Fatalf("deviceAuthenticationBytes: %v", err)
		}
		tag, err := macTag(emacKey, protected, payload)
		if err != nil {
			t.Fatalf("macTag: %v", err)
		}
		forged, err := cbor.Marshal(coseMac0{Protected: protected, Unprotected: map[int]any{}, Tag: tag})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		// The tag is genuine for the header it names, so only the algorithm check
		// catches this.
		if err := VerifyDeviceMac(forged, emacKey, f.docType, f.transcript); err == nil {
			t.Fatal("a MAC naming an algorithm other than HMAC 256/256 verified")
		}
	})

	t.Run("attached payload", func(t *testing.T) {
		payload, err := deviceAuthenticationBytes(f.docType, f.transcript)
		if err != nil {
			t.Fatalf("deviceAuthenticationBytes: %v", err)
		}
		protected, err := macProtectedHeader()
		if err != nil {
			t.Fatalf("macProtectedHeader: %v", err)
		}
		tag, err := macTag(emacKey, protected, payload)
		if err != nil {
			t.Fatalf("macTag: %v", err)
		}
		attached, err := cbor.Marshal(coseMac0{
			Protected: protected, Unprotected: map[int]any{}, Payload: payload, Tag: tag,
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := VerifyDeviceMac(attached, emacKey, f.docType, f.transcript); err == nil {
			t.Fatal("a MAC with an attached payload verified; 9.1.3.5 requires a null payload")
		}
	})
}

// signOnlySigner is a crypto.Signer with no usable private key behind it, standing
// in for a platform key handle that can sign but cannot agree keys.
type signOnlySigner struct{ pub *ecdsa.PublicKey }

func (s signOnlySigner) Public() crypto.PublicKey { return s.pub }
func (s signOnlySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// TestSigningOnlyKeyCannotMac is the constraint that pushes work back into
// issuance: a device key created for signing cannot perform the ECKA-DH of
// 9.1.3.5, and the failure has to say so rather than looking like a bug.
func TestSigningOnlyKeyCannotMac(t *testing.T) {
	real, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	holder, err := NewHolderFromSigner(signOnlySigner{pub: real.PublicKey()})
	if err != nil {
		t.Fatalf("NewHolderFromSigner: %v", err)
	}

	// It is still a perfectly good Holder for the signature branch.
	var _ Holder = holder

	_, err = holder.AgreeSharedSecret(real.PublicKey())
	if err == nil {
		t.Fatal("a signing-only key performed key agreement")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("issuance")) {
		t.Errorf("the error does not point at the issuance-time fix: %v", err)
	}
}

// TestDeviceAuthIsExactlyOneBranch pins the CDDL's choice in 8.3.2.1.2.2.
func TestDeviceAuthIsExactlyOneBranch(t *testing.T) {
	if err := (DeviceAuth{}).validate(); err == nil {
		t.Error("a DeviceAuth with neither branch was accepted")
	}
	if err := (DeviceAuth{
		DeviceSignature: cbor.RawMessage{0x01}, DeviceMac: cbor.RawMessage{0x02},
	}).validate(); err == nil {
		t.Error("a DeviceAuth with both branches was accepted")
	}
	if err := (DeviceAuth{DeviceSignature: cbor.RawMessage{0x01}}).validate(); err != nil {
		t.Errorf("deviceSignature alone was rejected: %v", err)
	}
	if err := (DeviceAuth{DeviceMac: cbor.RawMessage{0x02}}).validate(); err != nil {
		t.Errorf("deviceMac alone was rejected: %v", err)
	}
}

// TestAttachDeviceMac checks a MAC-authenticated document survives a response
// round trip with the deviceMac branch intact.
func TestAttachDeviceMac(t *testing.T) {
	f := newMacFixture(t)
	issuer, err := NewTestIssuer()
	if err != nil {
		t.Fatalf("NewTestIssuer: %v", err)
	}
	credential, err := issuer.Issue(f.docType, f.docType,
		map[string]any{"age_over_18": true}, f.holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	deviceMac, err := MacDeviceAuth(f.holder, f.docType, f.transcript, &f.eReaderKey.PublicKey)
	if err != nil {
		t.Fatalf("MacDeviceAuth: %v", err)
	}
	presented, err := AttachDeviceMac(credential, deviceMac)
	if err != nil {
		t.Fatalf("AttachDeviceMac: %v", err)
	}

	encoded, err := NewDeviceResponse(*presented).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var response DeviceResponse
	if err := mdocDecMode.Unmarshal(encoded, &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	auth := response.Documents[0].DeviceSigned.DeviceAuth
	if len(auth.DeviceMac) == 0 {
		t.Fatal("deviceMac did not survive the round trip")
	}
	if len(auth.DeviceSignature) != 0 {
		t.Error("deviceSignature present alongside deviceMac")
	}

	emacKey, err := DeriveEMacKeyAsReader(f.eReaderKey, f.holder.PublicKey(), f.transcript)
	if err != nil {
		t.Fatalf("DeriveEMacKeyAsReader: %v", err)
	}
	if err := VerifyDeviceMac(auth.DeviceMac, emacKey, f.docType, f.transcript); err != nil {
		t.Fatalf("the transmitted deviceMac does not verify: %v", err)
	}
}
