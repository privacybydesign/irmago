package keyshareCore

import (
	"crypto/rand"
	"testing"

	"github.com/privacybydesign/gabi/big"
)

func TestPacketAccess(t *testing.T) {
	var testSecret = big.NewInt(51232)
	var testPassword [64]byte
	_, err := rand.Read(testPassword[:])
	if err != nil {
		t.Fatal(err)
	}

	var p unencryptedKeysharePacket
	p.setPin(testPassword)
	p.setKeyshareSecret(testSecret)
	if p.getPin() != testPassword {
		t.Error("password doesn't match")
	}
	if p.getKeyshareSecret().Cmp(testSecret) != 0 {
		t.Error("keyshare secret doesn't match")
	}
}

func TestPacketEncryptDecrypt(t *testing.T) {
	// Setup keys for test
	_, err := rand.Read(encryptionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptionKeyID = 1
	decryptionKeys[encryptionKeyID] = encryptionKey

	// Test parameters
	var testSecret = big.NewInt(5)
	var testPassword [64]byte
	_, err = rand.Read(testPassword[:])
	if err != nil {
		t.Fatal(err)
	}

	// Create and encrypt packet
	var p_before unencryptedKeysharePacket
	p_before.setPin(testPassword)
	err = p_before.setKeyshareSecret(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	p_encypted, err := encryptPacket(p_before)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt and test values
	p_after, err := decryptPacket(p_encypted)
	if err != nil {
		t.Fatal(err)
	}
	if p_after.getPin() != testPassword {
		t.Error("passwords don't match")
	}
	if p_after.getKeyshareSecret().Cmp(testSecret) != 0 {
		t.Error("keyshare secrets don't match")
	}
}

func TestPacketAuthentication(t *testing.T) {
	// Setup keys for test
	_, err := rand.Read(encryptionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptionKeyID = 1
	decryptionKeys[encryptionKeyID] = encryptionKey

	// Test parameters
	var testSecret = big.NewInt(5)
	var testPassword [64]byte
	_, err = rand.Read(testPassword[:])
	if err != nil {
		t.Fatal(err)
	}

	// Create and encrypt packet
	var p_before unencryptedKeysharePacket
	p_before.setPin(testPassword)
	err = p_before.setKeyshareSecret(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	p_encrypted, err := encryptPacket(p_before)
	if err != nil {
		t.Fatal(err)
	}

	// Modify encrypted packet and check that it no longer decrypts
	p_encrypted[33] = 0
	p_encrypted[34] = 15
	_, err = decryptPacket(p_encrypted)
	if err == nil {
		t.Error("Tampering not detected")
	}
}

func TestMultiKey(t *testing.T) {
	// Setup keys for test
	_, err := rand.Read(encryptionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptionKeyID = 1
	decryptionKeys[encryptionKeyID] = encryptionKey
	// Setup keys for test (2)
	_, err = rand.Read(encryptionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptionKeyID = 2
	decryptionKeys[encryptionKeyID] = encryptionKey

	// Test parameters
	var testSecret = big.NewInt(5)
	var testPassword [64]byte
	_, err = rand.Read(testPassword[:])
	if err != nil {
		t.Fatal(err)
	}

	// Create packet
	var p_before unencryptedKeysharePacket
	p_before.setPin(testPassword)
	err = p_before.setKeyshareSecret(testSecret)
	if err != nil {
		t.Fatal(err)
	}

	// encrypt with key 1
	encryptionKeyID = 1
	encryptionKey = decryptionKeys[encryptionKeyID]
	e1, err := encryptPacket(p_before)
	if err != nil {
		t.Fatal(err)
	}

	// encrypt with key 2
	encryptionKeyID = 2
	encryptionKey = decryptionKeys[encryptionKeyID]
	e2, err := encryptPacket(p_before)
	if err != nil {
		t.Fatal(err)
	}

	// Check e1
	p_after, err := decryptPacket(e1)
	if err != nil {
		t.Error(err)
	}
	if p_after != p_before {
		t.Error("packet mismatch on key 1")
	}

	// Check e2
	p_after, err = decryptPacket(e2)
	if err != nil {
		t.Error(err)
	}
	if p_after != p_before {
		t.Error("packet mismatch on key 2")
	}

	// check that unknown key is detected correctly
	delete(decryptionKeys, 1)
	_, err = decryptPacket(e1)
	if err == nil {
		t.Error("Missing decryption key not detected.")
	}
}
