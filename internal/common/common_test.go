package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/privacybydesign/gabi/signed"
	"github.com/stretchr/testify/require"
)

func TestSchemePrivateKeyWithPassphrase(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	passphrase := []byte("test")
	encryptedKey, err := MarshalSchemePrivateKeyWithPassphrase(key, passphrase)
	require.NoError(t, err)

	// Key should be encrypted, so it should not parse as a normal key anymore.
	_, err = signed.UnmarshalPemPrivateKey(encryptedKey)
	require.Error(t, err)

	// Unmarshal the key again to test the decryption.
	decryptedKey, err := ParseSchemePrivateKeyWithPassphrase(encryptedKey, passphrase)
	require.NoError(t, err)
	require.True(t, decryptedKey.Equal(key))
}

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"clean input unchanged", "GET /irma/session/abc123", "GET /irma/session/abc123"},
		{"empty string", "", ""},
		{"newline escaped", "line1\nline2", "line1\\nline2"},
		{"carriage return escaped", "line1\rline2", "line1\\rline2"},
		{"crlf escaped as one token", "line1\r\nline2", "line1\\r\\nline2"},
		{
			"forged log entry is neutralized",
			"user\r\nlevel=fatal msg=\"forged entry\"",
			"user\\r\\nlevel=fatal msg=\"forged entry\"",
		},
		{"multiple newlines", "a\nb\nc", "a\\nb\\nc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := SanitizeForLog(tc.input)
			require.Equal(t, tc.expected, out)
			// The result must never contain a raw CR or LF that could start a new log line.
			require.NotContains(t, out, "\n")
			require.NotContains(t, out, "\r")
		})
	}
}
