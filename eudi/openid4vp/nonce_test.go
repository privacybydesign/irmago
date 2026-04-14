package openid4vp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateNonce_Valid(t *testing.T) {
	valid := []string{
		"abc123",
		"A-Z.a-z_0-9~",
		"nonce-with-hyphens",
		"nonce.with.dots",
		"nonce_with_underscores",
		"nonce~with~tildes",
	}
	for _, n := range valid {
		require.NoError(t, validateNonce(n), "nonce %q should be valid", n)
	}
}

func TestValidateNonce_Empty(t *testing.T) {
	require.ErrorContains(t, validateNonce(""), "nonce is required")
}

func TestValidateNonce_InvalidCharacters(t *testing.T) {
	invalid := []string{
		"nonce with spaces",
		"nonce+plus",
		"nonce/slash",
		"nonce=equals",
		"nonce&ampersand",
		"nonce#hash",
		"nonce@at",
		"nonce!bang",
		"nonce%percent",
	}
	for _, n := range invalid {
		require.ErrorContains(t, validateNonce(n), "invalid character",
			"nonce %q should be rejected", n)
	}
}
