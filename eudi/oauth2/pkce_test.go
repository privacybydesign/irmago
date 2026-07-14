package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestS256CodeChallengeProvider_GenerateCodeChallenge(t *testing.T) {
	provider := &S256CodeChallengeProvider{}

	tests := []struct {
		verifier string
	}{
		{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
		{"testverifier"},
		{"anotherVerifier123!"},
		{"short"},
		{"with-special_chars~._-"},
	}

	for _, tt := range tests {
		t.Run(tt.verifier, func(t *testing.T) {
			cc := provider.GenerateCodeChallenge(tt.verifier)
			if cc.method != "S256" {
				t.Errorf("expected method 'S256', got '%s'", cc.method)
			}

			expectedHash := sha256.Sum256([]byte(tt.verifier))
			expectedChallenge := base64.RawURLEncoding.EncodeToString(expectedHash[:])
			if cc.challenge != expectedChallenge {
				t.Errorf("expected challenge '%s', got '%s'", expectedChallenge, cc.challenge)
			}
		})
	}
}

func TestS256CodeChallengeProvider_GenerateCodeChallenge_EmptyVerifier(t *testing.T) {
	provider := &S256CodeChallengeProvider{}
	cc := provider.GenerateCodeChallenge("")
	if cc.method != "S256" {
		t.Errorf("expected method 'S256', got '%s'", cc.method)
	}
	expectedHash := sha256.Sum256([]byte(""))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(expectedHash[:])
	if cc.challenge != expectedChallenge {
		t.Errorf("expected challenge '%s', got '%s'", expectedChallenge, cc.challenge)
	}
}

func TestGenerateVerifier_ValidSizes(t *testing.T) {
	tests := []struct {
		byteSize uint
	}{
		{22}, // 44 chars (min valid)
		{32}, // 64 chars (default)
		{64}, // 128 chars (max valid)
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("byteSize_%d", tt.byteSize), func(t *testing.T) {
			verifier, err := GenerateVerifier(tt.byteSize)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(verifier) != int(tt.byteSize*2) {
				t.Errorf("expected verifier length %d, got %d", tt.byteSize*2, len(verifier))
			}
		})
	}
}

func TestGenerateVerifier_TooSmall(t *testing.T) {
	// 21 bytes = 42 chars, which is less than the minimum 43 chars
	verifier, err := GenerateVerifier(21)
	if err == nil {
		t.Errorf("expected error for too small byteSize, got verifier: %s", verifier)
	}
}

func TestGenerateVerifier_TooLarge(t *testing.T) {
	// 65 bytes = 130 chars, which is more than the maximum 128 chars
	verifier, err := GenerateVerifier(65)
	if err == nil {
		t.Errorf("expected error for too large byteSize, got verifier: %s", verifier)
	}
}

func TestGenerateVerifier_Randomness(t *testing.T) {
	verifier1, err1 := GenerateVerifier(32)
	verifier2, err2 := GenerateVerifier(32)
	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected error: %v %v", err1, err2)
	}
	if verifier1 == verifier2 {
		t.Errorf("expected different verifiers, got the same: %s", verifier1)
	}
}
