package oauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

const DefaultVerifierSize = 32
const minVerifierSizeChars = 43
const maxVerifierSizeChars = 128

type CodeChallenge struct {
	method    string
	challenge string
}

func (c *CodeChallenge) GetCodeChallenge() string {
	return c.challenge
}

func (c *CodeChallenge) GetCodeChallengeMethod() string {
	return c.method
}

type CodeChallengeProvider interface {
	GenerateCodeChallenge(verifier string) CodeChallenge
}

type S256CodeChallengeProvider struct{}

func (p *S256CodeChallengeProvider) GenerateCodeChallenge(verifier string) CodeChallenge {
	// The code challenge is the BASE64URL-encoded SHA256 hash of the code verifier. See https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
	hash := sha256.Sum256([]byte(verifier))
	return CodeChallenge{
		method:    "S256",
		challenge: base64.RawURLEncoding.EncodeToString(hash[:]),
	}
}

type PlainCodeChallengeProvider struct{}

func (p *PlainCodeChallengeProvider) GenerateCodeChallenge(verifier string) CodeChallenge {
	// The code challenge is the same as the code verifier for the "plain" method. See https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
	return CodeChallenge{
		method:    "plain",
		challenge: verifier,
	}
}

func GenerateVerifier(byteSize uint) (string, error) {
	// PKCE code verifier should be a high-entropy cryptographic random string with a minimum length of 43 characters and a maximum length of 128 characters. See https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
	if byteSize*2 < minVerifierSizeChars {
		return "", fmt.Errorf("PKCE code verifier must be at least %d characters (%d bytes)", minVerifierSizeChars, (minVerifierSizeChars+1)/2)
	}

	if byteSize*2 > maxVerifierSizeChars {
		return "", fmt.Errorf("PKCE code verifier must be at most %d characters (%d bytes)", maxVerifierSizeChars, (maxVerifierSizeChars+1)/2)
	}

	buf := make([]byte, byteSize)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("could not generate random bytes: %v", err)
	}

	return hex.EncodeToString(buf), nil
}

func GenerateDefaultSizeVerifier() string {
	codeVerifier, err := GenerateVerifier(DefaultVerifierSize)
	if err != nil {
		panic(err)
	}
	return codeVerifier

}
