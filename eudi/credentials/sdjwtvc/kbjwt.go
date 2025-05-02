package sdjwtvc

import (
	"encoding/json"
	"fmt"
)

// a string containg the key binding jwt (just the jwt, no ~ or something)
type KeyBindingJwt string

type KeyBindingJwtPayload struct {
	// REQUIRED: the hash over the **COMPLETE** issuer signed JWT part of the SD-JWT
	IssuerSignedJwtHash string `json:"sd_hash"`

	// REQUIRED: the nonce for this, should always have the value "nonce"
	Nonce string `json:"nonce"`

	// REQUIRED: the time of issuance
	IssuedAt int64 `json:"iat"`

	// Should be "Verifier"
	Audience string `json:"aud"`
}

const (
	Key_SdHash   string = "sd_hash"
	Key_Nonce    string = "nonce"
	Key_Audience string = "aud"
)

// An interface for creating a key binding jwt from a hash.
// Can be used to move creating the kbjwt to a server.
type KbJwtCreator interface {
	// takes in the hash over the issuer signed JWT and the selected disclosures
	CreateKbJwt(sdJwtHash string) (KeyBindingJwt, error)
}

type DefaultKbJwtCreator struct {
	Clock      Clock
	JwtCreator JwtCreator
}

func (c *DefaultKbJwtCreator) CreateKbJwt(hash string) (KeyBindingJwt, error) {
	payload := KeyBindingJwtPayload{
		IssuerSignedJwtHash: hash,
		Nonce:               "nonce",
		IssuedAt:            c.Clock.Now(),
		Audience:            "Verifier",
	}
	json, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	customHeaders := map[string]string{
		"typ": KbJwtTyp,
	}

	jwt, err := c.JwtCreator.CreateSignedJwt(customHeaders, string(json))
	return KeyBindingJwt(jwt), err
}

func CreateKbJwt(sdJwt SdJwtVc, creator KbJwtCreator) (KeyBindingJwt, error) {
	alg, err := extractHashingAlgorithm(sdJwt)
	if err != nil {
		return "", err
	}

	hash, err := CreateHash(alg, string(sdJwt))
	if err != nil {
		return "", nil
	}

	return creator.CreateKbJwt(hash)
}

func extractHashingAlgorithm(sdJwt SdJwtVc) (HashingAlgorithm, error) {
	issuerSignedJwt, _, _, err := SplitSdJwtVc(sdJwt)
	if err != nil {
		return "", err
	}
	_, claims, err := decodeJwtWithoutCheckingSignature(string(issuerSignedJwt))
	if err != nil {
		return "", err
	}

	alg, ok := claims[Key_SdAlg].(string)
	if !ok {
		return "", fmt.Errorf("failed to get %s field from claims", Key_SdAlg)
	}
	return HashingAlgorithm(alg), nil
}
