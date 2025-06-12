package sdjwtvc

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/utils"
)

// KeyBindingJwt is a string containing the key binding jwt (just the jwt, no ~ or something)
type KeyBindingJwt string

type KeyBindingJwtPayload struct {
	// REQUIRED: the hash over the **COMPLETE** issuer signed JWT part of the SD-JWT
	IssuerSignedJwtHash string `json:"sd_hash"`

	// REQUIRED: the nonce for this, should correspond to the one from the authorization
	Nonce string `json:"nonce"`

	// REQUIRED: the time of issuance
	IssuedAt int64 `json:"iat"`

	// Should equal "client_id" field from the openid4vp auth request
	Audience string `json:"aud"`
}

const (
	Key_SdHash   string = "sd_hash"
	Key_Nonce    string = "nonce"
	Key_Audience string = "aud"
)

// KbJwtCreator is an interface for creating a key binding jwt from a hash.
// Can be used to move creating the kbjwt to a server.
type KbJwtCreator interface {
	// takes in the hash over the issuer signed JWT and the selected disclosures
	CreateKbJwt(hash string, holderKey jwk.Key, nonce string, audience string) (KeyBindingJwt, error)
}

type DefaultKbJwtCreator struct {
	Clock      Clock
	JwtCreator JwtCreator
}

func (c *DefaultKbJwtCreator) CreateKbJwt(hash string, holderKey jwk.Key, nonce string, audience string) (KeyBindingJwt, error) {
	payload := KeyBindingJwtPayload{
		IssuerSignedJwtHash: hash,
		Nonce:               nonce,
		IssuedAt:            c.Clock.Now(),
		Audience:            audience,
	}
	json, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	customHeaders := map[string]any{
		"typ": KbJwtTyp,
	}

	jwt, err := c.JwtCreator.CreateSignedJwt(customHeaders, string(json))
	return KeyBindingJwt(jwt), err
}

func CreateKbJwt(sdJwt SdJwtVc, creator KbJwtCreator, nonce string, audience string) (KeyBindingJwt, error) {
	alg, holderKey, err := extractHashingAlgorithmAndHolderPubKey(sdJwt)
	if err != nil {
		return "", err
	}

	hash, err := CreateHash(alg, string(sdJwt))
	if err != nil {
		return "", nil
	}

	return creator.CreateKbJwt(hash, holderKey, nonce, audience)
}

func extractHashingAlgorithmAndHolderPubKey(sdJwt SdJwtVc) (HashingAlgorithm, jwk.Key, error) {
	issuerSignedJwt, _, _, err := SplitSdJwtVc(sdJwt)
	if err != nil {
		return "", nil, err
	}
	_, claims, err := decodeJwtWithoutCheckingSignature(string(issuerSignedJwt))
	if err != nil {
		return "", nil, err
	}

	alg, ok := claims[Key_SdAlg].(string)
	if !ok {
		return "", nil, fmt.Errorf("failed to get %s field from claims", Key_SdAlg)
	}

	confirm, err := utils.ExtractOptionalWith(claims, Key_Confirmationkey, parseConfirmField)

	if err != nil {
		return "", nil, err
	}

	keyJson, err := json.Marshal(confirm.Jwk)
	if err != nil {
		return "", nil, err
	}
	key, err := jwk.ParseKey(keyJson)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse key (%v) from json: %v", keyJson, err)
	}

	return HashingAlgorithm(alg), key, nil
}
