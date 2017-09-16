package irmago

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

type keyshareServer struct {
	URL        string              `json:"url"`
	Username   string              `json:"username"`
	Nonce      []byte              `json:"nonce"`
	PrivateKey *paillierPrivateKey `json:"keyPair"`
}

type keyshareRegistration struct {
	Username  string             `json:"username"`
	Pin       string             `json:"pin"`
	PublicKey *paillierPublicKey `json:"publicKey"`
}

type KeyshareHandler interface {
	StartKeyshareRegistration(manager *SchemeManager, registrationCallback func(email, pin string))
}

func newKeyshareServer(privatekey *paillierPrivateKey, url, email string) (ks *keyshareServer, err error) {
	ks = &keyshareServer{
		Nonce:      make([]byte, 32),
		URL:        url,
		Username:   email,
		PrivateKey: privatekey,
	}
	_, err = rand.Read(ks.Nonce)
	return
}

func (ks *keyshareServer) HashedPin(pin string) string {
	hash := sha256.Sum256(append(ks.Nonce, []byte(pin)...))
	return base64.RawStdEncoding.EncodeToString(hash[:])
}
