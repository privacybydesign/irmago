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
	StartKeyshareRegistration(manager *SchemeManager)
}

func newKeyshareServer(privatekey *paillierPrivateKey, url, email string) (ks *keyshareServer, err error) {
	ks.Nonce = make([]byte, 0, 32)
	ks.URL = url
	ks.Username = email
	ks.PrivateKey = privatekey
	_, err = rand.Read(ks.Nonce)
	return
}

func (ks *keyshareServer) HashedPin(pin string) string {
	hash := sha256.Sum256(append(ks.Nonce, []byte(pin)...))
	return base64.RawStdEncoding.EncodeToString(hash[:])
}

func KeyshareEnroll(manager *SchemeManager, email, pin string) error {
	transport := NewHTTPTransport(manager.KeyshareServer)
	kss, err := newKeyshareServer(Manager.paillierKey(), manager.URL, email)
	if err != nil {
		return err
	}
	message := keyshareRegistration{
		Username:  email,
		Pin:       kss.HashedPin(pin),
		PublicKey: (*paillierPublicKey)(&kss.PrivateKey.PublicKey),
	}

	// TODO: examine error returned by Post() to see if it tells us that the email address is already in use
	result := &struct{}{}
	err = transport.Post("/web/users/selfenroll", result, message)
	if err != nil {
		return err
	}
	return Manager.addKeyshareServer(manager, kss)
}
