package irmago

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/mcornejo/go-go-gadget-paillier"
)

type keyshareServer struct {
	URL          string              `json:"url"`
	Username     string              `json:"username"`
	Nonce        []byte              `json:"nonce"`
	PrivateKey   *paillierPrivateKey `json:"keyPair"`
	keyGenerator paillierKeygen
}

type keyshareRegistration struct {
	Username  string             `json:"username"`
	Pin       string             `json:"pin"`
	PublicKey paillier.PublicKey `json:"publicKey"`
}

func newKeyshareServer(keygen paillierKeygen) (ks *keyshareServer, err error) {
	ks.Nonce = make([]byte, 0, 32)
	ks.keyGenerator = keygen
	_, err = rand.Read(ks.Nonce)
	return
}

func (ks *keyshareServer) HashedPin(pin string) string {
	hash := sha256.Sum256(append(ks.Nonce, []byte(pin)...))
	return base64.RawStdEncoding.EncodeToString(hash[:])
}

func (ks *keyshareServer) GetKey() *paillierPrivateKey {
	if ks.PrivateKey == nil {
		ks.PrivateKey = ks.keyGenerator.paillierKey()
	}
	return ks.PrivateKey
}

func KeyshareEnroll(manager *SchemeManager, email, pin string) error {
	//NewHTTPTransport(qr.URL)
}
