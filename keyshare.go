package irmago

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"

	"github.com/mcornejo/go-go-gadget-paillier"
)

type keyshareServer struct {
	URL          string              `json:"url"`
	Username     string              `json:"username"`
	Nonce        []byte              `json:"nonce"`
	PrivateKey   *paillierPrivateKey `json:"keyPair"`
	keyGenerator paillierKeygen
}

// paillierPrivateKey is an alias for paillier.PrivateKey so that we can add a custom unmarshaler to it.
type paillierPrivateKey paillier.PrivateKey

type paillierKeygen interface {
	paillierKey() *paillierPrivateKey
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

func (psk *paillierPrivateKey) UnmarshalJSON(bytes []byte) (err error) {
	// First try to unmarshal it as a keypair serialized in the old Android format
	oldFormat := &struct {
		PrivateKey struct {
			L *big.Int `json:"lambda"`
			U *big.Int `json:"preCalculatedDenominator"`
		} `json:"privateKey"`
		PublicKey struct {
			N        *big.Int `json:"n"`
			G        *big.Int `json:"g"`
			NSquared *big.Int `json:"nSquared"`
		} `json:"publicKey"`
	}{}
	if err = json.Unmarshal(bytes, oldFormat); err != nil {
		return
	}
	if oldFormat.PrivateKey.L != nil {
		psk.L = oldFormat.PrivateKey.L
		psk.U = oldFormat.PrivateKey.U
		psk.PublicKey.G = oldFormat.PublicKey.G
		psk.PublicKey.N = oldFormat.PublicKey.N
		psk.PublicKey.NSquared = oldFormat.PublicKey.NSquared
		return nil
	}

	newFormat := new(paillier.PrivateKey)
	if err = json.Unmarshal(bytes, newFormat); err != nil {
		return
	}
	*psk = paillierPrivateKey(*newFormat)
	return
}

func (psk *paillierPrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(paillier.PrivateKey(*psk))
}

func (psk *paillierPrivateKey) Encrypt(bytes []byte) ([]byte, error) {
	return paillier.Encrypt(&psk.PublicKey, bytes)
}

func (psk *paillierPrivateKey) Decrypt(bytes []byte) ([]byte, error) {
	return paillier.Decrypt((*paillier.PrivateKey)(psk), bytes)
}
