package irmaclient

import (
	"encoding/json"

	"math/big"

	"github.com/credentials/go-go-gadget-paillier"
)

// paillierPrivateKey is an alias for paillier.PrivateKey so that we can add a custom unmarshaler to it.
type paillierPrivateKey paillier.PrivateKey
type paillierPublicKey paillier.PublicKey

func (psk *paillierPrivateKey) UnmarshalJSON(bytes []byte) (err error) {
	sk := new(paillier.PrivateKey)
	if err = json.Unmarshal(bytes, sk); err != nil {
		return
	}
	*psk = paillierPrivateKey(*sk)
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

func (ppk *paillierPublicKey) MarshalJSON() ([]byte, error) {
	temp := struct {
		N        *big.Int `json:"n"`
		G        *big.Int `json:"g"`
		NSquared *big.Int `json:"nSquared"`
		Bits     int      `json:"bits"`
	}{ppk.N, ppk.G, ppk.NSquared, ppk.N.BitLen()}
	return json.Marshal(temp)
}
