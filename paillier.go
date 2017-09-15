package irmago

import (
	"encoding/json"
	"math/big"

	paillier "github.com/mcornejo/go-go-gadget-paillier"
)

// paillierPrivateKey is an alias for paillier.PrivateKey so that we can add a custom unmarshaler to it.
type paillierPrivateKey paillier.PrivateKey
type paillierPublicKey paillier.PublicKey

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

func (ppk *paillierPublicKey) MarshalJSON() ([]byte, error) {
	temp := struct {
		N        *big.Int `json:"n"`
		G        *big.Int `json:"g"`
		NSquared *big.Int `json:"nSquared"`
		Bits     int      `json:"bits"`
	}{ppk.N, ppk.G, ppk.NSquared, ppk.N.BitLen()}
	return json.Marshal(temp)
}
