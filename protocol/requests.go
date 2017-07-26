package protocol

import "math/big"

type SessionRequest struct {
	Context *big.Int
	Nonce   *big.Int
}

type DisclosureRequest struct {
	SessionRequest
	content *AttributeDisjunctionList
}
