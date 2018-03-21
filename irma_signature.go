package irma

import (
	"crypto/sha256"
	"encoding/asn1"
	"github.com/mhe/gabi"
	"log"
	"math/big"
)

// IrmaSignedMessage is a message signed with an attribute-based signature
// The 'realnonce' will be calculated as: SigRequest.GetNonce() = ASN1(sha256(message), sha256(nonce))
type IrmaSignedMessage struct {
	Signature *gabi.ProofList `json:"signature"`
	Nonce     *big.Int        `json:"nonce"`
	Context   *big.Int        `json:"context"`
	Message   string          `json:"message"`
}

func (im *IrmaSignedMessage) GetNonce() *big.Int {
	return ASN1ConvertSignatureNonce(im.Message, im.Nonce)
}

func (im *IrmaSignedMessage) MatchesNonceAndContext(request *SignatureRequest) bool {
	// TODO: string comparison needed?
	return im.Nonce.String() == request.Nonce.String() &&
		im.Context.String() == request.Context.String() &&
		im.GetNonce().String() == request.GetNonce().String()
}

// Create an IrmaSignedMessage struct and check if type assertions hold
// bool is false if type assertion failed
func SignedMessageFromSession(session IrmaSession, message interface{}) (*IrmaSignedMessage, bool) {
	signature, ok1 := message.(gabi.ProofList)
	request, ok2 := session.(*SignatureRequest)

	if !ok1 || !ok2 {
		return nil, false
	}

	return &IrmaSignedMessage{
		Signature: &signature,
		Nonce:     request.Nonce,
		Context:   request.Context,
		Message:   request.Message,
	}, true
}

// Convert a Nonce to a nonce of a signature session
// (with the message already hashed into it).
func ASN1ConvertSignatureNonce(message string, nonce *big.Int) *big.Int {
	hashbytes := sha256.Sum256([]byte(message))
	hashint := new(big.Int).SetBytes(hashbytes[:])
	// TODO the 2 should be abstracted away
	asn1bytes, err := asn1.Marshal([]interface{}{big.NewInt(2), nonce, hashint})
	if err != nil {
		log.Print(err) // TODO? does this happen?
	}
	asn1hash := sha256.Sum256(asn1bytes)
	return new(big.Int).SetBytes(asn1hash[:])
}
