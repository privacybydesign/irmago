package irma

import (
	"crypto/sha256"
	"encoding/asn1"
	"math/big"

	"github.com/bwesterb/go-atum"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

// IrmaSignedMessage is a message signed with an attribute-based signature
// The 'realnonce' will be calculated as: SigRequest.GetNonce() = ASN1(sha256(message), sha256(nonce))
type IrmaSignedMessage struct {
	Signature   gabi.ProofList       `json:"signature"`
	Nonce       *big.Int             `json:"nonce"`
	Context     *big.Int             `json:"context"`
	Message     string               `json:"message"`
	MessageType SignatureMessageType `json:"messageType"`
	Timestamp   *atum.Timestamp      `json:"timestamp"`
}

type SignatureMessageType string

const (
	SignatureMessageTypeString = "string"
	SignatureMessageTypeJPG    = "jpg"
)

func (im *IrmaSignedMessage) GetNonce() (*big.Int, error) {
	return ASN1ConvertSignatureNonce([]byte(im.Message), im.MessageType, im.Nonce, im.Timestamp)
}

func (im *IrmaSignedMessage) MatchesNonceAndContext(request *SignatureRequest) bool {
	sigNonce, sigErr := im.GetNonce()
	reqNonce, reqErr := request.GetNonce()
	if sigErr != nil || reqErr != nil {
		return false
	}
	return im.Nonce.Cmp(request.Nonce) == 0 &&
		im.Context.Cmp(request.Context) == 0 &&
		sigNonce.Cmp(reqNonce) == 0
}

func (t SignatureMessageType) Valid() bool {
	return t == "" || t == SignatureMessageTypeString || t == SignatureMessageTypeJPG
}

// ASN1ConvertSignatureNonce computes the nonce that is used in the creation of the attribute-based signature:
//    nonce = SHA256(serverNonce, SHA256(message), timestampSignature)
// where serverNonce is the nonce sent by the signature requestor.
func ASN1ConvertSignatureNonce(message []byte, messageType SignatureMessageType, nonce *big.Int, timestamp *atum.Timestamp) (*big.Int, error) {
	if !messageType.Valid() {
		return nil, errors.New("Invalid message type")
	}
	msgHash := sha256.Sum256(message)
	tohash := []interface{}{nonce, new(big.Int).SetBytes(msgHash[:])}
	if timestamp != nil {
		tohash = append(tohash, timestamp.Sig.Data)
	}
	if messageType != "" {
		tohash = append(tohash, messageType)
	}
	asn1bytes, err := asn1.Marshal(tohash)
	if err != nil {
		return nil, err
	}
	asn1hash := sha256.Sum256(asn1bytes)
	return new(big.Int).SetBytes(asn1hash[:]), nil
}
