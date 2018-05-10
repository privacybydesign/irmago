package irma

import (
	"crypto/sha256"
	"encoding/asn1"
	"log"
	"math/big"

	"github.com/bwesterb/go-atum"
	"github.com/mhe/gabi"
)

// IrmaSignedMessage is a message signed with an attribute-based signature
// The 'realnonce' will be calculated as: SigRequest.GetNonce() = ASN1(sha256(message), sha256(nonce))
type IrmaSignedMessage struct {
	Signature gabi.ProofList  `json:"signature"`
	Nonce     *big.Int        `json:"nonce"`
	Context   *big.Int        `json:"context"`
	Message   string          `json:"message"`
	Timestamp *atum.Timestamp `json:"timestamp"`
}

func (im *IrmaSignedMessage) GetNonce() *big.Int {
	return ASN1ConvertSignatureNonce(im.Message, im.Nonce, im.Timestamp)
}

func (im *IrmaSignedMessage) MatchesNonceAndContext(request *SignatureRequest) bool {
	return im.Nonce.Cmp(request.Nonce) == 0 &&
		im.Context.Cmp(request.Context) == 0 &&
		im.GetNonce().Cmp(request.GetNonce()) == 0
}

// Convert a Nonce to a nonce of a signature session
// (with the message already hashed into it).
func ASN1ConvertSignatureNonce(message string, nonce *big.Int, timestamp *atum.Timestamp) *big.Int {
	msgHash := sha256.Sum256([]byte(message))
	tohash := []interface{}{nonce, new(big.Int).SetBytes(msgHash[:])}
	if timestamp != nil {
		tohash = append(tohash, timestamp.Sig.Data)
	}
	// TODO remove the 2, or keep backwards compatible?
	tohash = append([]interface{}{big.NewInt(int64(len(tohash)))}, tohash...)
	asn1bytes, err := asn1.Marshal(tohash)
	if err != nil {
		log.Print(err) // TODO
	}
	asn1hash := sha256.Sum256(asn1bytes)
	return new(big.Int).SetBytes(asn1hash[:])
}
