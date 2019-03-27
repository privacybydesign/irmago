package irma

import (
	"crypto/sha256"
	"encoding/asn1"
	"log"
	gobig "math/big"

	"github.com/bwesterb/go-atum"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

// SignedMessage is a message signed with an attribute-based signature
// The 'realnonce' will be calculated as: SigRequest.GetNonce() = ASN1(nonce, SHA256(message), timestampSignature)
type SignedMessage struct {
	Signature gabi.ProofList            `json:"signature"`
	Indices   DisclosedAttributeIndices `json:"indices"`
	Nonce     *big.Int                  `json:"nonce"`
	Context   *big.Int                  `json:"context"`
	Message   string                    `json:"message"`
	Timestamp *atum.Timestamp           `json:"timestamp"`
}

func (sm *SignedMessage) GetNonce() *big.Int {
	return ASN1ConvertSignatureNonce(sm.Message, sm.Nonce, sm.Timestamp)
}

func (sm *SignedMessage) MatchesNonceAndContext(request *SignatureRequest) bool {
	return sm.Context.Cmp(request.GetContext()) == 0 &&
		sm.GetNonce().Cmp(request.GetNonce(sm.Timestamp)) == 0
}

func (sm *SignedMessage) Disclosure() *Disclosure {
	return &Disclosure{
		Proofs:  sm.Signature,
		Indices: sm.Indices,
	}
}

// ASN1ConvertSignatureNonce computes the nonce that is used in the creation of the attribute-based signature:
//    nonce = SHA256(serverNonce, SHA256(message), timestampSignature)
// where serverNonce is the nonce sent by the signature requestor.
func ASN1ConvertSignatureNonce(message string, nonce *big.Int, timestamp *atum.Timestamp) *big.Int {
	msgHash := sha256.Sum256([]byte(message))
	tohash := []interface{}{nonce.Value(), new(gobig.Int).SetBytes(msgHash[:])}
	if timestamp != nil {
		tohash = append(tohash, timestamp.Sig.Data)
	}
	asn1bytes, err := asn1.Marshal(tohash)
	if err != nil {
		log.Print(err) // TODO
	}
	asn1hash := sha256.Sum256(asn1bytes)
	return new(big.Int).SetBytes(asn1hash[:])
}
