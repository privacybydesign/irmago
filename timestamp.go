package irma

import (
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/bwesterb/go-atum"
	"github.com/mhe/gabi"
)

// GetTimestamp GETs a signed timestamp (a signature over the current time and the parameters)
// over the message to be signed, the randomized signatures over the attributes, and the disclosed
// attributes, for in attribute-based signature sessions.
func GetTimestamp(message string, sigs []*big.Int, disclosed [][]*big.Int) (*atum.Timestamp, error) {
	nonce, err := TimestampRequest(message, sigs, disclosed)
	if err != nil {
		return nil, err
	}
	alg := atum.Ed25519
	return atum.SendRequest(TimestampServerURL, atum.Request{
		Nonce:           nonce,
		PreferredSigAlg: &alg,
	})
}

// TimestampRequest computes the nonce to be signed by a timestamp server, given a message to be signed
// in an attribute-based signature session along with the randomized signatures over the attributes
// and the disclosed attributes.
func TimestampRequest(message string, sigs []*big.Int, disclosed [][]*big.Int) ([]byte, error) {
	msgHash := sha256.Sum256([]byte(message))

	bts, err := asn1.Marshal(struct {
		Sigs      []*big.Int
		MsgHash   []byte
		Disclosed [][]*big.Int
	}{
		sigs, msgHash[:], disclosed,
	})
	if err != nil {
		return nil, err
	}

	hashed := sha256.Sum256(bts)
	return hashed[:], nil
}

const TimestampServerURL = "https://metrics.privacybydesign.foundation/atum"

// Given an IrmaSignedMessage, verify the timestamp over the signed message, disclosed attributes,
// and rerandomized CL-signatures.
func VerifyTimestamp(irmaSignature *IrmaSignedMessage, message string, conf *Configuration) error {
	if irmaSignature.Timestamp.ServerUrl != TimestampServerURL {
		return errors.New("Untrusted timestamp server")
	}

	// Extract the disclosed attributes and randomized CL-signatures from the proofs in order to
	// construct the nonce that should be signed by the timestamp server.
	zero := big.NewInt(0)
	size := len(*irmaSignature.Signature)
	sigs := make([]*big.Int, size)
	disclosed := make([][]*big.Int, size)
	for i, proof := range *irmaSignature.Signature {
		proofd := proof.(*gabi.ProofD)
		meta := MetadataFromInt(proofd.ADisclosed[1], conf)
		sigs[i] = proofd.A

		// TODO check for nil
		attrcount := len(meta.CredentialType().Attributes) + 2 // plus secret key and metadata
		disclosed[i] = make([]*big.Int, attrcount)
		for j := 0; j < attrcount; j++ {
			val, ok := proofd.ADisclosed[j]
			if !ok {
				disclosed[i][j] = zero
			} else {
				disclosed[i][j] = val
			}
		}
	}

	bts, err := TimestampRequest(message, sigs, disclosed)
	if err != nil {
		return err
	}
	valid, err := irmaSignature.Timestamp.Verify(bts)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("Timestamp signature invalid")
	}
	return nil
}
