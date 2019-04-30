package irma

import (
	"crypto/sha256"
	"encoding/asn1"
	gobig "math/big"

	"github.com/bwesterb/go-atum"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

// GetTimestamp GETs a signed timestamp (a signature over the current time and the parameters)
// over the message to be signed, the randomized signatures over the attributes, and the disclosed
// attributes, for in attribute-based signature sessions.
func GetTimestamp(message string, sigs []*big.Int, disclosed [][]*big.Int, conf *Configuration) (*atum.Timestamp, error) {
	nonce, err := TimestampRequest(message, sigs, disclosed, true, conf)
	if err != nil {
		return nil, err
	}
	alg := atum.Ed25519
	return atum.SendRequest(TimestampServerURL, atum.Request{
		Nonce:           nonce,
		PreferredSigAlg: &alg,
	})
}

var bigZero = big.NewInt(0)

// TimestampRequest computes the nonce to be signed by a timestamp server, given a message to be signed
// in an attribute-based signature session along with the randomized signatures over the attributes
// and the disclosed attributes.
func TimestampRequest(message string, sigs []*big.Int, disclosed [][]*big.Int, new bool, conf *Configuration) ([]byte, error) {
	msgHash := sha256.Sum256([]byte(message))

	// Convert the sigs and disclosed (double) slices to (double) slices of gobig.Int's for asn1
	sigsint := make([]*gobig.Int, len(sigs))
	for i, k := range sigs {
		sigsint[i] = k.Value()
	}

	disclosedint := make([][]*gobig.Int, len(disclosed))
	dlreps := make([]*gobig.Int, len(disclosed))
	var d interface{} = disclosedint
	for i, _ := range disclosed {
		if !new {
			disclosedint[i] = make([]*gobig.Int, len(disclosed[i]))
			for j, k := range disclosed[i] {
				disclosedint[i][j] = k.Value()
			}
		} else {
			if len(disclosed[i]) < 2 || disclosed[i][1].Cmp(bigZero) == 0 {
				return nil, errors.Errorf("metadata attribute of credential %d not disclosed", i)
			}
			meta := MetadataFromInt(disclosed[i][1], conf)
			pk, err := conf.PublicKey(meta.CredentialType().IssuerIdentifier(), meta.KeyCounter())
			if err != nil {
				return nil, err
			}
			dlreps[i] = gabi.RepresentToPublicKey(pk, disclosed[i]).Value()
		}
	}
	if new {
		d = dlreps
	}

	bts, err := asn1.Marshal(struct {
		Sigs      []*gobig.Int
		MsgHash   []byte
		Disclosed interface{}
	}{
		sigsint, msgHash[:], d,
	})
	if err != nil {
		return nil, err
	}

	hashed := sha256.Sum256(bts)
	return hashed[:], nil
}

const TimestampServerURL = "https://metrics.privacybydesign.foundation/atum"

// Given an SignedMessage, verify the timestamp over the signed message, disclosed attributes,
// and rerandomized CL-signatures.
func (sm *SignedMessage) VerifyTimestamp(message string, conf *Configuration) error {
	if sm.Timestamp.ServerUrl != TimestampServerURL {
		return errors.New("Untrusted timestamp server")
	}

	// Extract the disclosed attributes and randomized CL-signatures from the proofs in order to
	// construct the nonce that should be signed by the timestamp server.
	zero := big.NewInt(0)
	size := len(sm.Signature)
	sigs := make([]*big.Int, size)
	disclosed := make([][]*big.Int, size)
	for i, proof := range sm.Signature {
		proofd := proof.(*gabi.ProofD)
		sigs[i] = proofd.A
		ct := MetadataFromInt(proofd.ADisclosed[1], conf).CredentialType()
		if ct == nil {
			return errors.New("Cannot verify timestamp: signature contains attributes from unknown credential type")
		}
		attrcount := len(ct.AttributeTypes) + 2 // plus secret key and metadata
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

	bts, err := TimestampRequest(message, sigs, disclosed, sm.Version >= 2, conf)
	if err != nil {
		return err
	}
	valid, err := sm.Timestamp.Verify(bts)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("Timestamp signature invalid")
	}
	return nil
}
