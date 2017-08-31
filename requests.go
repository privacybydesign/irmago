package irmago

import (
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"time"

	"github.com/mhe/gabi"
)

type SessionRequest struct {
	Context *big.Int `json:"nonce"`
	Nonce   *big.Int `json:"context"`
}

type DisclosureRequest struct {
	SessionRequest
	Content AttributeDisjunctionList `json:"content"`
}

type SignatureRequest struct {
	DisclosureRequest
	Message     string `json:"message"`
	MessageType string `json:"messageType"`
}

type IssuanceRequest struct {
	SessionRequest
	Credentials []*CredentialRequest     `json:"credentials"`
	Disclose    AttributeDisjunctionList `json:"disclose"`

	state *issuanceState
}

type CredentialRequest struct {
	Validity   *Timestamp                `json:"validity"`
	KeyCounter int                       `json:"keyCounter"`
	Credential *CredentialTypeIdentifier `json:"credential"`
	Attributes map[string]string         `json:"attributes"`
}

// Timestamp is a time.Time that marshals to Unix timestamps.
type Timestamp time.Time

type issuanceState struct {
	nonce2   *big.Int
	builders []*gabi.CredentialBuilder
}

func (cr *CredentialRequest) AttributeList() (*AttributeList, error) {
	meta := NewMetadataAttribute()
	meta.setKeyCounter(cr.KeyCounter)
	meta.setCredentialTypeIdentifier(cr.Credential.String())
	meta.setSigningDate()
	err := meta.setExpiryDate(cr.Validity)
	if err != nil {
		return nil, err
	}

	attrs := make([]*big.Int, len(cr.Attributes)+1, len(cr.Attributes)+1)
	credtype := MetaStore.Credentials[*cr.Credential]
	if credtype == nil {
		return nil, errors.New("Unknown credential type")
	}
	if len(credtype.Attributes) != len(cr.Attributes) {
		return nil, errors.New("Received unexpected amount of attributes")
	}

	attrs[0] = meta.Int
	for i, attrtype := range credtype.Attributes {
		if str, present := cr.Attributes[attrtype.ID]; present {
			attrs[i+1] = new(big.Int).SetBytes([]byte(str))
		} else {
			return nil, errors.New("Unknown attribute")
		}
	}

	return NewAttributeListFromInts(attrs), nil
}

func newIssuanceState(request *IssuanceRequest) (*issuanceState, error) {
	nonce2, err := gabi.RandomBigInt(gabi.DefaultSystemParameters[4096].Lstatzk)
	if err != nil {
		return nil, err
	}
	return &issuanceState{
		nonce2:   nonce2,
		builders: []*gabi.CredentialBuilder{},
	}, nil
}

func (ir *IssuanceRequest) GetContext() *big.Int {
	return ir.Context
}

func (ir *IssuanceRequest) GetNonce() *big.Int {
	return ir.Nonce
}

func (dr *DisclosureRequest) GetContext() *big.Int {
	return dr.Context
}

func (dr *DisclosureRequest) GetNonce() *big.Int {
	return dr.Nonce
}

func (sr *SignatureRequest) GetContext() *big.Int {
	return sr.Context
}

func (sr *SignatureRequest) GetNonce() *big.Int {
	hashbytes := sha256.Sum256([]byte(sr.Message))
	hashint := new(big.Int).SetBytes(hashbytes[:])
	// TODO the 2 should be abstracted away
	asn1bytes, err := asn1.Marshal([]interface{}{big.NewInt(2), sr.Nonce, hashint})
	if err != nil {
		log.Print(err) // TODO? does this happen?
	}
	asn1hash := sha256.Sum256(asn1bytes)
	return new(big.Int).SetBytes(asn1hash[:])
}

// MarshalJSON marshals a timestamp.
func (t *Timestamp) MarshalJSON() ([]byte, error) {
	ts := time.Time(*t).Unix()
	stamp := fmt.Sprint(ts)
	return []byte(stamp), nil
}

// UnmarshalJSON unmarshals a timestamp.
func (t *Timestamp) UnmarshalJSON(b []byte) error {
	ts, err := strconv.Atoi(string(b))
	if err != nil {
		return err
	}
	*t = Timestamp(time.Unix(int64(ts), 0))
	return nil
}
