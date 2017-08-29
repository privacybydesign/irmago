package irmago

import (
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"time"
)

// Timestamp is a time.Time that marshals to Unix timestamps.
type Timestamp time.Time

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
	Credentials []CredentialRequest      `json:"credentials"`
	Disclose    AttributeDisjunctionList `json:"disclose"`
}

type CredentialRequest struct {
	Validity   *Timestamp
	KeyCounter int
	Credential CredentialTypeIdentifier
	Attributes map[string]string
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
