package protocol

import (
	"encoding/asn1"
	"math/big"

	"crypto/sha256"

	"log"

	"github.com/credentials/irmago"
)

type SessionRequest struct {
	Context *big.Int `json:"nonce"`
	Nonce   *big.Int `json:"context"`
}

type DisclosureRequest struct {
	SessionRequest
	Content irmago.AttributeDisjunctionList `json:"content"`
}

type SignatureRequest struct {
	DisclosureRequest
	Message     string `json:"message"`
	MessageType string `json:"messageType"`
}

type CredentialRequest struct {
	Validity   *Timestamp
	KeyCounter int
	Credential irmago.CredentialTypeIdentifier
	Attributes map[string]string
}

type ServerRequest struct {
	ServerName string     `json:"iss"`
	IssuedAt   *Timestamp `json:"iat"`
	Type       string     `json:"subject"`
}

type IssuanceRequest struct {
	SessionRequest
	Credentials []CredentialRequest             `json:"credentials"`
	Disclose    irmago.AttributeDisjunctionList `json:"disclose"`
}

type ServiceProviderRequest struct {
	ServerRequest
	Request struct {
		Request DisclosureRequest `json:"request"`
	} `json:"sprequest"`
}

type SignatureServerRequest struct {
	ServerRequest
	Request struct {
		Request SignatureRequest `json:"request"`
	} `json:"sigrequest"`
}

type IdentityProviderRequest struct {
	ServerRequest
	Request struct {
		Request IssuanceRequest `json:"request"`
	} `json:"iprequest"`
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
	// BigInteger messageHash = Crypto.sha256Hash(message.getBytes());
	// return Crypto.sha256Hash(Crypto.asn1Encode(nonce, messageHash));

	hashbytes := sha256.Sum256([]byte(sr.Message))
	hashint := new(big.Int).SetBytes(hashbytes[:])
	asn1bytes, err := asn1.Marshal([]*big.Int{sr.Nonce, hashint})
	if err != nil {
		log.Print(err) // TODO? does this happen?
	}
	asn1hash := sha256.Sum256(asn1bytes)
	return new(big.Int).SetBytes(asn1hash[:])
}

func (spr *ServiceProviderRequest) DisjunctionList() irmago.AttributeDisjunctionList {
	return spr.Request.Request.Content
}

func (ssr *SignatureServerRequest) DisjunctionList() irmago.AttributeDisjunctionList {
	return ssr.Request.Request.Content
}

func (ipr *IdentityProviderRequest) DisjunctionList() irmago.AttributeDisjunctionList {
	return ipr.Request.Request.Disclose
}
