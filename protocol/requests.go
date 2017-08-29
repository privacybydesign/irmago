package protocol

import (
	"encoding/asn1"
	"math/big"
	"time"

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

type IssuanceRequest struct {
	SessionRequest
	Credentials []CredentialRequest             `json:"credentials"`
	Disclose    irmago.AttributeDisjunctionList `json:"disclose"`
}

type CredentialRequest struct {
	Validity   *Timestamp
	KeyCounter int
	Credential irmago.CredentialTypeIdentifier
	Attributes map[string]string
}

type ServerJwt struct {
	ServerName string     `json:"iss"`
	IssuedAt   *Timestamp `json:"iat"`
	Type       string     `json:"sub"`
}

type ServiceProviderRequest struct {
	Request DisclosureRequest `json:"request"`
}

type SignatureServerRequest struct {
	Request SignatureRequest `json:"request"`
}

type IdentityProviderRequest struct {
	Request IssuanceRequest `json:"request"`
}

type ServiceProviderJwt struct {
	ServerJwt
	Request ServiceProviderRequest `json:"sprequest"`
}

type SignatureServerJwt struct {
	ServerJwt
	Request SignatureServerRequest `json:"absrequest"`
}

type IdentityProviderJwt struct {
	ServerJwt
	Request IdentityProviderRequest `json:"iprequest"`
}

func NewServiceProviderJwt(servername string, dr DisclosureRequest) *ServiceProviderJwt {
	now := Timestamp(time.Now())
	return &ServiceProviderJwt{
		ServerJwt: ServerJwt{
			ServerName: servername,
			IssuedAt:   &now,
			Type:       "verification_request",
		},
		Request: ServiceProviderRequest{Request: dr},
	}
}

func NewSignatureServerJwt(servername string, sr SignatureRequest) *SignatureServerJwt {
	now := Timestamp(time.Now())
	return &SignatureServerJwt{
		ServerJwt: ServerJwt{
			ServerName: servername,
			IssuedAt:   &now,
			Type:       "signature_request",
		},
		Request: SignatureServerRequest{Request: sr},
	}
}

func NewIdentityProviderJwt(servername string, ir IssuanceRequest) *IdentityProviderJwt {
	now := Timestamp(time.Now())
	return &IdentityProviderJwt{
		ServerJwt: ServerJwt{
			ServerName: servername,
			IssuedAt:   &now,
			Type:       "signature_request",
		},
		Request: IdentityProviderRequest{Request: ir},
	}
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

func (spr *ServiceProviderJwt) DisjunctionList() irmago.AttributeDisjunctionList {
	return spr.Request.Request.Content
}

func (ssr *SignatureServerJwt) DisjunctionList() irmago.AttributeDisjunctionList {
	return ssr.Request.Request.Content
}

func (ipr *IdentityProviderJwt) DisjunctionList() irmago.AttributeDisjunctionList {
	return ipr.Request.Request.Disclose
}
