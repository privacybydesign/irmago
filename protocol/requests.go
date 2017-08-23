package protocol

import (
	"math/big"

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

func (spr *ServiceProviderRequest) DisjunctionList() irmago.AttributeDisjunctionList {
	return spr.Request.Request.Content
}

func (ssr *SignatureServerRequest) DisjunctionList() irmago.AttributeDisjunctionList {
	return ssr.Request.Request.Content
}

func (ipr *IdentityProviderRequest) DisjunctionList() irmago.AttributeDisjunctionList {
	return ipr.Request.Request.Disclose
}
