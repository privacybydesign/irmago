package protocol

import (
	"time"

	"github.com/credentials/irmago"
)

type ServerJwt struct {
	ServerName string            `json:"iss"`
	IssuedAt   *irmago.Timestamp `json:"iat"`
	Type       string            `json:"sub"`
}

type ServiceProviderRequest struct {
	Request irmago.DisclosureRequest `json:"request"`
}

type SignatureServerRequest struct {
	Request irmago.SignatureRequest `json:"request"`
}

type IdentityProviderRequest struct {
	Request irmago.IssuanceRequest `json:"request"`
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

func NewServiceProviderJwt(servername string, dr irmago.DisclosureRequest) *ServiceProviderJwt {
	now := irmago.Timestamp(time.Now())
	return &ServiceProviderJwt{
		ServerJwt: ServerJwt{
			ServerName: servername,
			IssuedAt:   &now,
			Type:       "verification_request",
		},
		Request: ServiceProviderRequest{Request: dr},
	}
}

func NewSignatureServerJwt(servername string, sr irmago.SignatureRequest) *SignatureServerJwt {
	now := irmago.Timestamp(time.Now())
	return &SignatureServerJwt{
		ServerJwt: ServerJwt{
			ServerName: servername,
			IssuedAt:   &now,
			Type:       "signature_request",
		},
		Request: SignatureServerRequest{Request: sr},
	}
}

func NewIdentityProviderJwt(servername string, ir irmago.IssuanceRequest) *IdentityProviderJwt {
	now := irmago.Timestamp(time.Now())
	return &IdentityProviderJwt{
		ServerJwt: ServerJwt{
			ServerName: servername,
			IssuedAt:   &now,
			Type:       "signature_request",
		},
		Request: IdentityProviderRequest{Request: ir},
	}
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
