package protocol

import (
	"time"

	"github.com/credentials/irmago"
)

type ServerJwt struct {
	Type       string           `json:"sub"`
	ServerName string           `json:"iss"`
	IssuedAt   irmago.Timestamp `json:"iat"`
}

type ServiceProviderRequest struct {
	Request *irmago.DisclosureRequest `json:"request"`
}

type SignatureRequestorRequest struct {
	Request *irmago.SignatureRequest `json:"request"`
}

type IdentityProviderRequest struct {
	Request *irmago.IssuanceRequest `json:"request"`
}

type ServiceProviderJwt struct {
	ServerJwt
	Request ServiceProviderRequest `json:"sprequest"`
}

type SignatureRequestorJwt struct {
	ServerJwt
	Request SignatureRequestorRequest `json:"absrequest"`
}

type IdentityProviderJwt struct {
	ServerJwt
	Request IdentityProviderRequest `json:"iprequest"`
}

func NewServiceProviderJwt(servername string, dr *irmago.DisclosureRequest) *ServiceProviderJwt {
	return &ServiceProviderJwt{
		ServerJwt: ServerJwt{
			ServerName: servername,
			IssuedAt:   irmago.Timestamp(time.Now()),
			Type:       "verification_request",
		},
		Request: ServiceProviderRequest{Request: dr},
	}
}

func NewSignatureRequestorJwt(servername string, sr *irmago.SignatureRequest) *SignatureRequestorJwt {
	return &SignatureRequestorJwt{
		ServerJwt: ServerJwt{
			ServerName: servername,
			IssuedAt:   irmago.Timestamp(time.Now()),
			Type:       "signature_request",
		},
		Request: SignatureRequestorRequest{Request: sr},
	}
}

func NewIdentityProviderJwt(servername string, ir *irmago.IssuanceRequest) *IdentityProviderJwt {
	return &IdentityProviderJwt{
		ServerJwt: ServerJwt{
			ServerName: servername,
			IssuedAt:   irmago.Timestamp(time.Now()),
			Type:       "issue_request",
		},
		Request: IdentityProviderRequest{Request: ir},
	}
}

type RequestorJwt interface {
	IrmaSession() irmago.Session
}

func (jwt *ServiceProviderJwt) IrmaSession() irmago.Session    { return jwt.Request.Request }
func (jwt *SignatureRequestorJwt) IrmaSession() irmago.Session { return jwt.Request.Request }
func (jwt *IdentityProviderJwt) IrmaSession() irmago.Session   { return jwt.Request.Request }
