package protocol

import (
	"time"

	"github.com/credentials/irmago"
)

// ServerJwt contains standard JWT fields.
type ServerJwt struct {
	Type       string           `json:"sub"`
	ServerName string           `json:"iss"`
	IssuedAt   irmago.Timestamp `json:"iat"`
}

// A ServiceProviderRequest contains a disclosure request.
type ServiceProviderRequest struct {
	Request *irmago.DisclosureRequest `json:"request"`
}

// A SignatureRequestorRequest contains a signing request.
type SignatureRequestorRequest struct {
	Request *irmago.SignatureRequest `json:"request"`
}

// An IdentityProviderRequest contains an issuance request.
type IdentityProviderRequest struct {
	Request *irmago.IssuanceRequest `json:"request"`
}

// ServiceProviderJwt is a requestor JWT for a disclosure session.
type ServiceProviderJwt struct {
	ServerJwt
	Request ServiceProviderRequest `json:"sprequest"`
}

// SignatureRequestorJwt is a requestor JWT for a signing session.
type SignatureRequestorJwt struct {
	ServerJwt
	Request SignatureRequestorRequest `json:"absrequest"`
}

// IdentityProviderJwt is a requestor JWT for issuance session.
type IdentityProviderJwt struct {
	ServerJwt
	Request IdentityProviderRequest `json:"iprequest"`
}

// NewServiceProviderJwt returns a new ServiceProviderJwt.
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

// NewSignatureRequestorJwt returns a new SignatureRequestorJwt.
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

// NewIdentityProviderJwt returns a new IdentityProviderJwt.
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

// A RequestorJwt contains an IRMA session object.
type RequestorJwt interface {
	IrmaSession() irmago.Session
}

// IrmaSession returns an IRMA session object.
func (jwt *ServiceProviderJwt) IrmaSession() irmago.Session { return jwt.Request.Request }

// IrmaSession returns an IRMA session object.
func (jwt *SignatureRequestorJwt) IrmaSession() irmago.Session { return jwt.Request.Request }

// IrmaSession returns an IRMA session object.
func (jwt *IdentityProviderJwt) IrmaSession() irmago.Session { return jwt.Request.Request }
