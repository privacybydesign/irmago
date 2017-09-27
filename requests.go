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

// SessionRequest contains the context and nonce for an IRMA session.
type SessionRequest struct {
	Context *big.Int `json:"nonce"`
	Nonce   *big.Int `json:"context"`
	choice  *DisclosureChoice
}

// DisclosureChoice returns the attributes to be disclosed in this session.
func (sr *SessionRequest) DisclosureChoice() *DisclosureChoice {
	return sr.choice
}

// SetDisclosureChoice sets the attributes to be disclosed in this session.
func (sr *SessionRequest) SetDisclosureChoice(choice *DisclosureChoice) {
	sr.choice = choice
}

// A DisclosureRequest is a request to disclose certain attributes.
type DisclosureRequest struct {
	SessionRequest
	Content AttributeDisjunctionList `json:"content"`
}

// A SignatureRequest is a a request to sign a message with certain attributes.
type SignatureRequest struct {
	DisclosureRequest
	Message     string `json:"message"`
	MessageType string `json:"messageType"`
}

// An IssuanceRequest is a request to issue certain credentials,
// optionally also asking for certain attributes to be simultaneously disclosed.
type IssuanceRequest struct {
	SessionRequest
	Credentials []*CredentialRequest     `json:"credentials"`
	Disclose    AttributeDisjunctionList `json:"disclose"`

	state *issuanceState
}

// A CredentialRequest contains the attributes and metadata of a credential
// that will be issued in an IssuanceRequest.
type CredentialRequest struct {
	Validity   *Timestamp                `json:"validity"`
	KeyCounter int                       `json:"keyCounter"`
	Credential *CredentialTypeIdentifier `json:"credential"`
	Attributes map[string]string         `json:"attributes"`
}

// ServerJwt contains standard JWT fields.
type ServerJwt struct {
	Type       string    `json:"sub"`
	ServerName string    `json:"iss"`
	IssuedAt   Timestamp `json:"iat"`
}

// A ServiceProviderRequest contains a disclosure request.
type ServiceProviderRequest struct {
	Request *DisclosureRequest `json:"request"`
}

// A SignatureRequestorRequest contains a signing request.
type SignatureRequestorRequest struct {
	Request *SignatureRequest `json:"request"`
}

// An IdentityProviderRequest contains an issuance request.
type IdentityProviderRequest struct {
	Request *IssuanceRequest `json:"request"`
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

// Timestamp is a time.Time that marshals to Unix timestamps.
type Timestamp time.Time

type issuanceState struct {
	nonce2   *big.Int
	builders []*gabi.CredentialBuilder
}

// AttributeList returns the list of attributes from this credential request.
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

	return NewAttributeListFromInts(attrs)
}

func newIssuanceState() (*issuanceState, error) {
	nonce2, err := gabi.RandomBigInt(gabi.DefaultSystemParameters[4096].Lstatzk)
	if err != nil {
		return nil, err
	}
	return &issuanceState{
		nonce2:   nonce2,
		builders: []*gabi.CredentialBuilder{},
	}, nil
}

// Distributed indicates if a keyshare is involved in this session.
func (ir *IssuanceRequest) Distributed() bool {
	for _, manager := range ir.SchemeManagers() {
		if MetaStore.SchemeManagers[manager].Distributed() {
			return true
		}
	}
	return false
}

// SchemeManagers returns a list of all scheme managers involved in this session.
func (ir *IssuanceRequest) SchemeManagers() []SchemeManagerIdentifier {
	list := []SchemeManagerIdentifier{}
	for _, cred := range ir.Credentials {
		list = append(list, cred.Credential.IssuerIdentifier().SchemeManagerIdentifier())
	}
	for _, disjunctions := range ir.Disclose {
		for _, attr := range disjunctions.Attributes {
			list = append(list, attr.CredentialTypeIdentifier().IssuerIdentifier().SchemeManagerIdentifier())
		}
	}
	return list
}

// DisjunctionList returns the attributes that must be disclosed in this issuance session.
func (ir *IssuanceRequest) DisjunctionList() AttributeDisjunctionList { return ir.Disclose }

// GetContext returns the context of this session.
func (ir *IssuanceRequest) GetContext() *big.Int { return ir.Context }

// SetContext sets the context of this session.
func (ir *IssuanceRequest) SetContext(context *big.Int) { ir.Context = context }

// GetNonce returns the nonce of this session.
func (ir *IssuanceRequest) GetNonce() *big.Int { return ir.Nonce }

// SetNonce sets the nonce of this session.
func (ir *IssuanceRequest) SetNonce(nonce *big.Int) { ir.Nonce = nonce }

// Distributed indicates if a keyshare is involved in this session.
func (dr *DisclosureRequest) Distributed() bool {
	for _, manager := range dr.SchemeManagers() {
		if MetaStore.SchemeManagers[manager].Distributed() {
			return true
		}
	}
	return false
}

// SchemeManagers returns a list of all scheme managers involved in this session.
func (dr *DisclosureRequest) SchemeManagers() []SchemeManagerIdentifier {
	list := []SchemeManagerIdentifier{}
	for _, disjunction := range dr.Content {
		for _, attr := range disjunction.Attributes {
			list = append(list, attr.CredentialTypeIdentifier().IssuerIdentifier().SchemeManagerIdentifier())
		}
	}
	return list
}

// DisjunctionList returns the attributes to be disclosed in this session.
func (dr *DisclosureRequest) DisjunctionList() AttributeDisjunctionList { return dr.Content }

// GetContext returns the context of this session.
func (dr *DisclosureRequest) GetContext() *big.Int { return dr.Context }

// SetContext sets the context of this session.
func (dr *DisclosureRequest) SetContext(context *big.Int) { dr.Context = context }

// GetNonce returns the nonce of this session.
func (dr *DisclosureRequest) GetNonce() *big.Int { return dr.Nonce }

// SetNonce sets the nonce of this session.
func (dr *DisclosureRequest) SetNonce(nonce *big.Int) { dr.Nonce = nonce }

// DisjunctionList returns the attributes with which the message must be signed.
func (sr *SignatureRequest) DisjunctionList() AttributeDisjunctionList { return sr.Content }

// GetContext returns the context of this session.
func (sr *SignatureRequest) GetContext() *big.Int { return sr.Context }

// SetContext sets the context of this session.
func (sr *SessionRequest) SetContext(context *big.Int) { sr.Context = context }

// SetNonce sets the nonce of this session.
func (sr *SessionRequest) SetNonce(nonce *big.Int) { sr.Nonce = nonce }

// GetNonce returns the nonce of this signature session
// (with the message already hashed into it).
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

// NewServiceProviderJwt returns a new ServiceProviderJwt.
func NewServiceProviderJwt(servername string, dr *DisclosureRequest) *ServiceProviderJwt {
	return &ServiceProviderJwt{
		ServerJwt: ServerJwt{
			ServerName: servername,
			IssuedAt:   Timestamp(time.Now()),
			Type:       "verification_request",
		},
		Request: ServiceProviderRequest{Request: dr},
	}
}

// NewSignatureRequestorJwt returns a new SignatureRequestorJwt.
func NewSignatureRequestorJwt(servername string, sr *SignatureRequest) *SignatureRequestorJwt {
	return &SignatureRequestorJwt{
		ServerJwt: ServerJwt{
			ServerName: servername,
			IssuedAt:   Timestamp(time.Now()),
			Type:       "signature_request",
		},
		Request: SignatureRequestorRequest{Request: sr},
	}
}

// NewIdentityProviderJwt returns a new IdentityProviderJwt.
func NewIdentityProviderJwt(servername string, ir *IssuanceRequest) *IdentityProviderJwt {
	return &IdentityProviderJwt{
		ServerJwt: ServerJwt{
			ServerName: servername,
			IssuedAt:   Timestamp(time.Now()),
			Type:       "issue_request",
		},
		Request: IdentityProviderRequest{Request: ir},
	}
}

// A RequestorJwt contains an IRMA session object.
type RequestorJwt interface {
	IrmaSession() Session
}

// IrmaSession returns an IRMA session object.
func (jwt *ServiceProviderJwt) IrmaSession() Session { return jwt.Request.Request }

// IrmaSession returns an IRMA session object.
func (jwt *SignatureRequestorJwt) IrmaSession() Session { return jwt.Request.Request }

// IrmaSession returns an IRMA session object.
func (jwt *IdentityProviderJwt) IrmaSession() Session { return jwt.Request.Request }
