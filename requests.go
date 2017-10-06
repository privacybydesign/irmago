package irmago

import (
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"time"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

// SessionRequest contains the context and nonce for an IRMA session.
type SessionRequest struct {
	Context     *big.Int `json:"context"`
	Nonce       *big.Int `json:"nonce"`
	Candidates  [][]*AttributeIdentifier
	choice      *DisclosureChoice
	identifiers *IrmaIdentifierSet
}

func (sr *SessionRequest) SetCandidates(candidates [][]*AttributeIdentifier) {
	sr.Candidates = candidates
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
	Credentials        []*CredentialRequest     `json:"credentials"`
	Disclose           AttributeDisjunctionList `json:"disclose"`
	CredentialInfoList CredentialInfoList       `json:",omitempty"`

	state *issuanceState
}

// A CredentialRequest contains the attributes and metadata of a credential
// that will be issued in an IssuanceRequest.
type CredentialRequest struct {
	Validity         *Timestamp                `json:"validity"`
	KeyCounter       int                       `json:"keyCounter"`
	CredentialTypeID *CredentialTypeIdentifier `json:"credential"`
	Attributes       map[string]string         `json:"attributes"`
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

// IrmaSession is an IRMA session.
type IrmaSession interface {
	GetNonce() *big.Int
	SetNonce(*big.Int)
	GetContext() *big.Int
	SetContext(*big.Int)
	ToDisclose() AttributeDisjunctionList
	DisclosureChoice() *DisclosureChoice
	SetDisclosureChoice(choice *DisclosureChoice)
	SetCandidates(candidates [][]*AttributeIdentifier)
	Identifiers() *IrmaIdentifierSet
}

// Timestamp is a time.Time that marshals to Unix timestamps.
type Timestamp time.Time

type issuanceState struct {
	nonce2   *big.Int
	builders []*gabi.CredentialBuilder
}

func (cr *CredentialRequest) Info(store *ConfigurationStore) (*CredentialInfo, error) {
	list, err := cr.AttributeList(store)
	if err != nil {
		return nil, err
	}
	return NewCredentialInfo(list.Ints, store), nil
}

// AttributeList returns the list of attributes from this credential request.
func (cr *CredentialRequest) AttributeList(store *ConfigurationStore) (*AttributeList, error) {
	meta := NewMetadataAttribute()
	meta.setKeyCounter(cr.KeyCounter)
	meta.setCredentialTypeIdentifier(cr.CredentialTypeID.String())
	meta.setSigningDate()
	err := meta.setExpiryDate(cr.Validity)
	if err != nil {
		return nil, err
	}

	attrs := make([]*big.Int, len(cr.Attributes)+1, len(cr.Attributes)+1)
	credtype := store.CredentialTypes[*cr.CredentialTypeID]
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

	return NewAttributeListFromInts(attrs, store), nil
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

func (dr *IssuanceRequest) Identifiers() *IrmaIdentifierSet {
	if dr.identifiers == nil {
		dr.identifiers = &IrmaIdentifierSet{
			SchemeManagers:  map[SchemeManagerIdentifier]struct{}{},
			Issuers:         map[IssuerIdentifier]struct{}{},
			CredentialTypes: map[CredentialTypeIdentifier]struct{}{},
			PublicKeys:      map[IssuerIdentifier][]int{},
		}

		for _, credreq := range dr.Credentials {
			issuer := credreq.CredentialTypeID.IssuerIdentifier()
			dr.identifiers.SchemeManagers[issuer.SchemeManagerIdentifier()] = struct{}{}
			dr.identifiers.Issuers[issuer] = struct{}{}
			dr.identifiers.CredentialTypes[*credreq.CredentialTypeID] = struct{}{}
			if dr.identifiers.PublicKeys[issuer] == nil {
				dr.identifiers.PublicKeys[issuer] = []int{}
			}
			dr.identifiers.PublicKeys[issuer] = append(dr.identifiers.PublicKeys[issuer], credreq.KeyCounter)
		}

		for _, disjunction := range dr.Disclose {
			for _, attr := range disjunction.Attributes {
				dr.identifiers.SchemeManagers[attr.CredentialTypeIdentifier().IssuerIdentifier().SchemeManagerIdentifier()] = struct{}{}
				dr.identifiers.Issuers[attr.CredentialTypeIdentifier().IssuerIdentifier()] = struct{}{}
				dr.identifiers.CredentialTypes[attr.CredentialTypeIdentifier()] = struct{}{}
			}
		}
	}
	return dr.identifiers
}

// ToDisclose returns the attributes that must be disclosed in this issuance session.
func (ir *IssuanceRequest) ToDisclose() AttributeDisjunctionList { return ir.Disclose }

// GetContext returns the context of this session.
func (ir *IssuanceRequest) GetContext() *big.Int { return ir.Context }

// SetContext sets the context of this session.
func (ir *IssuanceRequest) SetContext(context *big.Int) { ir.Context = context }

// GetNonce returns the nonce of this session.
func (ir *IssuanceRequest) GetNonce() *big.Int { return ir.Nonce }

// SetNonce sets the nonce of this session.
func (ir *IssuanceRequest) SetNonce(nonce *big.Int) { ir.Nonce = nonce }

func (dr *DisclosureRequest) Identifiers() *IrmaIdentifierSet {
	if dr.identifiers == nil {
		dr.identifiers = &IrmaIdentifierSet{
			SchemeManagers:  map[SchemeManagerIdentifier]struct{}{},
			Issuers:         map[IssuerIdentifier]struct{}{},
			CredentialTypes: map[CredentialTypeIdentifier]struct{}{},
			PublicKeys:      map[IssuerIdentifier][]int{},
		}
		for _, disjunction := range dr.Content {
			for _, attr := range disjunction.Attributes {
				dr.identifiers.SchemeManagers[attr.CredentialTypeIdentifier().IssuerIdentifier().SchemeManagerIdentifier()] = struct{}{}
				dr.identifiers.Issuers[attr.CredentialTypeIdentifier().IssuerIdentifier()] = struct{}{}
				dr.identifiers.CredentialTypes[attr.CredentialTypeIdentifier()] = struct{}{}
			}
		}
	}
	return dr.identifiers
}

// ToDisclose returns the attributes to be disclosed in this session.
func (dr *DisclosureRequest) ToDisclose() AttributeDisjunctionList { return dr.Content }

// GetContext returns the context of this session.
func (dr *DisclosureRequest) GetContext() *big.Int { return dr.Context }

// SetContext sets the context of this session.
func (dr *DisclosureRequest) SetContext(context *big.Int) { dr.Context = context }

// GetNonce returns the nonce of this session.
func (dr *DisclosureRequest) GetNonce() *big.Int { return dr.Nonce }

// SetNonce sets the nonce of this session.
func (dr *DisclosureRequest) SetNonce(nonce *big.Int) { dr.Nonce = nonce }

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
	IrmaSession() IrmaSession
}

// IrmaSession returns an IRMA session object.
func (jwt *ServiceProviderJwt) IrmaSession() IrmaSession { return jwt.Request.Request }

// IrmaSession returns an IRMA session object.
func (jwt *SignatureRequestorJwt) IrmaSession() IrmaSession { return jwt.Request.Request }

// IrmaSession returns an IRMA session object.
func (jwt *IdentityProviderJwt) IrmaSession() IrmaSession { return jwt.Request.Request }
