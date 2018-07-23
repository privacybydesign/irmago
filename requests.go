package irma

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"strconv"
	"time"

	"encoding/json"

	"github.com/bwesterb/go-atum"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago/internal/fs"
)

// SessionRequest contains the context and nonce for an IRMA session.
type SessionRequest struct {
	Context    *big.Int                 `json:"context"`
	Nonce      *big.Int                 `json:"nonce"`
	Candidates [][]*AttributeIdentifier `json:"-"`

	Choice *DisclosureChoice  `json:"-"`
	Ids    *IrmaIdentifierSet `json:"-"`

	version *ProtocolVersion
}

func (sr *SessionRequest) SetCandidates(candidates [][]*AttributeIdentifier) {
	sr.Candidates = candidates
}

// DisclosureChoice returns the attributes to be disclosed in this session.
func (sr *SessionRequest) DisclosureChoice() *DisclosureChoice {
	return sr.Choice
}

// SetDisclosureChoice sets the attributes to be disclosed in this session.
func (sr *SessionRequest) SetDisclosureChoice(choice *DisclosureChoice) {
	sr.Choice = choice
}

// ...
func (sr *SessionRequest) SetVersion(v *ProtocolVersion) {
	sr.version = v
}

// ...
func (sr *SessionRequest) GetVersion() *ProtocolVersion {
	return sr.version
}

// A DisclosureRequest is a request to disclose certain attributes.
type DisclosureRequest struct {
	SessionRequest
	Content AttributeDisjunctionList `json:"content"`
}

// A SignatureRequest is a a request to sign a message with certain attributes.
type SignatureRequest struct {
	DisclosureRequest
	Message   string          `json:"message"`
	Timestamp *atum.Timestamp `json:"-"`
}

// An IssuanceRequest is a request to issue certain credentials,
// optionally also asking for certain attributes to be simultaneously disclosed.
type IssuanceRequest struct {
	SessionRequest
	Credentials []*CredentialRequest     `json:"credentials"`
	Disclose    AttributeDisjunctionList `json:"disclose"`

	// Derived data
	CredentialInfoList        CredentialInfoList `json:",omitempty"`
	RemovalCredentialInfoList CredentialInfoList
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
	SetVersion(*ProtocolVersion)
	ToDisclose() AttributeDisjunctionList
	DisclosureChoice() *DisclosureChoice
	SetDisclosureChoice(choice *DisclosureChoice)
	SetCandidates(candidates [][]*AttributeIdentifier)
	Identifiers() *IrmaIdentifierSet
}

// Timestamp is a time.Time that marshals to Unix timestamps.
type Timestamp time.Time

func (cr *CredentialRequest) Info(conf *Configuration, metadataVersion byte) (*CredentialInfo, error) {
	list, err := cr.AttributeList(conf, metadataVersion)
	if err != nil {
		return nil, err
	}
	return NewCredentialInfo(list.Ints, conf), nil
}

// AttributeList returns the list of attributes from this credential request.
func (cr *CredentialRequest) AttributeList(conf *Configuration, metadataVersion byte) (*AttributeList, error) {
	meta := NewMetadataAttribute(metadataVersion)
	meta.setKeyCounter(cr.KeyCounter)
	meta.setCredentialTypeIdentifier(cr.CredentialTypeID.String())
	meta.setSigningDate()
	err := meta.setExpiryDate(cr.Validity)
	if err != nil {
		return nil, err
	}

	credtype := conf.CredentialTypes[*cr.CredentialTypeID]
	if credtype == nil {
		return nil, errors.New("Unknown credential type")
	}

	// Check that there are no attributes in the credential request that aren't
	// in the credential descriptor.
	for crName := range cr.Attributes {
		found := false
		for _, ad := range credtype.Attributes {
			if ad.ID == crName {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("Unknown CR attribute")
		}
	}

	attrs := make([]*big.Int, len(credtype.Attributes)+1)
	attrs[0] = meta.Int
	for i, attrtype := range credtype.Attributes {
		attrs[i+1] = new(big.Int)
		if str, present := cr.Attributes[attrtype.ID]; present {
			// Set attribute to str << 1 + 1
			attrs[i+1].SetBytes([]byte(str))
			if meta.Version() >= 0x03 {
				attrs[i+1].Lsh(attrs[i+1], 1)             // attr <<= 1
				attrs[i+1].Add(attrs[i+1], big.NewInt(1)) // attr += 1
			}
		} else {
			if attrtype.Optional != "true" {
				return nil, errors.New("Required attribute not provided")
			}
		}
	}

	return NewAttributeListFromInts(attrs, conf), nil
}

func (ir *IssuanceRequest) Identifiers() *IrmaIdentifierSet {
	if ir.Ids == nil {
		ir.Ids = &IrmaIdentifierSet{
			SchemeManagers:  map[SchemeManagerIdentifier]struct{}{},
			Issuers:         map[IssuerIdentifier]struct{}{},
			CredentialTypes: map[CredentialTypeIdentifier]struct{}{},
			PublicKeys:      map[IssuerIdentifier][]int{},
		}

		for _, credreq := range ir.Credentials {
			issuer := credreq.CredentialTypeID.IssuerIdentifier()
			ir.Ids.SchemeManagers[issuer.SchemeManagerIdentifier()] = struct{}{}
			ir.Ids.Issuers[issuer] = struct{}{}
			ir.Ids.CredentialTypes[*credreq.CredentialTypeID] = struct{}{}
			if ir.Ids.PublicKeys[issuer] == nil {
				ir.Ids.PublicKeys[issuer] = []int{}
			}
			ir.Ids.PublicKeys[issuer] = append(ir.Ids.PublicKeys[issuer], credreq.KeyCounter)
		}

		for _, disjunction := range ir.Disclose {
			for _, attr := range disjunction.Attributes {
				var cti CredentialTypeIdentifier
				if !attr.IsCredential() {
					cti = attr.CredentialTypeIdentifier()
				} else {
					cti = NewCredentialTypeIdentifier(attr.String())
				}
				ir.Ids.SchemeManagers[cti.IssuerIdentifier().SchemeManagerIdentifier()] = struct{}{}
				ir.Ids.Issuers[cti.IssuerIdentifier()] = struct{}{}
				ir.Ids.CredentialTypes[cti] = struct{}{}
			}
		}
	}
	return ir.Ids
}

// ToDisclose returns the attributes that must be disclosed in this issuance session.
func (ir *IssuanceRequest) ToDisclose() AttributeDisjunctionList {
	if ir.Disclose == nil {
		return AttributeDisjunctionList{}
	}

	return ir.Disclose
}

func (ir *IssuanceRequest) GetCredentialInfoList(conf *Configuration, version *ProtocolVersion) (CredentialInfoList, error) {
	if ir.CredentialInfoList == nil {
		for _, credreq := range ir.Credentials {
			info, err := credreq.Info(conf, GetMetadataVersion(version))
			if err != nil {
				return nil, err
			}
			ir.CredentialInfoList = append(ir.CredentialInfoList, info)
		}
	}
	return ir.CredentialInfoList, nil
}

// GetContext returns the context of this session.
func (ir *IssuanceRequest) GetContext() *big.Int { return ir.Context }

// SetContext sets the context of this session.
func (ir *IssuanceRequest) SetContext(context *big.Int) { ir.Context = context }

// GetNonce returns the nonce of this session.
func (ir *IssuanceRequest) GetNonce() *big.Int { return ir.Nonce }

// SetNonce sets the nonce of this session.
func (ir *IssuanceRequest) SetNonce(nonce *big.Int) { ir.Nonce = nonce }

func (dr *DisclosureRequest) Identifiers() *IrmaIdentifierSet {
	if dr.Ids == nil {
		dr.Ids = &IrmaIdentifierSet{
			SchemeManagers:  map[SchemeManagerIdentifier]struct{}{},
			Issuers:         map[IssuerIdentifier]struct{}{},
			CredentialTypes: map[CredentialTypeIdentifier]struct{}{},
			PublicKeys:      map[IssuerIdentifier][]int{},
		}
		for _, disjunction := range dr.Content {
			for _, attr := range disjunction.Attributes {
				dr.Ids.SchemeManagers[attr.CredentialTypeIdentifier().IssuerIdentifier().SchemeManagerIdentifier()] = struct{}{}
				dr.Ids.Issuers[attr.CredentialTypeIdentifier().IssuerIdentifier()] = struct{}{}
				dr.Ids.CredentialTypes[attr.CredentialTypeIdentifier()] = struct{}{}
			}
		}
	}
	return dr.Ids
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
	return ASN1ConvertSignatureNonce(sr.Message, sr.Nonce, sr.Timestamp)
}

// Convert fields in JSON string to BigInterger if they are string
// Supply fieldnames as a slice as second argument
func convertFieldsToBigInt(jsonString []byte, fieldNames []string) ([]byte, error) {
	var rawRequest map[string]interface{}

	err := json.Unmarshal(jsonString, &rawRequest)
	if err != nil {
		return nil, err
	}

	for _, fieldName := range fieldNames {
		field := new(big.Int)
		fieldString := fmt.Sprintf("%v", rawRequest[fieldName])
		field.SetString(fieldString, 10)
		rawRequest[fieldName] = field
	}

	return json.Marshal(rawRequest)
}

// Custom Unmarshalling to support both json with string and int fields for nonce and context
// i.e. {"nonce": "42", "context": "1337", ... } and {"nonce": 42, "context": 1337, ... }
func (sr *SignatureRequest) UnmarshalJSON(b []byte) error {
	type SignatureRequestTemp SignatureRequest // To avoid 'recursive unmarshalling'

	fixedRequest, err := convertFieldsToBigInt(b, []string{"nonce", "context"})
	if err != nil {
		return err
	}

	var result SignatureRequestTemp
	err = json.Unmarshal(fixedRequest, &result)
	if err != nil {
		return err
	}

	sr.DisclosureRequest = result.DisclosureRequest
	sr.Message = result.Message

	return err
}

func (sr *SignatureRequest) SignatureFromMessage(message interface{}) (*IrmaSignedMessage, error) {
	signature, ok := message.(gabi.ProofList)

	if !ok {
		return nil, errors.Errorf("Type assertion failed")
	}

	return &IrmaSignedMessage{
		Signature: signature,
		Nonce:     sr.Nonce,
		Context:   sr.Context,
		Message:   sr.Message,
		Timestamp: sr.Timestamp,
	}, nil
}

// Check if Timestamp is before other Timestamp. Used for checking expiry of attributes
func (t Timestamp) Before(u Timestamp) bool {
	return time.Time(t).Before(time.Time(u))
}

func (t Timestamp) After(u Timestamp) bool {
	return time.Time(t).After(time.Time(u))
}

// MarshalJSON marshals a timestamp.
func (t *Timestamp) MarshalJSON() ([]byte, error) {
	return []byte(t.String()), nil
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

// Timestamp implements Stringer.
func (t *Timestamp) String() string {
	return fmt.Sprint(time.Time(*t).Unix())
}

func readTimestamp(path string) (*Timestamp, bool, error) {
	exists, err := fs.PathExists(path)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}
	bts, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, true, errors.New("Could not read scheme manager timestamp")
	}
	ts, err := parseTimestamp(bts)
	return ts, true, err
}

func parseTimestamp(bts []byte) (*Timestamp, error) {
	// Remove final character \n if present
	if bts[len(bts)-1] == '\n' {
		bts = bts[:len(bts)-1]
	}
	// convert from byte slice to string; parse as int
	str, err := strconv.ParseInt(string(bts), 10, 64)
	if err != nil {
		return nil, err
	}
	ts := Timestamp(time.Unix(str, 0))
	return &ts, nil
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
	Requestor() string
}

func (jwt *ServerJwt) Requestor() string { return jwt.ServerName }

// IrmaSession returns an IRMA session object.
func (jwt *ServiceProviderJwt) IrmaSession() IrmaSession { return jwt.Request.Request }

// IrmaSession returns an IRMA session object.
func (jwt *SignatureRequestorJwt) IrmaSession() IrmaSession { return jwt.Request.Request }

// IrmaSession returns an IRMA session object.
func (jwt *IdentityProviderJwt) IrmaSession() IrmaSession { return jwt.Request.Request }
