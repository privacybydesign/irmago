package irma

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/irmago/internal/fs"
)

// BaseRequest contains the context and nonce for an IRMA session.
type BaseRequest struct {
	Context *big.Int `json:"context,omitempty"`
	Nonce   *big.Int `json:"nonce,omitempty"`
	Type    Action   `json:"type"`

	Candidates [][]*AttributeIdentifier `json:"-"`
	Choice     *DisclosureChoice        `json:"-"`
	Ids        *IrmaIdentifierSet       `json:"-"`

	Version *ProtocolVersion `json:"protocolVersion,omitempty"`
}

func (sr *BaseRequest) SetCandidates(candidates [][]*AttributeIdentifier) {
	sr.Candidates = candidates
}

// DisclosureChoice returns the attributes to be disclosed in this session.
func (sr *BaseRequest) DisclosureChoice() *DisclosureChoice {
	return sr.Choice
}

// SetDisclosureChoice sets the attributes to be disclosed in this session.
func (sr *BaseRequest) SetDisclosureChoice(choice *DisclosureChoice) {
	sr.Choice = choice
}

// ...
func (sr *BaseRequest) SetVersion(v *ProtocolVersion) {
	sr.Version = v
}

// ...
func (sr *BaseRequest) GetVersion() *ProtocolVersion {
	return sr.Version
}

// A DisclosureRequest is a request to disclose certain attributes.
type DisclosureRequest struct {
	BaseRequest
	Content AttributeDisjunctionList `json:"content"`
}

// A SignatureRequest is a a request to sign a message with certain attributes.
type SignatureRequest struct {
	DisclosureRequest
	Message string `json:"message"`

	// Session state
	Timestamp *atum.Timestamp `json:"-"`
}

// An IssuanceRequest is a request to issue certain credentials,
// optionally also asking for certain attributes to be simultaneously disclosed.
type IssuanceRequest struct {
	BaseRequest
	Credentials []*CredentialRequest     `json:"credentials"`
	Disclose    AttributeDisjunctionList `json:"disclose"`

	// Derived data
	CredentialInfoList        CredentialInfoList `json:",omitempty"`
	RemovalCredentialInfoList CredentialInfoList `json:",omitempty"`
}

// A CredentialRequest contains the attributes and metadata of a credential
// that will be issued in an IssuanceRequest.
type CredentialRequest struct {
	Validity         *Timestamp               `json:"validity,omitempty"`
	KeyCounter       int                      `json:"keyCounter,omitempty"`
	CredentialTypeID CredentialTypeIdentifier `json:"credential"`
	Attributes       map[string]string        `json:"attributes"`
}

// ServerJwt contains standard JWT fields.
type ServerJwt struct {
	Type       string    `json:"sub"`
	ServerName string    `json:"iss"`
	IssuedAt   Timestamp `json:"iat"`
}

// RequestorBaseRequest contains fields present in all RequestorRequest types
// with which the requestor configures an IRMA session.
type RequestorBaseRequest struct {
	ResultJwtValidity int    `json:"validity"`    // Validity of session result JWT in seconds
	ClientTimeout     int    `json:"timeout"`     // Wait this many seconds for the IRMA app to connect before the session times out
	CallbackUrl       string `json:"callbackUrl"` // URL to post session result to
}

// RequestorRequest is the message with which requestors start an IRMA session. It contains a
// SessionRequest instance for the irmaclient along with extra fields in a RequestorBaseRequest.
type RequestorRequest interface {
	Validator
	SessionRequest() SessionRequest
	Base() RequestorBaseRequest
}

// A ServiceProviderRequest contains a disclosure request.
type ServiceProviderRequest struct {
	RequestorBaseRequest
	Request *DisclosureRequest `json:"request"`
}

// A SignatureRequestorRequest contains a signing request.
type SignatureRequestorRequest struct {
	RequestorBaseRequest
	Request *SignatureRequest `json:"request"`
}

// An IdentityProviderRequest contains an issuance request.
type IdentityProviderRequest struct {
	RequestorBaseRequest
	Request *IssuanceRequest `json:"request"`
}

// ServiceProviderJwt is a requestor JWT for a disclosure session.
type ServiceProviderJwt struct {
	ServerJwt
	Request *ServiceProviderRequest `json:"sprequest"`
}

// SignatureRequestorJwt is a requestor JWT for a signing session.
type SignatureRequestorJwt struct {
	ServerJwt
	Request *SignatureRequestorRequest `json:"absrequest"`
}

// IdentityProviderJwt is a requestor JWT for issuance session.
type IdentityProviderJwt struct {
	ServerJwt
	Request *IdentityProviderRequest `json:"iprequest"`
}

func (r *ServiceProviderRequest) Validate() error {
	if r.Request == nil {
		return errors.New("Not a ServiceProviderRequest")
	}
	return r.Request.Validate()
}

func (r *SignatureRequestorRequest) Validate() error {
	if r.Request == nil {
		return errors.New("Not a SignatureRequestorRequest")
	}
	return r.Request.Validate()
}

func (r *IdentityProviderRequest) Validate() error {
	if r.Request == nil {
		return errors.New("Not a IdentityProviderRequest")
	}
	return r.Request.Validate()
}

func (r *ServiceProviderRequest) SessionRequest() SessionRequest {
	return r.Request
}

func (r *SignatureRequestorRequest) SessionRequest() SessionRequest {
	return r.Request
}

func (r *IdentityProviderRequest) SessionRequest() SessionRequest {
	return r.Request
}

func (r *ServiceProviderRequest) Base() RequestorBaseRequest {
	return r.RequestorBaseRequest
}

func (r *SignatureRequestorRequest) Base() RequestorBaseRequest {
	return r.RequestorBaseRequest
}

func (r *IdentityProviderRequest) Base() RequestorBaseRequest {
	return r.RequestorBaseRequest
}

// SessionRequest instances contain all information the irmaclient needs to perform an IRMA session.
type SessionRequest interface {
	Validator
	GetNonce() *big.Int
	SetNonce(*big.Int)
	GetContext() *big.Int
	SetContext(*big.Int)
	GetVersion() *ProtocolVersion
	SetVersion(*ProtocolVersion)
	ToDisclose() AttributeDisjunctionList
	DisclosureChoice() *DisclosureChoice
	SetDisclosureChoice(choice *DisclosureChoice)
	SetCandidates(candidates [][]*AttributeIdentifier)
	Identifiers() *IrmaIdentifierSet
	Action() Action
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

// Validate checks that this credential request is consistent with the specified Configuration:
// the credential type is known, all required attributes are present and no unknown attributes
// are given.
func (cr *CredentialRequest) Validate(conf *Configuration) error {
	credtype := conf.CredentialTypes[cr.CredentialTypeID]
	if credtype == nil {
		return errors.New("Credential request of unknown credential type")
	}

	// Check that there are no attributes in the credential request that aren't
	// in the credential descriptor.
	for crName := range cr.Attributes {
		found := false
		for _, ad := range credtype.AttributeTypes {
			if ad.ID == crName {
				found = true
				break
			}
		}
		if !found {
			return errors.New("Credential request contaiins unknown attribute")
		}
	}

	for _, attrtype := range credtype.AttributeTypes {
		if _, present := cr.Attributes[attrtype.ID]; !present && attrtype.Optional != "true" {
			return errors.New("Required attribute not present in credential request")
		}
	}

	return nil
}

// AttributeList returns the list of attributes from this credential request.
func (cr *CredentialRequest) AttributeList(conf *Configuration, metadataVersion byte) (*AttributeList, error) {
	if err := cr.Validate(conf); err != nil {
		return nil, err
	}

	// Compute metadata attribute
	meta := NewMetadataAttribute(metadataVersion)
	meta.setKeyCounter(cr.KeyCounter)
	meta.setCredentialTypeIdentifier(cr.CredentialTypeID.String())
	meta.setSigningDate()
	if err := meta.setExpiryDate(cr.Validity); err != nil {
		return nil, err
	}

	// Compute other attributes
	credtype := conf.CredentialTypes[cr.CredentialTypeID]
	attrs := make([]*big.Int, len(credtype.AttributeTypes)+1)
	attrs[0] = meta.Int
	for i, attrtype := range credtype.AttributeTypes {
		attrs[i+1] = new(big.Int)
		if str, present := cr.Attributes[attrtype.ID]; present {
			// Set attribute to str << 1 + 1
			attrs[i+1].SetBytes([]byte(str))
			if meta.Version() >= 0x03 {
				attrs[i+1].Lsh(attrs[i+1], 1)             // attr <<= 1
				attrs[i+1].Add(attrs[i+1], big.NewInt(1)) // attr += 1
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
			ir.Ids.CredentialTypes[credreq.CredentialTypeID] = struct{}{}
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

func (ir *IssuanceRequest) Action() Action { return ActionIssuing }

func (ir *IssuanceRequest) Validate() error {
	if ir.Type != ActionIssuing {
		return errors.New("Not an issuance request")
	}
	if len(ir.Credentials) == 0 {
		return errors.New("Empty issuance request")
	}
	return nil
}

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

func (dr *DisclosureRequest) Action() Action { return ActionDisclosing }

func (dr *DisclosureRequest) Validate() error {
	if dr.Type != ActionDisclosing {
		return errors.New("Not a disclosure request")
	}
	if len(dr.Content) == 0 {
		return errors.New("Disclosure request had no attributes")
	}
	for _, disjunction := range dr.Content {
		if len(disjunction.Attributes) == 0 {
			return errors.New("Disclosure request had an empty disjunction")
		}
	}
	return nil
}

// GetNonce returns the nonce of this signature session
// (with the message already hashed into it).
func (sr *SignatureRequest) GetNonce() *big.Int {
	return ASN1ConvertSignatureNonce(sr.Message, sr.Nonce, sr.Timestamp)
}

func (sr *SignatureRequest) SignatureFromMessage(message interface{}) (*SignedMessage, error) {
	signature, ok := message.(*Disclosure)

	if !ok {
		return nil, errors.Errorf("Type assertion failed")
	}

	return &SignedMessage{
		Signature: signature.Proofs,
		Indices:   signature.Indices,
		Nonce:     sr.Nonce,
		Context:   sr.Context,
		Message:   sr.Message,
		Timestamp: sr.Timestamp,
	}, nil
}

func (sr *SignatureRequest) Action() Action { return ActionSigning }

func (sr *SignatureRequest) Validate() error {
	if sr.Type != ActionSigning {
		return errors.New("Not a signature request")
	}
	if sr.Message == "" {
		return errors.New("Signature request had empty message")
	}
	if len(sr.Content) == 0 {
		return errors.New("Disclosure request had no attributes")
	}
	for _, disjunction := range sr.Content {
		if len(disjunction.Attributes) == 0 {
			return errors.New("Disclosure request had an empty disjunction")
		}
	}
	return nil
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
		Request: &ServiceProviderRequest{
			RequestorBaseRequest: RequestorBaseRequest{ResultJwtValidity: 120},
			Request:              dr,
		},
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
		Request: &SignatureRequestorRequest{
			RequestorBaseRequest: RequestorBaseRequest{ResultJwtValidity: 120},
			Request:              sr,
		},
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
		Request: &IdentityProviderRequest{
			RequestorBaseRequest: RequestorBaseRequest{ResultJwtValidity: 120},
			Request:              ir,
		},
	}
}

// A RequestorJwt contains an IRMA session object.
type RequestorJwt interface {
	Action() Action
	RequestorRequest() RequestorRequest
	SessionRequest() SessionRequest
	Requestor() string
	Valid() error
	Sign(jwt.SigningMethod, interface{}) (string, error)
}

func (jwt *ServerJwt) Requestor() string { return jwt.ServerName }

// SessionRequest returns an IRMA session object.
func (claims *ServiceProviderJwt) SessionRequest() SessionRequest { return claims.Request.Request }

// SessionRequest returns an IRMA session object.
func (claims *SignatureRequestorJwt) SessionRequest() SessionRequest { return claims.Request.Request }

// SessionRequest returns an IRMA session object.
func (claims *IdentityProviderJwt) SessionRequest() SessionRequest { return claims.Request.Request }

func (claims *ServiceProviderJwt) Sign(method jwt.SigningMethod, key interface{}) (string, error) {
	return jwt.NewWithClaims(method, claims).SignedString(key)
}

func (claims *SignatureRequestorJwt) Sign(method jwt.SigningMethod, key interface{}) (string, error) {
	return jwt.NewWithClaims(method, claims).SignedString(key)
}

func (claims *IdentityProviderJwt) Sign(method jwt.SigningMethod, key interface{}) (string, error) {
	return jwt.NewWithClaims(method, claims).SignedString(key)
}

func (claims *ServiceProviderJwt) RequestorRequest() RequestorRequest { return claims.Request }

func (claims *SignatureRequestorJwt) RequestorRequest() RequestorRequest { return claims.Request }

func (claims *IdentityProviderJwt) RequestorRequest() RequestorRequest { return claims.Request }

func (claims *ServiceProviderJwt) Valid() error {
	if claims.Type != "verification_request" {

		return errors.New("Verification jwt has invalid subject")
	}
	if time.Time(claims.IssuedAt).After(time.Now()) {
		return errors.New("Verification jwt not yet valid")
	}
	return nil
}

func (claims *SignatureRequestorJwt) Valid() error {
	if claims.Type != "signature_request" {
		return errors.New("Signature jwt has invalid subject")
	}
	if time.Time(claims.IssuedAt).After(time.Now()) {
		return errors.New("Signature jwt not yet valid")
	}
	return nil
}

func (claims *IdentityProviderJwt) Valid() error {
	if claims.Type != "issue_request" {
		return errors.New("Issuance jwt has invalid subject")
	}
	if time.Time(claims.IssuedAt).After(time.Now()) {
		return errors.New("Issuance jwt not yet valid")
	}
	return nil
}

func (claims *ServiceProviderJwt) Action() Action { return ActionDisclosing }

func (claims *SignatureRequestorJwt) Action() Action { return ActionSigning }

func (claims *IdentityProviderJwt) Action() Action { return ActionIssuing }

func SignSessionRequest(request SessionRequest, alg jwt.SigningMethod, key interface{}, name string) (string, error) {
	var jwtcontents RequestorJwt
	switch r := request.(type) {
	case *IssuanceRequest:
		jwtcontents = NewIdentityProviderJwt(name, r)
	case *DisclosureRequest:
		jwtcontents = NewServiceProviderJwt(name, r)
	case *SignatureRequest:
		jwtcontents = NewSignatureRequestorJwt(name, r)
	}
	return jwtcontents.Sign(alg, key)
}

func SignRequestorRequest(request RequestorRequest, alg jwt.SigningMethod, key interface{}, name string) (string, error) {
	var jwtcontents RequestorJwt
	switch r := request.(type) {
	case *IdentityProviderRequest:
		jwtcontents = NewIdentityProviderJwt(name, nil)
		jwtcontents.(*IdentityProviderJwt).Request = r
	case *ServiceProviderRequest:
		jwtcontents = NewServiceProviderJwt(name, nil)
		jwtcontents.(*ServiceProviderJwt).Request = r
	case *SignatureRequestorRequest:
		jwtcontents = NewSignatureRequestorJwt(name, nil)
		jwtcontents.(*SignatureRequestorJwt).Request = r
	}
	return jwtcontents.Sign(alg, key)
}
