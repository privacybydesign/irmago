package irma

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/irmago/internal/fs"
)

// BaseRequest contains the context and nonce for an IRMA session.
type BaseRequest struct {
	// Denotes session type, must be "disclosing", "signing" or "issuing"
	Type Action `json:"type"`
	// Message version. Current version is 2.
	Version int `json:"v"`

	// Chosen by the IRMA server during the session
	Context         *big.Int         `json:"context,omitempty"`
	Nonce           *big.Int         `json:"nonce,omitempty"`
	ProtocolVersion *ProtocolVersion `json:"protocolVersion,omitempty"`

	// cache for Identifiers() method
	ids *IrmaIdentifierSet
}

// An AttributeCon is only satisfied if all of its containing attribute requests are satisfied.
type AttributeCon []AttributeRequest

// An AttributeDisCon is satisfied if at least one of its containing AttributeCon is satisfied.
type AttributeDisCon []AttributeCon

// AttributeConDisCon is only satisfied if all of the containing AttributeDisCon are satisfied.
type AttributeConDisCon []AttributeDisCon

// A DisclosureRequest is a request to disclose certain attributes. Construct new instances using
// NewDisclosureRequest().
type DisclosureRequest struct {
	BaseRequest

	Disclose AttributeConDisCon       `json:"disclose"`
	Labels   map[int]TranslatedString `json:"labels"`
}

// A SignatureRequest is a a request to sign a message with certain attributes. Construct new
// instances using NewSignatureRequest().
type SignatureRequest struct {
	DisclosureRequest
	Message string `json:"message"`
}

// An IssuanceRequest is a request to issue certain credentials,
// optionally also asking for certain attributes to be simultaneously disclosed. Construct new
// instances using NewIssuanceRequest().
type IssuanceRequest struct {
	DisclosureRequest
	Credentials []*CredentialRequest `json:"credentials"`

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

// SessionRequest instances contain all information the irmaclient needs to perform an IRMA session.
type SessionRequest interface {
	Validator
	Base() *BaseRequest
	GetNonce(timestamp *atum.Timestamp) *big.Int
	Disclosure() *DisclosureRequest
	Identifiers() *IrmaIdentifierSet
	Action() Action
}

// Timestamp is a time.Time that marshals to Unix timestamps.
type Timestamp time.Time

// ServerJwt contains standard JWT fields.
type ServerJwt struct {
	Type       string    `json:"sub"`
	ServerName string    `json:"iss"`
	IssuedAt   Timestamp `json:"iat"`
}

// RequestorBaseRequest contains fields present in all RequestorRequest types
// with which the requestor configures an IRMA session.
type RequestorBaseRequest struct {
	ResultJwtValidity int    `json:"validity,omitempty"`    // Validity of session result JWT in seconds
	ClientTimeout     int    `json:"timeout,omitempty"`     // Wait this many seconds for the IRMA app to connect before the session times out
	CallbackUrl       string `json:"callbackUrl,omitempty"` // URL to post session result to
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

// A RequestorJwt contains an IRMA session object.
type RequestorJwt interface {
	Action() Action
	RequestorRequest() RequestorRequest
	SessionRequest() SessionRequest
	Requestor() string
	Valid() error
	Sign(jwt.SigningMethod, interface{}) (string, error)
}

// A DisclosureChoice contains the attributes chosen to be disclosed.
type DisclosureChoice struct {
	Attributes [][]*AttributeIdentifier
}

// An AttributeRequest asks for an instance of an attribute type, possibly requiring it to have
// a specified value, in a session request.
type AttributeRequest struct {
	Type  AttributeTypeIdentifier
	Value *string
}

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)

func (b *BaseRequest) GetContext() *big.Int {
	if b.Context == nil {
		return bigOne
	}
	return b.Context
}

func (b *BaseRequest) GetNonce(*atum.Timestamp) *big.Int {
	if b.Nonce == nil {
		return bigZero
	}
	return b.Nonce
}

// CredentialTypes returns an array of all credential types occuring in this conjunction.
func (c AttributeCon) CredentialTypes() []CredentialTypeIdentifier {
	var result []CredentialTypeIdentifier
	tmp := map[CredentialTypeIdentifier]struct{}{}
	for _, attr := range c {
		tmp[attr.Type.CredentialTypeIdentifier()] = struct{}{}
	}
	for cred := range tmp {
		result = append(result, cred)
	}
	return result
}

func (c *AttributeCon) MarshalJSON() ([]byte, error) {
	var vals bool
	m := map[AttributeTypeIdentifier]*string{}
	var l []AttributeTypeIdentifier

	for _, attr := range *c {
		m[attr.Type] = attr.Value
		if attr.Value == nil {
			l = append(l, attr.Type)
		} else {
			vals = true
		}
	}

	if vals {
		return json.Marshal(m)
	} else {
		return json.Marshal(l)
	}
}

func (c *AttributeCon) UnmarshalJSON(bts []byte) error {
	var err error

	var l []AttributeTypeIdentifier
	if err = json.Unmarshal(bts, &l); err == nil {
		for _, id := range l {
			*c = append(*c, AttributeRequest{Type: id})
		}
		return nil
	}

	m := map[AttributeTypeIdentifier]*string{}
	if err = json.Unmarshal(bts, &m); err == nil {
		for id, val := range m {
			*c = append(*c, AttributeRequest{Type: id, Value: val})
		}
		return nil
	}

	var s string
	if err = json.Unmarshal(bts, &s); err == nil {
		*c = append(*c, NewAttributeRequest(s))
		return nil
	}

	return errors.New("Failed to unmarshal attribute conjunction")
}

func (ar *AttributeRequest) Satisfy(attr AttributeTypeIdentifier, val *string) bool {
	return ar.Type == attr && (ar.Value == nil || (val != nil && *ar.Value == *val))
}

func (c AttributeCon) Satisfy(proofs gabi.ProofList, indices []*DisclosedAttributeIndex, conf *Configuration) ([]*DisclosedAttribute, error) {
	if len(indices) < len(c) {
		return nil, nil
	}
	attrs := make([]*DisclosedAttribute, 0, len(c))

	for j := range c {
		index := indices[j]
		attr, val, err := extractAttribute(proofs, index, conf)
		if err != nil {
			return nil, err
		}
		if !c[j].Satisfy(attr.Identifier, val) {
			return nil, nil
		}
		attrs = append(attrs, attr)
	}
	return attrs, nil
}

func (dc AttributeDisCon) Satisfy(proofs gabi.ProofList, indices []*DisclosedAttributeIndex, conf *Configuration) ([]*DisclosedAttribute, error) {
	for _, con := range dc {
		attrs, err := con.Satisfy(proofs, indices, conf)
		if len(attrs) > 0 || err != nil {
			return attrs, err
		}
	}
	return nil, nil
}

func (cdc AttributeConDisCon) Satisfy(disclosure *Disclosure, conf *Configuration) (bool, [][]*DisclosedAttribute, error) {
	if len(disclosure.Indices) < len(cdc) {
		return false, nil, nil
	}
	list := make([][]*DisclosedAttribute, len(cdc))
	complete := true

	for i, discon := range cdc {
		attrs, err := discon.Satisfy(disclosure.Proofs, disclosure.Indices[i], conf)
		if err != nil {
			return false, nil, err
		}
		if len(attrs) > 0 {
			list[i] = attrs
		} else {
			complete = false
			list[i] = nil
		}
	}

	return complete, list, nil
}

func (cdc AttributeConDisCon) Iterate(f func(attr *AttributeRequest) error) error {
	var err error
	for _, discon := range cdc {
		for _, con := range discon {
			for _, attr := range con {
				if err = f(&attr); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (dr *DisclosureRequest) AddSingle(attr AttributeTypeIdentifier, value *string, label TranslatedString) {
	dr.Disclose = append(dr.Disclose, AttributeDisCon{AttributeCon{{Type: attr, Value: value}}})
	dr.Labels[len(dr.Disclose)-1] = label
}

func NewDisclosureRequest(attrs ...AttributeTypeIdentifier) *DisclosureRequest {
	request := &DisclosureRequest{
		BaseRequest: BaseRequest{Type: ActionDisclosing, Version: 2},
		Labels:      map[int]TranslatedString{},
	}
	for _, attr := range attrs {
		request.AddSingle(attr, nil, nil)
	}
	return request
}

func NewSignatureRequest(message string, attrs ...AttributeTypeIdentifier) *SignatureRequest {
	dr := NewDisclosureRequest(attrs...)
	dr.Type = ActionSigning
	return &SignatureRequest{
		DisclosureRequest: *dr,
		Message:           message,
	}
}

func NewIssuanceRequest(creds []*CredentialRequest, attrs ...AttributeTypeIdentifier) *IssuanceRequest {
	dr := NewDisclosureRequest(attrs...)
	dr.Type = ActionIssuing
	return &IssuanceRequest{
		DisclosureRequest: *dr,
		Credentials:       creds,
	}
}

func (dr *DisclosureRequest) Disclosure() *DisclosureRequest {
	return dr
}

func (dr *DisclosureRequest) Identifiers() *IrmaIdentifierSet {
	if dr.ids == nil {
		dr.ids = &IrmaIdentifierSet{
			SchemeManagers:  map[SchemeManagerIdentifier]struct{}{},
			Issuers:         map[IssuerIdentifier]struct{}{},
			CredentialTypes: map[CredentialTypeIdentifier]struct{}{},
			PublicKeys:      map[IssuerIdentifier][]int{},
		}

		_ = dr.Disclose.Iterate(func(a *AttributeRequest) error {
			attr := a.Type
			dr.ids.SchemeManagers[attr.CredentialTypeIdentifier().IssuerIdentifier().SchemeManagerIdentifier()] = struct{}{}
			dr.ids.Issuers[attr.CredentialTypeIdentifier().IssuerIdentifier()] = struct{}{}
			dr.ids.CredentialTypes[attr.CredentialTypeIdentifier()] = struct{}{}
			return nil
		})
	}
	return dr.ids
}

func (dr *DisclosureRequest) Base() *BaseRequest {
	return &dr.BaseRequest
}

func (dr *DisclosureRequest) Action() Action { return ActionDisclosing }

func (dr *DisclosureRequest) Validate() error {
	if dr.Type != ActionDisclosing {
		return errors.New("Not a disclosure request")
	}
	if len(dr.Disclose) == 0 {
		return errors.New("Disclosure request had no attributes")
	}
	for _, discon := range dr.Disclose {
		if len(discon) == 0 {
			return errors.New("Empty disjunction")
		}
	}
	return nil
}

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
	if ir.ids == nil {
		ir.ids = &IrmaIdentifierSet{
			SchemeManagers:  map[SchemeManagerIdentifier]struct{}{},
			Issuers:         map[IssuerIdentifier]struct{}{},
			CredentialTypes: map[CredentialTypeIdentifier]struct{}{},
			PublicKeys:      map[IssuerIdentifier][]int{},
		}

		for _, credreq := range ir.Credentials {
			issuer := credreq.CredentialTypeID.IssuerIdentifier()
			ir.ids.SchemeManagers[issuer.SchemeManagerIdentifier()] = struct{}{}
			ir.ids.Issuers[issuer] = struct{}{}
			ir.ids.CredentialTypes[credreq.CredentialTypeID] = struct{}{}
			if ir.ids.PublicKeys[issuer] == nil {
				ir.ids.PublicKeys[issuer] = []int{}
			}
			ir.ids.PublicKeys[issuer] = append(ir.ids.PublicKeys[issuer], credreq.KeyCounter)
		}

		ir.ids.join(ir.DisclosureRequest.Identifiers())
	}
	return ir.ids
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

func (ir *IssuanceRequest) Action() Action { return ActionIssuing }

func (ir *IssuanceRequest) Validate() error {
	if ir.Type != ActionIssuing {
		return errors.New("Not an issuance request")
	}
	if len(ir.Credentials) == 0 {
		return errors.New("Empty issuance request")
	}
	for _, cred := range ir.Credentials {
		if cred.Validity.Floor().Before(Timestamp(time.Now())) {
			return errors.New("Expired credential request")
		}
	}
	return nil
}

// GetNonce returns the nonce of this signature session
// (with the message already hashed into it).
func (sr *SignatureRequest) GetNonce(timestamp *atum.Timestamp) *big.Int {
	return ASN1ConvertSignatureNonce(sr.Message, sr.BaseRequest.GetNonce(nil), timestamp)
}

func (sr *SignatureRequest) SignatureFromMessage(message interface{}, timestamp *atum.Timestamp) (*SignedMessage, error) {
	signature, ok := message.(*Disclosure)

	if !ok {
		return nil, errors.Errorf("Type assertion failed")
	}

	nonce := sr.Nonce
	if nonce == nil {
		nonce = bigZero
	}
	return &SignedMessage{
		Signature: signature.Proofs,
		Indices:   signature.Indices,
		Nonce:     nonce,
		Context:   sr.GetContext(),
		Message:   sr.Message,
		Timestamp: timestamp,
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
	if len(sr.Disclose) == 0 {
		return errors.New("Signature request had no attributes")
	}
	for _, discon := range sr.Disclose {
		if len(discon) == 0 {
			return errors.New("Empty disjunction")
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

func (t *Timestamp) Floor() Timestamp {
	return Timestamp(time.Unix((time.Time(*t).Unix()/ExpiryFactor)*ExpiryFactor, 0))
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

func (jwt *ServerJwt) Requestor() string { return jwt.ServerName }

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

// NewAttributeRequest requests the specified attribute.
func NewAttributeRequest(attr string) AttributeRequest {
	return AttributeRequest{Type: NewAttributeTypeIdentifier(attr)}
}
