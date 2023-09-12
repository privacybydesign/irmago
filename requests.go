package irma

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/revocation"
	"github.com/privacybydesign/irmago/internal/common"
)

const (
	LDContextDisclosureRequest      = "https://irma.app/ld/request/disclosure/v2"
	LDContextSignatureRequest       = "https://irma.app/ld/request/signature/v2"
	LDContextIssuanceRequest        = "https://irma.app/ld/request/issuance/v2"
	LDContextRevocationRequest      = "https://irma.app/ld/request/revocation/v1"
	LDContextFrontendOptionsRequest = "https://irma.app/ld/request/frontendoptions/v1"
	LDContextClientSessionRequest   = "https://irma.app/ld/request/client/v1"
	LDContextSessionOptions         = "https://irma.app/ld/options/v1"
	DefaultJwtValidity              = 120
)

// BaseRequest contains information used by all IRMA session types, such the context and nonce,
// and revocation information.
type BaseRequest struct {
	LDContext string `json:"@context,omitempty"`

	// Set by the IRMA server during the session
	Context         *big.Int         `json:"context,omitempty"`
	Nonce           *big.Int         `json:"nonce,omitempty"`
	ProtocolVersion *ProtocolVersion `json:"protocolVersion,omitempty"`

	// Revocation is set by the requestor to indicate that it requires nonrevocation proofs for the
	// specified credential types.
	Revocation NonRevocationParameters `json:"revocation,omitempty"`

	ids *IrmaIdentifierSet // cache for Identifiers() method

	legacy          bool   // Whether or not this was deserialized from a legacy (pre-condiscon) request
	Type            Action `json:"type,omitempty"` // Session type, only used in legacy code
	DevelopmentMode bool   `json:"devMode,omitempty"`

	ClientReturnURL  string `json:"clientReturnUrl,omitempty"`  // URL to proceed to when IRMA session is completed
	AugmentReturnURL bool   `json:"augmentReturnUrl,omitempty"` // Whether to augment the return url with the server session token
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

	Disclose AttributeConDisCon       `json:"disclose,omitempty"`
	Labels   map[int]TranslatedString `json:"labels,omitempty"`

	SkipExpiryCheck []CredentialTypeIdentifier `json:"skipExpiryCheck,omitempty"`
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
	Validity                    *Timestamp               `json:"validity,omitempty"`
	KeyCounter                  uint                     `json:"keyCounter,omitempty"`
	CredentialTypeID            CredentialTypeIdentifier `json:"credential"`
	Attributes                  map[string]string        `json:"attributes"`
	RevocationKey               string                   `json:"revocationKey,omitempty"`
	RevocationSupported         bool                     `json:"revocationSupported,omitempty"`
	RandomBlindAttributeTypeIDs []string                 `json:"randomblindIDs,omitempty"`
}

// SessionRequest instances contain all information the irmaclient needs to perform an IRMA session.
type SessionRequest interface {
	Validator
	Base() *BaseRequest
	GetNonce(timestamp *atum.Timestamp) *big.Int
	Disclosure() *DisclosureRequest
	Identifiers() *IrmaIdentifierSet
	Action() Action
	Legacy() (SessionRequest, error)
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
	ResultJwtValidity int              `json:"validity,omitempty"`    // Validity of session result JWT in seconds
	ClientTimeout     int              `json:"timeout,omitempty"`     // Wait this many seconds for the IRMA app to connect before the session times out
	CallbackURL       string           `json:"callbackUrl,omitempty"` // URL to post session result to
	NextSession       *NextSessionData `json:"nextSession,omitempty"` // Data about session to start after this one (if any)
}

type NextSessionData struct {
	URL string `json:"url"` // URL from which to get the next session after this one
}

// RequestorRequest is the message with which requestors start an IRMA session. It contains a
// SessionRequest instance for the irmaclient along with extra fields in a RequestorBaseRequest.
type RequestorRequest interface {
	Validator
	SessionRequest() SessionRequest
	Base() *RequestorBaseRequest
}

func (r *RequestorBaseRequest) SetDefaultsIfNecessary() {
	if r.ResultJwtValidity == 0 {
		r.ResultJwtValidity = DefaultJwtValidity
	}
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

type RevocationJwt struct {
	ServerJwt
	Request *RevocationRequest `json:"revrequest"`
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
	Type    AttributeTypeIdentifier `json:"type"`
	Value   *string                 `json:"value,omitempty"`
	NotNull bool                    `json:"notNull,omitempty"`
}

type PairingMethod string

const (
	PairingMethodNone = "none"
	PairingMethodPin  = "pin"
)

// An FrontendOptionsRequest asks for a options change of a particular session.
type FrontendOptionsRequest struct {
	LDContext     string        `json:"@context,omitempty"`
	PairingMethod PairingMethod `json:"pairingMethod"`
}

// FrontendSessionRequest contains session parameters for the frontend.
type FrontendSessionRequest struct {
	// Authorization token to access frontend endpoints.
	Authorization FrontendAuthorization `json:"authorization"`
	// PairingRecommended indictes to the frontend that pairing is recommended when starting the session.
	PairingRecommended bool `json:"pairingHint,omitempty"`
	// MinProtocolVersion that the server supports for the frontend protocol.
	MinProtocolVersion *ProtocolVersion `json:"minProtocolVersion"`
	// MaxProtocolVersion that the server supports for the frontend protocol.
	MaxProtocolVersion *ProtocolVersion `json:"maxProtocolVersion"`
}

type RevocationRequest struct {
	LDContext      string                   `json:"@context,omitempty"`
	CredentialType CredentialTypeIdentifier `json:"type"`
	Key            string                   `json:"revocationKey,omitempty"`
	Issued         int64                    `json:"issued,omitempty"`
}

type NonRevocationRequest struct {
	Tolerance uint64                      `json:"tolerance,omitempty"`
	Updates   map[uint]*revocation.Update `json:"updates,omitempty"`
}

type NonRevocationParameters map[CredentialTypeIdentifier]*NonRevocationRequest

type SessionOptions struct {
	LDContext     string        `json:"@context,omitempty"`
	PairingMethod PairingMethod `json:"pairingMethod"`
	PairingCode   string        `json:"pairingCode,omitempty"`
}

// ClientSessionRequest contains all information irmaclient needs to know to initiate a session.
type ClientSessionRequest struct {
	LDContext       string           `json:"@context,omitempty"`
	ProtocolVersion *ProtocolVersion `json:"protocolVersion,omitempty"`
	Options         *SessionOptions  `json:"options,omitempty"`
	Request         SessionRequest   `json:"request,omitempty"`
}

func (choice *DisclosureChoice) Validate() error {
	if choice == nil {
		return nil
	}
	for _, attrlist := range choice.Attributes {
		for _, attr := range attrlist {
			if attr.CredentialHash == "" {
				return errors.Errorf("no credential hash specified for %s", attr.Type)
			}
		}
	}
	return nil
}

func (n *NonRevocationParameters) UnmarshalJSON(bts []byte) error {
	var slice []CredentialTypeIdentifier
	if *n == nil {
		*n = NonRevocationParameters{}
	}
	if err := json.Unmarshal(bts, &slice); err == nil {
		for _, s := range slice {
			(*n)[s] = &NonRevocationRequest{}
		}
		return nil
	}
	return json.Unmarshal(bts, (*map[CredentialTypeIdentifier]*NonRevocationRequest)(n))
}

func (n *NonRevocationParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal((*map[CredentialTypeIdentifier]*NonRevocationRequest)(n))
}

func (r *RevocationRequest) Validate() error {
	if r.LDContext != LDContextRevocationRequest {
		return errors.New("not a revocation request")
	}
	return nil
}

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)

func (b *BaseRequest) Legacy() bool {
	return b.legacy
}

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

// RequestsRevocation indicates whether or not the requestor requires a nonrevocation proof for
// the given credential type; that is, whether or not it included revocation update messages.
func (b *BaseRequest) RequestsRevocation(id CredentialTypeIdentifier) bool {
	return len(b.Revocation) > 0 && b.Revocation[id] != nil && len(b.Revocation[id].Updates) > 0
}

func (b *BaseRequest) RevocationSupported() bool {
	return !b.ProtocolVersion.Below(2, 6)
}

func (b *BaseRequest) Validate(conf *Configuration) error {
	for credid := range b.Revocation {
		credtyp, ok := conf.CredentialTypes[credid]
		if !ok {
			return errors.Errorf("cannot requet nonrevocation proof for %s: unknown credential type", credid)
		}
		if !credtyp.RevocationSupported() {
			return errors.Errorf("cannot request nonrevocation proof for %s: revocation not enabled in scheme", credid)
		}
	}
	return nil
}

// CredentialTypes returns an array of all credential types occurring in this conjunction.
func (c AttributeCon) CredentialTypes() []CredentialTypeIdentifier {
	var result []CredentialTypeIdentifier

	for _, attr := range c {
		typ := attr.Type.CredentialTypeIdentifier()
		if len(result) == 0 || result[len(result)-1] != typ {
			result = append(result, typ)
		}
	}

	return result
}

func (c AttributeCon) Validate() error {
	// Unlike AttributeDisCon, we don't have to check here that the current instance is of length 0,
	// as that is actually a valid conjunction: one that specifies that the containing disjunction
	// is optional.

	credtypes := map[CredentialTypeIdentifier]struct{}{}
	var last CredentialTypeIdentifier
	for _, attr := range c {
		count := attr.Type.PartsCount()
		if count != 3 && count != 2 {
			return errors.Errorf("Expected attribute request to consist of 4 or 3 parts, %d found", count+1)
		}
		typ := attr.Type.CredentialTypeIdentifier()
		if _, contains := credtypes[typ]; contains && last != typ {
			return errors.New("Within inner conjunctions, attributes from the same credential type must be adjacent")
		}
		last = typ
		credtypes[typ] = struct{}{}
	}
	return nil
}

// AttributeRequest synonym with default JSON (un)marshaler
type jsonAttributeRequest AttributeRequest

func (ar *AttributeRequest) UnmarshalJSON(bts []byte) error {
	var s AttributeTypeIdentifier

	// first try to parse as JSON string into s
	if err := json.Unmarshal(bts, &s); err == nil {
		*ar = AttributeRequest{Type: s}
		return nil
	}

	return json.Unmarshal(bts, (*jsonAttributeRequest)(ar))
}

func (ar *AttributeRequest) MarshalJSON() ([]byte, error) {
	if !ar.NotNull && ar.Value == nil {
		return json.Marshal(ar.Type)
	}
	return json.Marshal((*jsonAttributeRequest)(ar))
}

// Satisfy indicates whether the given attribute type and value satisfies this AttributeRequest.
func (ar *AttributeRequest) Satisfy(attr AttributeTypeIdentifier, val *string) bool {
	return ar.Type == attr &&
		(!ar.NotNull || val != nil) &&
		(ar.Value == nil || (val != nil && *ar.Value == *val))
}

// Satisfy returns if each of the attributes specified by proofs and indices satisfies each of
// the contained AttributeRequests's. If so it also returns a list of the disclosed attribute values.
func (c AttributeCon) Satisfy(proofs gabi.ProofList, indices []*DisclosedAttributeIndex, revocation map[int]*time.Time, conf *Configuration) (bool, []*DisclosedAttribute, error) {
	if len(indices) < len(c) {
		return false, nil, nil
	}
	attrs := make([]*DisclosedAttribute, 0, len(c))
	if len(c) == 0 {
		return true, attrs, nil
	}

	for j := range c {
		index := indices[j]
		attr, val, err := extractAttribute(proofs, index, revocation[index.CredentialIndex], conf)
		if err != nil {
			return false, nil, err
		}
		if !c[j].Satisfy(attr.Identifier, val) {
			return false, nil, nil
		}
		attrs = append(attrs, attr)
	}
	return true, attrs, nil
}

func (dc AttributeDisCon) Validate() error {
	if len(dc) == 0 {
		return errors.New("Empty disjunction")
	}
	var err error
	for _, con := range dc {
		if err = con.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Satisfy returns true if the attributes specified by proofs and indices satisfies any one of the
// contained AttributeCon's. If so it also returns a list of the disclosed attribute values.
func (dc AttributeDisCon) Satisfy(proofs gabi.ProofList, indices []*DisclosedAttributeIndex, revocation map[int]*time.Time, conf *Configuration) (bool, []*DisclosedAttribute, error) {
	for _, con := range dc {
		satisfied, attrs, err := con.Satisfy(proofs, indices, revocation, conf)
		if err != nil {
			return false, nil, err
		}
		if satisfied {
			return true, attrs, nil
		}
	}
	return false, nil, nil
}

func (cdc AttributeConDisCon) Validate(conf *Configuration) error {
	for _, discon := range cdc {
		for _, con := range discon {
			var nonsingleton *CredentialTypeIdentifier
			for _, attr := range con {
				typ := attr.Type.CredentialTypeIdentifier()
				if !conf.CredentialTypes[typ].IsSingleton {
					if nonsingleton != nil && *nonsingleton != typ {
						return errors.New("Multiple non-singletons within one inner conjunction are not allowed")
					} else {
						nonsingleton = &typ
					}
				}
			}
		}
	}
	return nil
}

// Satisfy returns true if each of the contained AttributeDisCon is satisfied by the specified disclosure.
// If so it also returns the disclosed attributes.
func (cdc AttributeConDisCon) Satisfy(disclosure *Disclosure, revocation map[int]*time.Time, conf *Configuration) (bool, [][]*DisclosedAttribute, error) {
	if len(disclosure.Indices) < len(cdc) {
		return false, nil, nil
	}
	list := make([][]*DisclosedAttribute, len(cdc))
	complete := true

	for i, discon := range cdc {
		satisfied, attrs, err := discon.Satisfy(disclosure.Proofs, disclosure.Indices[i], revocation, conf)
		if err != nil {
			return false, nil, err
		}
		if satisfied {
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
			// Iterate by index to avoid passing (a pointer to) a copy of the AttributeRequest to f,
			// as this function is also used to modify requests.
			for i := range con {
				if err = f(&(con[i])); err != nil {
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
		BaseRequest: BaseRequest{LDContext: LDContextDisclosureRequest},
		Labels:      map[int]TranslatedString{},
	}
	for _, attr := range attrs {
		request.AddSingle(attr, nil, nil)
	}
	return request
}

func NewSignatureRequest(message string, attrs ...AttributeTypeIdentifier) *SignatureRequest {
	dr := NewDisclosureRequest(attrs...)
	dr.LDContext = LDContextSignatureRequest
	return &SignatureRequest{
		DisclosureRequest: *dr,
		Message:           message,
	}
}

func NewIssuanceRequest(creds []*CredentialRequest, attrs ...AttributeTypeIdentifier) *IssuanceRequest {
	dr := NewDisclosureRequest(attrs...)
	dr.LDContext = LDContextIssuanceRequest
	return &IssuanceRequest{
		DisclosureRequest: *dr,
		Credentials:       creds,
	}
}

func (dr *DisclosureRequest) Disclosure() *DisclosureRequest {
	return dr
}

func (dr *DisclosureRequest) identifiers() *IrmaIdentifierSet {
	ids := newIrmaIdentifierSet()
	_ = dr.Disclose.Iterate(func(a *AttributeRequest) error {
		attr := a.Type
		ids.SchemeManagers[attr.CredentialTypeIdentifier().IssuerIdentifier().SchemeManagerIdentifier()] = struct{}{}
		ids.Issuers[attr.CredentialTypeIdentifier().IssuerIdentifier()] = struct{}{}
		ids.CredentialTypes[attr.CredentialTypeIdentifier()] = struct{}{}
		ids.AttributeTypes[attr] = struct{}{}
		return nil
	})

	return ids
}

func (dr *DisclosureRequest) Identifiers() *IrmaIdentifierSet {
	if dr.ids == nil {
		dr.ids = dr.identifiers()
	}
	return dr.ids
}

func (dr *DisclosureRequest) Base() *BaseRequest {
	return &dr.BaseRequest
}

func (dr *DisclosureRequest) Action() Action { return ActionDisclosing }

func (dr *DisclosureRequest) IsDisclosureRequest() bool {
	return dr.LDContext == LDContextDisclosureRequest
}

func (dr *DisclosureRequest) Validate() error {
	if !dr.IsDisclosureRequest() {
		return errors.New("Not a disclosure request")
	}
	if len(dr.Identifiers().AttributeTypes) == 0 {
		return errors.New("Disclosure request had no attributes")
	}
	var err error
	for _, discon := range dr.Disclose {
		if err = discon.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (cr *CredentialRequest) Info(conf *Configuration, metadataVersion byte, issuedAt time.Time) (*CredentialInfo, error) {
	list, err := cr.AttributeList(conf, metadataVersion, nil, issuedAt)
	if err != nil {
		return nil, err
	}
	return list.CredentialInfo(), nil
}

// Validate checks that this credential request is consistent with the specified Configuration:
// the credential type is known, all required attributes are present and no unknown attributes
// are given.
func (cr *CredentialRequest) Validate(conf *Configuration) error {
	credtype := conf.CredentialTypes[cr.CredentialTypeID]
	if credtype == nil {
		return &SessionError{ErrorType: ErrorUnknownIdentifier, Err: errors.New("Credential request of unknown credential type")}
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
			return &SessionError{ErrorType: ErrorUnknownIdentifier, Err: errors.New("Credential request of unknown credential type")}
		}
	}

	for _, attrtype := range credtype.AttributeTypes {
		_, present := cr.Attributes[attrtype.ID]
		if !present && !attrtype.RevocationAttribute && !attrtype.RandomBlind && attrtype.Optional != "true" {
			return &SessionError{ErrorType: ErrorRequiredAttributeMissing, Err: errors.New("Required attribute not present in credential request")}
		}
		if present && attrtype.RevocationAttribute {
			return &SessionError{ErrorType: ErrorRevocation, Err: errors.New("revocation attribute cannot be set in credential request")}
		}
		if present && attrtype.RandomBlind {
			return &SessionError{ErrorType: ErrorRandomBlind, Err: errors.New("randomblind attribute cannot be set in credential request")}
		}
	}

	// Check that the random blind attributes match between client configuration / CredentialRequest
	clientRandomBlindAttributeIDs := credtype.RandomBlindAttributeNames()
	if !stringSliceEqual(clientRandomBlindAttributeIDs, cr.RandomBlindAttributeTypeIDs) {
		return &SessionError{ErrorType: ErrorRandomBlind, Err: errors.New("mismatch in randomblind attributes between server/client")}
	}

	return nil
}

// Checks for equality between two slices of strings
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// AttributeList returns the list of attributes from this credential request.
func (cr *CredentialRequest) AttributeList(
	conf *Configuration,
	metadataVersion byte,
	revocationAttr *big.Int,
	issuedAt time.Time,
) (*AttributeList, error) {
	if err := cr.Validate(conf); err != nil {
		return nil, err
	}

	credtype := conf.CredentialTypes[cr.CredentialTypeID]
	if !credtype.RevocationSupported() && revocationAttr != nil {
		return nil, errors.Errorf("cannot specify revocationAttr: credtype %s does not support revocation", cr.CredentialTypeID.String())
	}

	// Compute metadata attribute
	meta := NewMetadataAttribute(metadataVersion)
	meta.setKeyCounter(cr.KeyCounter)
	meta.setCredentialTypeIdentifier(cr.CredentialTypeID.String())
	meta.setSigningDate(issuedAt)
	if err := meta.setExpiryDate(cr.Validity); err != nil {
		return nil, err
	}

	// Compute other attributes
	attrs := make([]*big.Int, len(credtype.AttributeTypes)+1)
	attrs[0] = meta.Int
	if credtype.RevocationSupported() {
		if revocationAttr != nil {
			attrs[credtype.RevocationIndex+1] = revocationAttr
		} else {
			attrs[credtype.RevocationIndex+1] = bigZero
		}
	}
	for i, attrtype := range credtype.AttributeTypes {
		if attrtype.RevocationAttribute || attrtype.RandomBlind {
			continue
		}
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

	list := NewAttributeListFromInts(attrs, conf)
	list.RevocationSupported = cr.RevocationSupported
	return list, nil
}

func (ir *IssuanceRequest) Identifiers() *IrmaIdentifierSet {
	if ir.ids == nil {
		ir.ids = newIrmaIdentifierSet()

		for _, credreq := range ir.Credentials {
			issuer := credreq.CredentialTypeID.IssuerIdentifier()
			ir.ids.SchemeManagers[issuer.SchemeManagerIdentifier()] = struct{}{}
			ir.ids.Issuers[issuer] = struct{}{}
			credID := credreq.CredentialTypeID
			ir.ids.CredentialTypes[credID] = struct{}{}
			for attr := range credreq.Attributes { // this is kind of ugly
				ir.ids.AttributeTypes[NewAttributeTypeIdentifier(credID.String()+"."+attr)] = struct{}{}
			}
			if ir.ids.PublicKeys[issuer] == nil {
				ir.ids.PublicKeys[issuer] = []uint{}
			}
			ir.ids.PublicKeys[issuer] = append(ir.ids.PublicKeys[issuer], credreq.KeyCounter)
		}

		ir.ids.join(ir.DisclosureRequest.identifiers())
	}
	return ir.ids
}

func (ir *IssuanceRequest) GetCredentialInfoList(
	conf *Configuration,
	version *ProtocolVersion,
	issuedAt time.Time,
) (CredentialInfoList, error) {
	if ir.CredentialInfoList == nil {
		for _, credreq := range ir.Credentials {
			info, err := credreq.Info(conf, GetMetadataVersion(version), issuedAt)
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
	if ir.LDContext != LDContextIssuanceRequest {
		return errors.New("Not an issuance request")
	}
	if len(ir.Credentials) == 0 {
		return errors.New("Empty issuance request")
	}
	for _, cred := range ir.Credentials {
		count := cred.CredentialTypeID.PartsCount()
		if count != 2 {
			return errors.Errorf("Expected credential ID to consist of 3 parts, %d found", count+1)
		}
	}
	var err error
	for _, discon := range ir.Disclose {
		if err = discon.Validate(); err != nil {
			return err
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
		LDContext: LDContextSignedMessage,
		Signature: signature.Proofs,
		Indices:   signature.Indices,
		Nonce:     nonce,
		Context:   sr.GetContext(),
		Message:   sr.Message,
		Timestamp: timestamp,
	}, nil
}

func (sr *SignatureRequest) Action() Action { return ActionSigning }

func (sr *SignatureRequest) IsSignatureRequest() bool {
	return sr.LDContext == LDContextSignatureRequest
}

func (sr *SignatureRequest) Validate() error {
	if !sr.IsSignatureRequest() {
		return errors.New("Not a signature request")
	}
	if sr.Message == "" {
		return errors.New("Signature request had empty message")
	}
	if len(sr.Disclose) == 0 {
		return errors.New("Signature request had no attributes")
	}
	var err error
	for _, discon := range sr.Disclose {
		if err = discon.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Before checks if Timestamp is before other Timestamp. Used for checking expiry of attributes.
func (t Timestamp) Before(u Timestamp) bool {
	return time.Time(t).Before(time.Time(u))
}

// After checks if Timestamp is after other Timestamp. Used for checking expiry of attributes.
func (t Timestamp) After(u Timestamp) bool {
	return time.Time(t).After(time.Time(u))
}

// Sub returns the time difference between two Timestamps.
func (t Timestamp) Sub(u Timestamp) time.Duration {
	return time.Time(t).Sub(time.Time(u))
}

// IsZero checks whether Timestamp is uninitialized
func (t Timestamp) IsZero() bool {
	return time.Time(t).IsZero()
}

func (t *Timestamp) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(t.String(), start)
}

func (t *Timestamp) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var ts int64
	if err := d.DecodeElement(&ts, &start); err != nil {
		return err
	}
	*t = Timestamp(time.Unix(ts, 0))
	return nil
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

// String returns the timestamp as a Unix time string.
func (t *Timestamp) String() string {
	return fmt.Sprint(time.Time(*t).Unix())
}

func (t *Timestamp) Floor() Timestamp {
	return Timestamp(time.Unix((time.Time(*t).Unix()/ExpiryFactor)*ExpiryFactor, 0))
}

func readTimestamp(path string) (*Timestamp, bool, error) {
	exists, err := common.PathExists(path)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}
	bts, err := os.ReadFile(path)
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
			RequestorBaseRequest: RequestorBaseRequest{ResultJwtValidity: DefaultJwtValidity},
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
			RequestorBaseRequest: RequestorBaseRequest{ResultJwtValidity: DefaultJwtValidity},
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
			RequestorBaseRequest: RequestorBaseRequest{ResultJwtValidity: DefaultJwtValidity},
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

func (r *ServiceProviderRequest) Base() *RequestorBaseRequest {
	return &r.RequestorBaseRequest
}

func (r *SignatureRequestorRequest) Base() *RequestorBaseRequest {
	return &r.RequestorBaseRequest
}

func (r *IdentityProviderRequest) Base() *RequestorBaseRequest {
	return &r.RequestorBaseRequest
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

func (claims *RevocationJwt) Valid() error {
	if time.Time(claims.IssuedAt).After(time.Now()) {
		return errors.New("Signature jwt not yet valid")
	}
	return nil
}

func (claims *RevocationJwt) Sign(method jwt.SigningMethod, key interface{}) (string, error) {
	return jwt.NewWithClaims(method, claims).SignedString(key)
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

// NewFrontendOptionsRequest returns a new options request initialized with default values for each option
func NewFrontendOptionsRequest() FrontendOptionsRequest {
	return FrontendOptionsRequest{
		LDContext:     LDContextFrontendOptionsRequest,
		PairingMethod: PairingMethodNone,
	}
}

func (or *FrontendOptionsRequest) Validate() error {
	if or.LDContext != LDContextFrontendOptionsRequest {
		return errors.New("Not a frontend options request")
	}
	return nil
}

func (cr *ClientSessionRequest) UnmarshalJSON(data []byte) error {
	// Unmarshal in alias first to prevent infinite recursion
	type alias ClientSessionRequest
	err := json.Unmarshal(data, (*alias)(cr))
	if err != nil {
		return err
	}
	if cr.LDContext == LDContextClientSessionRequest {
		return nil
	}

	// For legacy sessions initialize client request by hand using the fetched request
	err = json.Unmarshal(data, cr.Request)
	if err != nil {
		return err
	}
	cr.LDContext = LDContextClientSessionRequest
	cr.ProtocolVersion = cr.Request.Base().ProtocolVersion
	cr.Options = &SessionOptions{
		LDContext:     LDContextSessionOptions,
		PairingMethod: PairingMethodNone,
	}
	return nil
}

func (cr *ClientSessionRequest) Validate() error {
	if cr.LDContext != LDContextClientSessionRequest {
		return errors.New("Not a client request")
	}
	// The 'Request' field is not required. When this field is empty, we have to skip the validation.
	// We cannot detect this easily, because in Go empty structs are automatically populated with
	// default values. We can also not use a pointer reference because SessionRequest is an interface.
	// Therefore we use reflection to check whether the struct that implements the interface is empty.
	if !reflect.ValueOf(cr.Request).Elem().IsZero() {
		return cr.Request.Validate()
	}
	return nil
}
