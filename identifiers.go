package irma

import (
	"database/sql/driver" // only imported to refer to the driver.Value type
	"fmt"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor"
	"github.com/go-errors/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type metaObjectIdentifier string

func (oi *metaObjectIdentifier) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*string)(oi))
}

func (oi metaObjectIdentifier) MarshalCBOR() (data []byte, err error) {
	return cbor.Marshal(string(oi), cbor.EncOptions{})
}

// RequestorSchemeIdentifier identifies a requestor scheme. Equal to its ID. For example "pbdf-requestors"
type RequestorSchemeIdentifier struct {
	metaObjectIdentifier
}

type RequestorIdentifier struct {
	metaObjectIdentifier
}

type IssueWizardIdentifier struct {
	metaObjectIdentifier
}

// SchemeManagerIdentifier identifies a scheme manager. Equal to its ID. For example "irma-demo".
type SchemeManagerIdentifier struct {
	metaObjectIdentifier
}

// IssuerIdentifier identifies an issuer. For example "irma-demo.RU".
type IssuerIdentifier struct {
	metaObjectIdentifier
}

// PublicKeyIdentifier identifies a single key from an issuer. For example: "irma-demo.RU-1"
type PublicKeyIdentifier struct {
	Issuer  IssuerIdentifier `json:"issuer"`
	Counter uint             `json:"counter"`
}

// CredentialTypeIdentifier identifies a credentialtype. For example "irma-demo.RU.studentCard".
type CredentialTypeIdentifier struct {
	metaObjectIdentifier
}

// AttributeTypeIdentifier identifies an attribute. For example "irma-demo.RU.studentCard.studentID".
type AttributeTypeIdentifier struct {
	metaObjectIdentifier
}

// CredentialIdentifier identifies a credential instance.
type CredentialIdentifier struct {
	Type CredentialTypeIdentifier
	Hash string
}

// AttributeIdentifier identifies an attribute instance.
type AttributeIdentifier struct {
	Type           AttributeTypeIdentifier
	CredentialHash string
}

// IrmaIdentifierSet contains a set (ensured by using map[...]struct{}) of all scheme managers,
// all issuers, all credential types, all public keys and all attribute types that are involved in an IRMA session.
type IrmaIdentifierSet struct {
	SchemeManagers   map[SchemeManagerIdentifier]struct{}
	Issuers          map[IssuerIdentifier]struct{}
	CredentialTypes  map[CredentialTypeIdentifier]struct{}
	PublicKeys       map[IssuerIdentifier][]uint
	AttributeTypes   map[AttributeTypeIdentifier]struct{}
	RequestorSchemes map[RequestorSchemeIdentifier]struct{}
}

func newIrmaIdentifierSet() *IrmaIdentifierSet {
	return &IrmaIdentifierSet{
		SchemeManagers:   map[SchemeManagerIdentifier]struct{}{},
		Issuers:          map[IssuerIdentifier]struct{}{},
		CredentialTypes:  map[CredentialTypeIdentifier]struct{}{},
		PublicKeys:       map[IssuerIdentifier][]uint{},
		AttributeTypes:   map[AttributeTypeIdentifier]struct{}{},
		RequestorSchemes: map[RequestorSchemeIdentifier]struct{}{},
	}
}

// Parent returns the parent object of this identifier.
func (oi metaObjectIdentifier) Parent() string {
	str := string(oi)
	if i := strings.LastIndex(str, "."); i != -1 {
		return str[:i]
	} else {
		return str
	}
}

// Name returns the last part of this identifier.
func (oi metaObjectIdentifier) Name() string {
	str := string(oi)
	return str[strings.LastIndex(str, ".")+1:]
}

// String returns this identifier as a string.
func (oi metaObjectIdentifier) String() string {
	return string(oi)
}

func (oi metaObjectIdentifier) Empty() bool {
	return len(oi) == 0
}

func (oi metaObjectIdentifier) Root() string {
	str := string(oi)
	if i := strings.Index(str, "."); i != -1 {
		return str[:i]
	} else {
		return str
	}
}

func (oi metaObjectIdentifier) PartsCount() int {
	return strings.Count(string(oi), ".")
}

// NewRequestorSchemeIdentifier converts the specified identifier to a RequestorSchemeIdentifier.
func NewRequestorSchemeIdentifier(id string) RequestorSchemeIdentifier {
	return RequestorSchemeIdentifier{metaObjectIdentifier(id)}
}

// NewRequestorIdentifier converts the specified identifier to a NewRequestorIdentifier.
func NewRequestorIdentifier(id string) RequestorIdentifier {
	return RequestorIdentifier{metaObjectIdentifier(id)}
}

// NewIssueWizardIdentifier converts the specified identifier to a NewIssueWizardIdentifier.
func NewIssueWizardIdentifier(id string) IssueWizardIdentifier {
	return IssueWizardIdentifier{metaObjectIdentifier(id)}
}

// NewSchemeManagerIdentifier converts the specified identifier to a SchemeManagerIdentifier.
func NewSchemeManagerIdentifier(id string) SchemeManagerIdentifier {
	return SchemeManagerIdentifier{metaObjectIdentifier(id)}
}

// NewIssuerIdentifier converts the specified identifier to a IssuerIdentifier.
func NewIssuerIdentifier(id string) IssuerIdentifier {
	return IssuerIdentifier{metaObjectIdentifier(id)}
}

// NewCredentialTypeIdentifier converts the specified identifier to a CredentialTypeIdentifier.
func NewCredentialTypeIdentifier(id string) CredentialTypeIdentifier {
	return CredentialTypeIdentifier{metaObjectIdentifier(id)}
}

// NewAttributeTypeIdentifier converts the specified identifier to a AttributeTypeIdentifier.
func NewAttributeTypeIdentifier(id string) AttributeTypeIdentifier {
	return AttributeTypeIdentifier{metaObjectIdentifier(id)}
}

// RequestorIdentifier returns the requestor identifier of the issue wizard.
func (id IssueWizardIdentifier) RequestorIdentifier() RequestorIdentifier {
	return NewRequestorIdentifier(id.Parent())
}

// RequestorSchemeIdentifier returns the requestor scheme identifier of the requestor.
func (id RequestorIdentifier) RequestorSchemeIdentifier() RequestorSchemeIdentifier {
	return NewRequestorSchemeIdentifier(id.Parent())
}

// SchemeManagerIdentifier returns the scheme manager identifer of the issuer.
func (id IssuerIdentifier) SchemeManagerIdentifier() SchemeManagerIdentifier {
	return NewSchemeManagerIdentifier(id.Parent())
}

// IssuerIdentifier returns the IssuerIdentifier of the credential identifier.
func (id CredentialTypeIdentifier) IssuerIdentifier() IssuerIdentifier {
	return NewIssuerIdentifier(id.Parent())
}

func (id CredentialTypeIdentifier) SchemeManagerIdentifier() SchemeManagerIdentifier {
	return NewSchemeManagerIdentifier(id.Root())
}

// CredentialTypeIdentifier returns the CredentialTypeIdentifier of the attribute identifier.
func (id AttributeTypeIdentifier) CredentialTypeIdentifier() CredentialTypeIdentifier {
	if id.IsCredential() {
		return NewCredentialTypeIdentifier(id.String())
	}
	return NewCredentialTypeIdentifier(id.Parent())
}

// IsCredential returns true if this attribute refers to its containing credential
// (i.e., it consists of only 3 parts).
func (id AttributeTypeIdentifier) IsCredential() bool {
	return strings.Count(id.String(), ".") == 2
}

// CredentialIdentifier returns the credential identifier of this attribute.
func (ai *AttributeIdentifier) CredentialIdentifier() CredentialIdentifier {
	return CredentialIdentifier{Type: ai.Type.CredentialTypeIdentifier(), Hash: ai.CredentialHash}
}

// MarshalText implements encoding.TextMarshaler.
func (id SchemeManagerIdentifier) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *SchemeManagerIdentifier) UnmarshalText(text []byte) error {
	*id = NewSchemeManagerIdentifier(string(text))
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (id RequestorSchemeIdentifier) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *RequestorSchemeIdentifier) UnmarshalText(text []byte) error {
	*id = NewRequestorSchemeIdentifier(string(text))
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (id RequestorIdentifier) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *RequestorIdentifier) UnmarshalText(text []byte) error {
	*id = NewRequestorIdentifier(string(text))
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (id IssueWizardIdentifier) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *IssueWizardIdentifier) UnmarshalText(text []byte) error {
	*id = NewIssueWizardIdentifier(string(text))
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (id IssuerIdentifier) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *IssuerIdentifier) UnmarshalText(text []byte) error {
	*id = NewIssuerIdentifier(string(text))
	return nil
}

func (pki *PublicKeyIdentifier) UnmarshalText(text []byte) error {
	str := string(text)
	index := strings.LastIndex(str, "-")
	if index == -1 {
		return errors.New("Invalid PublicKeyIdentifier")
	}
	counter, err := strconv.Atoi(str[index+1:])
	if err != nil {
		return err
	}
	*pki = PublicKeyIdentifier{Issuer: NewIssuerIdentifier(str[:index]), Counter: uint(counter)}
	return nil
}

func (pki *PublicKeyIdentifier) MarshalText() (text []byte, err error) {
	return []byte(pki.String()), nil
}

func (pki *PublicKeyIdentifier) String() string {
	return fmt.Sprintf("%s-%d", pki.Issuer, pki.Counter)
}

// MarshalText implements encoding.TextMarshaler.
func (id CredentialTypeIdentifier) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *CredentialTypeIdentifier) UnmarshalText(text []byte) error {
	*id = NewCredentialTypeIdentifier(string(text))
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (id AttributeTypeIdentifier) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *AttributeTypeIdentifier) UnmarshalText(text []byte) error {
	*id = NewAttributeTypeIdentifier(string(text))
	return nil
}

func (set *IrmaIdentifierSet) join(other *IrmaIdentifierSet) {
	for scheme := range other.SchemeManagers {
		set.SchemeManagers[scheme] = struct{}{}
	}
	for issuer := range other.Issuers {
		set.Issuers[issuer] = struct{}{}
	}
	for ct := range other.CredentialTypes {
		set.CredentialTypes[ct] = struct{}{}
	}
	for at := range other.AttributeTypes {
		set.AttributeTypes[at] = struct{}{}
	}
	for issuer := range other.PublicKeys {
		if len(set.PublicKeys[issuer]) == 0 {
			set.PublicKeys[issuer] = make([]uint, 0, len(other.PublicKeys[issuer]))
		}
		set.PublicKeys[issuer] = append(set.PublicKeys[issuer], other.PublicKeys[issuer]...)
	}
	for scheme := range other.RequestorSchemes {
		set.RequestorSchemes[scheme] = struct{}{}
	}
}

func (set *IrmaIdentifierSet) Distributed(conf *Configuration) bool {
	for id := range set.SchemeManagers {
		if conf.SchemeManagers[id].Distributed() {
			return true
		}
	}
	return false
}

func (set *IrmaIdentifierSet) allSchemes() map[SchemeManagerIdentifier]struct{} {
	schemes := make(map[SchemeManagerIdentifier]struct{})
	for s := range set.SchemeManagers {
		schemes[s] = struct{}{}
	}
	for i := range set.Issuers {
		schemes[i.SchemeManagerIdentifier()] = struct{}{}
	}
	for i := range set.PublicKeys {
		if len(set.PublicKeys[i]) > 0 {
			schemes[i.SchemeManagerIdentifier()] = struct{}{}
		}
	}
	for c := range set.CredentialTypes {
		schemes[c.IssuerIdentifier().SchemeManagerIdentifier()] = struct{}{}
	}
	for a := range set.AttributeTypes {
		schemes[a.CredentialTypeIdentifier().IssuerIdentifier().SchemeManagerIdentifier()] = struct{}{}
	}
	return schemes
}

func (set *IrmaIdentifierSet) String() string {
	var builder strings.Builder
	for s := range set.SchemeManagers {
		builder.WriteString(s.String() + ", ")
	}
	for s := range set.RequestorSchemes {
		builder.WriteString(s.String() + ", ")
	}
	for i := range set.Issuers {
		builder.WriteString(i.String() + ", ")
	}
	for i, keys := range set.PublicKeys {
		for _, k := range keys {
			builder.WriteString(fmt.Sprintf("%s-%d", i.String(), k))
		}
	}
	for c := range set.CredentialTypes {
		builder.WriteString(c.String() + ", ")
	}
	for a := range set.AttributeTypes {
		builder.WriteString(a.String() + ", ")
	}
	s := builder.String()
	if len(s) > 0 { // strip trailing comma
		s = s[:len(s)-2]
	}
	return s
}

func (set *IrmaIdentifierSet) Empty() bool {
	return len(set.SchemeManagers) == 0 &&
		len(set.Issuers) == 0 &&
		len(set.CredentialTypes) == 0 &&
		len(set.PublicKeys) == 0 &&
		len(set.AttributeTypes) == 0 &&
		len(set.RequestorSchemes) == 0
}

// Value implements sql/driver Scanner interface.
func (oi metaObjectIdentifier) Value() (driver.Value, error) {
	return oi.String(), nil
}

// Scan implements sql/driver Scanner interface.
func (oi *metaObjectIdentifier) Scan(src interface{}) error {
	switch s := src.(type) {
	case string:
		*oi = metaObjectIdentifier(s)
		return nil
	case []byte:
		*oi = metaObjectIdentifier(s)
		return nil
	}
	return errors.New("cannot convert source: not a string or []byte")
}

// GormDBDataType implements the gorm.io/gorm/migrator GormDataTypeInterface interface.
func (metaObjectIdentifier) GormDBDataType(db *gorm.DB, _ *schema.Field) string {
	switch db.Dialector.Name() {
	case "postgres":
		return "text"
	case "mysql":
		return "varchar(255)"
	default:
		return ""
	}
}
