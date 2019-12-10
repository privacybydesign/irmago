package irma

import (
	"database/sql/driver" // only imported to refer to the driver.Value type
	"fmt"
	"strings"

	"github.com/go-errors/errors"
	"github.com/jinzhu/gorm"
)

type metaObjectIdentifier string

func (oi *metaObjectIdentifier) UnmarshalBinary(data []byte) error {
	*oi = metaObjectIdentifier(data)
	return nil
}

func (oi metaObjectIdentifier) MarshalBinary() (data []byte, err error) {
	return []byte(oi), nil
}

// SchemeManagerIdentifier identifies a scheme manager. Equal to its ID. For example "irma-demo".
type SchemeManagerIdentifier struct {
	metaObjectIdentifier
}

// IssuerIdentifier identifies an issuer. For example "irma-demo.RU".
type IssuerIdentifier struct {
	metaObjectIdentifier
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
	SchemeManagers  map[SchemeManagerIdentifier]struct{}
	Issuers         map[IssuerIdentifier]struct{}
	CredentialTypes map[CredentialTypeIdentifier]struct{}
	PublicKeys      map[IssuerIdentifier][]int
	AttributeTypes  map[AttributeTypeIdentifier]struct{}
}

func newIrmaIdentifierSet() *IrmaIdentifierSet {
	return &IrmaIdentifierSet{
		SchemeManagers:  map[SchemeManagerIdentifier]struct{}{},
		Issuers:         map[IssuerIdentifier]struct{}{},
		CredentialTypes: map[CredentialTypeIdentifier]struct{}{},
		PublicKeys:      map[IssuerIdentifier][]int{},
		AttributeTypes:  map[AttributeTypeIdentifier]struct{}{},
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

// SchemeManagerIdentifier returns the scheme manager identifer of the issuer.
func (id IssuerIdentifier) SchemeManagerIdentifier() SchemeManagerIdentifier {
	return NewSchemeManagerIdentifier(id.Parent())
}

// IssuerIdentifier returns the IssuerIdentifier of the credential identifier.
func (id CredentialTypeIdentifier) IssuerIdentifier() IssuerIdentifier {
	return NewIssuerIdentifier(id.Parent())
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
func (id IssuerIdentifier) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *IssuerIdentifier) UnmarshalText(text []byte) error {
	*id = NewIssuerIdentifier(string(text))
	return nil
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
			set.PublicKeys[issuer] = make([]int, 0, len(other.PublicKeys[issuer]))
		}
		set.PublicKeys[issuer] = append(set.PublicKeys[issuer], other.PublicKeys[issuer]...)
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
	return len(set.SchemeManagers) == 0 && len(set.Issuers) == 0 && len(set.CredentialTypes) == 0 && len(set.PublicKeys) == 0 && len(set.AttributeTypes) == 0
}

func (oi metaObjectIdentifier) Value() (driver.Value, error) {
	return oi.String(), nil
}

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

func (metaObjectIdentifier) GormDataType(dialect gorm.Dialect) string {
	switch dialect.GetName() {
	case "postgres":
		return "text"
	case "mysql":
		return "varchar(512)"
	default:
		return ""
	}
}
