package irma

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"

	"github.com/go-errors/errors"
)

const (
	// ExpiryFactor is the precision for the expiry attribute. Value is one week.
	ExpiryFactor   = 60 * 60 * 24 * 7
	metadataLength = 1 + 3 + 2 + 2 + 16
)

var (
	versionField     = metadataField{1, 0}
	signingDateField = metadataField{3, 1}
	validityField    = metadataField{2, 4}
	keyCounterField  = metadataField{2, 6}
	credentialID     = metadataField{16, 8}
)

// metadataField contains the length and offset of a field within a metadata attribute.
type metadataField struct {
	length int
	offset int
}

// metadataAttribute represents a metadata attribute. Contains the credential type, signing date, validity, and the public key counter.
type MetadataAttribute struct {
	Int  *big.Int
	pk   *gabi.PublicKey
	Conf *Configuration
}

// AttributeList contains attributes, excluding the secret key,
// providing convenient access to the metadata attribute.
type AttributeList struct {
	*MetadataAttribute  `json:"-"`
	Ints                []*big.Int
	Revoked             bool `json:",omitempty"`
	RevocationSupported bool `json:",omitempty"`
	strings             []TranslatedString
	attrMap             map[AttributeTypeIdentifier]TranslatedString
	info                *CredentialInfo
	h                   string
}

// NewAttributeListFromInts initializes a new AttributeList from a list of bigints.
func NewAttributeListFromInts(ints []*big.Int, conf *Configuration) *AttributeList {
	metadata := MetadataFromInt(ints[0], conf)
	credtype := metadata.CredentialType()
	idx := credtype.RevocationIndex + 1
	var rev bool
	if credtype != nil {
		rev = len(ints) > idx && ints[idx] != nil && ints[idx].Cmp(bigZero) != 0
	}
	return &AttributeList{
		Ints:                ints,
		MetadataAttribute:   metadata,
		RevocationSupported: rev,
	}
}

func (al *AttributeList) Info() *CredentialInfo {
	if al.info == nil {
		al.info = al.CredentialInfo()
	}
	al.info.Revoked = al.Revoked
	return al.info
}

// EqualsExceptMetadata checks whether two AttributeLists have the same attribute values.
// The attribute containing the metadata information is skipped in this check.
func (al *AttributeList) EqualsExceptMetadata(ol *AttributeList) bool {
	if len(al.Ints) != len(ol.Ints) {
		return false
	}

	// Check whether value of all attributes, except for metadata attribute, is equal
	for i := 1; i < len(al.Ints); i++ {
		if al.Ints[i].Cmp(ol.Ints[i]) != 0 {
			return false
		}
	}
	return true
}

func (al *AttributeList) Hash() string {
	if al.h == "" {
		bytes := []byte{}
		for _, i := range al.Ints {
			bytes = append(bytes, i.Bytes()...)
		}
		shasum := sha256.Sum256(bytes)
		al.h = hex.EncodeToString(shasum[:])
	}
	return al.h
}

func (al *AttributeList) Map() map[AttributeTypeIdentifier]TranslatedString {
	if al.attrMap == nil {
		al.attrMap = make(map[AttributeTypeIdentifier]TranslatedString)
		ctid := al.CredentialType().Identifier()
		attrTypes := al.Conf.CredentialTypes[ctid].AttributeTypes
		for i, val := range al.Strings() {
			if attrTypes[i].RevocationAttribute {
				continue
			}
			al.attrMap[attrTypes[i].GetAttributeTypeIdentifier()] = val
		}
	}
	return al.attrMap
}

// Strings converts the current instance to human-readable strings.
func (al *AttributeList) Strings() []TranslatedString {
	if al.strings == nil {
		al.strings = make([]TranslatedString, len(al.Ints)-1)
		for i := range al.Ints[1:] { // skip metadata
			val := al.decode(i)
			if val == nil {
				continue
			}
			al.strings[i] = NewTranslatedString(val)
		}
	}
	return al.strings
}

// NewTranslatedString returns a TranslatedString containing the specified string for each supported language,
// or nil when attr is nil.
func NewTranslatedString(attr *string) TranslatedString {
	if attr == nil {
		return nil
	}
	return map[string]string{
		"":   *attr, // raw value
		"en": *attr,
		"nl": *attr,
	}
}

func (al *AttributeList) decode(i int) *string {
	attr := al.Ints[i+1]
	metadataVersion := al.MetadataAttribute.Version()
	return decodeAttribute(attr, metadataVersion)
}

// Decode attribute value into string according to metadataVersion
func decodeAttribute(attr *big.Int, metadataVersion byte) *string {
	bi := new(big.Int).Set(attr)
	if metadataVersion >= 3 {
		if bi.Bit(0) == 0 { // attribute does not exist
			return nil
		}
		bi.Rsh(bi, 1)
	}
	str := string(bi.Bytes())
	return &str
}

// UntranslatedAttribute decodes the bigint corresponding to the specified attribute.
func (al *AttributeList) UntranslatedAttribute(identifier AttributeTypeIdentifier) *string {
	if al.CredentialType().Identifier() != identifier.CredentialTypeIdentifier() {
		return nil
	}
	for i, desc := range al.CredentialType().AttributeTypes {
		if desc.ID == string(identifier.Name()) {
			return al.decode(i)
		}
	}
	return nil
}

// Attribute returns the content of the specified attribute, or nil if not present in this attribute list.
func (al *AttributeList) Attribute(identifier AttributeTypeIdentifier) TranslatedString {
	if al.CredentialType().Identifier() != identifier.CredentialTypeIdentifier() {
		return nil
	}

	for i, val := range al.Strings() {
		if al.CredentialType().AttributeTypes[i].ID == string(identifier.Name()) {
			return val
		}
	}

	return nil
}

// MetadataFromInt wraps the given Int
func MetadataFromInt(i *big.Int, conf *Configuration) *MetadataAttribute {
	return &MetadataAttribute{Int: i, Conf: conf}
}

// NewMetadataAttribute constructs a new instance containing the default values:
// provided version as versionField
// now as signing date
// 0 as keycounter
// ValidityDefault (half a year) as default validity.
func NewMetadataAttribute(version byte) *MetadataAttribute {
	val := MetadataAttribute{new(big.Int), nil, nil}
	val.setField(versionField, []byte{version})
	val.setSigningDate()
	val.setKeyCounter(0)
	val.setDefaultValidityDuration()
	return &val
}

// Bytes returns this metadata attribute as a byte slice.
// Bigint's Bytes() method returns a big-endian byte slice, so add padding at begin.
func (attr *MetadataAttribute) Bytes() []byte {
	bytes := attr.Int.Bytes()
	if len(bytes) < metadataLength {
		bytes = append(make([]byte, metadataLength-len(bytes)), bytes...)
	}
	return bytes
}

// PublicKey extracts identifier of the Idemix public key with which this instance was signed,
// and returns this public key.
func (attr *MetadataAttribute) PublicKey() (*gabi.PublicKey, error) {
	if attr.pk == nil {
		var err error
		attr.pk, err = attr.Conf.PublicKey(attr.CredentialType().IssuerIdentifier(), attr.KeyCounter())
		if err != nil {
			return nil, err
		}
	}
	return attr.pk, nil
}

// Version returns the metadata version of this instance
func (attr *MetadataAttribute) Version() byte {
	return attr.field(versionField)[0]
}

// SigningDate returns the time at which this instance was signed
func (attr *MetadataAttribute) SigningDate() time.Time {
	bytes := attr.field(signingDateField)
	bytes = bytes[1:] // The signing date field is one byte too long
	timestamp := int64(binary.BigEndian.Uint16(bytes)) * ExpiryFactor
	return time.Unix(timestamp, 0)
}

func (attr *MetadataAttribute) setSigningDate() {
	attr.setField(signingDateField, shortToByte(uint(time.Now().Unix()/ExpiryFactor)))
}

// KeyCounter return the public key counter of the metadata attribute
func (attr *MetadataAttribute) KeyCounter() uint {
	return uint(binary.BigEndian.Uint16(attr.field(keyCounterField)))
}

func (attr *MetadataAttribute) setKeyCounter(i uint) {
	attr.setField(keyCounterField, shortToByte(i))
}

// ValidityDuration returns the amount of epochs during which this instance is valid
func (attr *MetadataAttribute) ValidityDuration() int {
	return int(binary.BigEndian.Uint16(attr.field(validityField)))
}

func (attr *MetadataAttribute) setValidityDuration(weeks uint) {
	attr.setField(validityField, shortToByte(weeks))
}

func (attr *MetadataAttribute) setDefaultValidityDuration() {
	// setExpiryDate only errors if setting the expiry date before the signing date,
	// which never happens here
	_ = attr.setExpiryDate(nil)
}

func (attr *MetadataAttribute) setExpiryDate(timestamp *Timestamp) error {
	signingTimestamp := attr.SigningDate()
	var expiry int64
	if timestamp == nil {
		expiry = signingTimestamp.AddDate(0, 6, 0).Unix()
	} else {
		expiry = time.Time(*timestamp).Unix()
	}
	signing := signingTimestamp.Unix()
	if expiry-signing < 0 {
		return errors.New("cannot set expired date")
	}
	attr.setValidityDuration(uint((expiry - signing) / ExpiryFactor))
	return nil
}

// CredentialType returns the credential type of the current instance
// using the Configuration.
func (attr *MetadataAttribute) CredentialType() *CredentialType {
	return attr.Conf.hashToCredentialType(attr.field(credentialID))
}

func (attr *MetadataAttribute) setCredentialTypeIdentifier(id string) {
	bytes := sha256.Sum256([]byte(id))
	attr.setField(credentialID, bytes[:16])
}

func (attr *MetadataAttribute) CredentialTypeHash() []byte {
	return attr.field(credentialID)
}

// Expiry returns the expiry date of this instance
func (attr *MetadataAttribute) Expiry() time.Time {
	expiry := attr.SigningDate().Unix() + int64(attr.ValidityDuration()*ExpiryFactor)
	return time.Unix(expiry, 0)
}

// IsValidOn returns whether this instance is still valid at the given time
func (attr *MetadataAttribute) IsValidOn(t time.Time) bool {
	return attr.Expiry().After(t)
}

// IsValid returns whether this instance is valid.
func (attr *MetadataAttribute) IsValid() bool {
	return attr.IsValidOn(time.Now())
}

// FloorToEpochBoundary returns the greatest time not greater than the argument
// that falls on the boundary of an epoch for attribute validity or expiry,
// of which the value is defined by ExpiryFactor (one week).
func FloorToEpochBoundary(t time.Time) time.Time {
	return time.Unix((t.Unix()/ExpiryFactor)*ExpiryFactor, 0)
}

func (attr *MetadataAttribute) field(field metadataField) []byte {
	return attr.Bytes()[field.offset : field.offset+field.length]
}

func (attr *MetadataAttribute) setField(field metadataField, value []byte) {
	if len(value) > field.length {
		panic("Specified metadata field too large")
	}

	bytes := attr.Bytes()

	// Push the value to the right within the field. Graphical representation:
	// --xxxXXX----
	// "-" indicates a byte of another field
	// "X" is a byte of the value and "x" of our field
	// In this example, our field has offset 2, length 6,
	// but the specified value is only 3 bytes long.
	startindex := field.length - len(value)
	for i := 0; i < field.length; i++ {
		if i < startindex {
			bytes[i+field.offset] = 0
		} else {
			bytes[i+field.offset] = value[i-startindex]
		}
	}

	attr.Int.SetBytes(bytes)
}

func shortToByte(x uint) []byte {
	bytes := make([]byte, 2)
	if x > 1<<16 {
		panic("overflow uint16")
	}
	binary.BigEndian.PutUint16(bytes, uint16(x))
	return bytes
}
