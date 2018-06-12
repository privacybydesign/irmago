package irma

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"time"

	"fmt"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

const (
	// ExpiryFactor is the precision for the expiry attribute. Value is one week.
	ExpiryFactor   = 60 * 60 * 24 * 7
	metadataLength = 1 + 3 + 2 + 2 + 16
)

type AttributeResult struct {
	AttributeValue       string                  `json:"value"` // Value of the disclosed attribute
	AttributeId          AttributeTypeIdentifier `json:"id"`
	AttributeProofStatus AttributeProofStatus    `json:"status"`
}

type AttributeResultList []*AttributeResult

// AttributeProofStatus is the proof status of a single attribute
type AttributeProofStatus string

const (
	PRESENT       = AttributeProofStatus("PRESENT")       // Attribute is disclosed and matches the value
	EXTRA         = AttributeProofStatus("EXTRA")         // Attribute is disclosed, but wasn't requested in request
	MISSING       = AttributeProofStatus("MISSING")       // Attribute is NOT disclosed, but should be according to request
	INVALID_VALUE = AttributeProofStatus("INVALID_VALUE") // Attribute is disclosed, but has invalid value according to request
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
	*MetadataAttribute `json:"-"`
	Ints               []*big.Int
	strings            []TranslatedString
	info               *CredentialInfo
	h                  string
}

// NewAttributeListFromInts initializes a new AttributeList from a list of bigints.
func NewAttributeListFromInts(ints []*big.Int, conf *Configuration) *AttributeList {
	return &AttributeList{
		Ints:              ints,
		MetadataAttribute: MetadataFromInt(ints[0], conf),
	}
}

func (al *AttributeList) Info() *CredentialInfo {
	if al.info == nil {
		al.info = NewCredentialInfo(al.Ints, al.Conf)
	}
	return al.info
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

// Strings converts the current instance to human-readable strings.
func (al *AttributeList) Strings() []TranslatedString {
	if al.strings == nil {
		al.strings = make([]TranslatedString, len(al.Ints)-1)
		for i := range al.Ints[1:] { // skip metadata
			val := al.decode(i)
			if val == nil {
				continue
			}
			al.strings[i] = map[string]string{"en": *val, "nl": *val} // TODO
		}
	}
	return al.strings
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
	for i, desc := range al.CredentialType().Attributes {
		if desc.ID == string(identifier.Name()) {
			return al.decode(i)
		}
	}
	return nil
}

// Attribute returns the content of the specified attribute, or "" if not present in this attribute list.
func (al *AttributeList) Attribute(identifier AttributeTypeIdentifier) TranslatedString {
	if al.CredentialType().Identifier() != identifier.CredentialTypeIdentifier() {
		return nil
	}
	for i, desc := range al.CredentialType().Attributes {
		if desc.ID == string(identifier.Name()) {
			return al.Strings()[i]
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
func (attr *MetadataAttribute) Bytes() []byte {
	bytes := attr.Int.Bytes()
	if len(bytes) < metadataLength {
		bytes = append(bytes, make([]byte, metadataLength-len(bytes))...)
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
	attr.setField(signingDateField, shortToByte(int(time.Now().Unix()/ExpiryFactor)))
}

// KeyCounter return the public key counter of the metadata attribute
func (attr *MetadataAttribute) KeyCounter() int {
	return int(binary.BigEndian.Uint16(attr.field(keyCounterField)))
}

func (attr *MetadataAttribute) setKeyCounter(i int) {
	attr.setField(keyCounterField, shortToByte(i))
}

// ValidityDuration returns the amount of epochs during which this instance is valid
func (attr *MetadataAttribute) ValidityDuration() int {
	return int(binary.BigEndian.Uint16(attr.field(validityField)))
}

func (attr *MetadataAttribute) setValidityDuration(weeks int) {
	attr.setField(validityField, shortToByte(weeks))
}

func (attr *MetadataAttribute) setDefaultValidityDuration() {
	attr.setExpiryDate(nil)
}

func (attr *MetadataAttribute) setExpiryDate(timestamp *Timestamp) error {
	var expiry int64
	if timestamp == nil {
		expiry = time.Now().AddDate(0, 6, 0).Unix()
	} else {
		expiry = time.Time(*timestamp).Unix()
	}
	signing := attr.SigningDate().Unix()
	attr.setValidityDuration(int((expiry - signing) / ExpiryFactor))
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

func shortToByte(x int) []byte {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, uint16(x))
	return bytes
}

// A DisclosureChoice contains the attributes chosen to be disclosed.
type DisclosureChoice struct {
	Attributes []*AttributeIdentifier
}

// An AttributeDisjunction encapsulates a list of possible attributes, one
// of which should be disclosed.
type AttributeDisjunction struct {
	Label      string                    `json:"label"`
	Attributes []AttributeTypeIdentifier `json:"attributes"`
	Values     map[AttributeTypeIdentifier]*string

	selected *AttributeTypeIdentifier
}

// AttributeDisjunction with the disclosed value that is used to satisfy the disjunction
type DisclosedAttributeDisjunction struct {
	AttributeDisjunction

	DisclosedValue string
	DisclosedId    AttributeTypeIdentifier
	ProofStatus    AttributeProofStatus
}

// An AttributeDisjunctionList is a list of AttributeDisjunctions.
type AttributeDisjunctionList []*AttributeDisjunction

// Convert disjunction to a DisclosedAttributeDisjunction that contains disclosed attribute+value
func (disjunction *AttributeDisjunction) ToDisclosedAttributeDisjunction(ar *AttributeResult) *DisclosedAttributeDisjunction {
	return &DisclosedAttributeDisjunction{
		AttributeDisjunction: *disjunction,
		DisclosedValue:       ar.AttributeValue,
		DisclosedId:          ar.AttributeId,
		ProofStatus:          ar.AttributeProofStatus,
	}
}

// HasValues indicates if the attributes of this disjunction have values
// that should be satisfied.
func (disjunction *AttributeDisjunction) HasValues() bool {
	return disjunction.Values != nil && len(disjunction.Values) != 0
}

// Satisfied indicates if this disjunction has a valid chosen attribute
// to be disclosed.
func (disjunction *AttributeDisjunction) Satisfied() bool {
	if disjunction.selected == nil {
		return false
	}
	for _, attr := range disjunction.Attributes {
		if *disjunction.selected == attr {
			return true
		}
	}
	return false
}

// Check whether specified attributedisjunction satisfy a list of disclosed attributes
// We return true if one of the attributes in the disjunction is satisfied
func (disjunction *AttributeDisjunction) SatisfyDisclosed(disclosed DisclosedCredentialList, conf *Configuration) (bool, *DisclosedAttributeDisjunction) {
	var attributeResult *AttributeResult
	for _, attr := range disjunction.Attributes {
		requestedValue := disjunction.Values[attr]

		var isSatisfied bool
		isSatisfied, attributeResult = disclosed.isAttributeSatisfied(attr, requestedValue)

		if isSatisfied {
			return true, disjunction.ToDisclosedAttributeDisjunction(attributeResult)
		}
	}

	// Nothing satisfied, attributeResult will contain the last attribute of the original request
	// TODO: do we want this?
	return false, disjunction.ToDisclosedAttributeDisjunction(attributeResult)
}

// MatchesConfig returns true if all attributes contained in the disjunction are
// present in the specified configuration.
func (disjunction *AttributeDisjunction) MatchesConfig(conf *Configuration) bool {
	for ai := range disjunction.Values {
		creddescription, exists := conf.CredentialTypes[ai.CredentialTypeIdentifier()]
		if !exists {
			return false
		}
		if !creddescription.ContainsAttribute(ai) {
			return false
		}
	}
	return true
}

// Satisfied indicates whether each contained attribute disjunction has a chosen attribute.
func (dl AttributeDisjunctionList) Satisfied() bool {
	for _, disjunction := range dl {
		if !disjunction.Satisfied() {
			return false
		}
	}
	return true
}

// Find searches for and returns the disjunction that contains the specified attribute identifier, or nil if not found.
func (dl AttributeDisjunctionList) Find(ai AttributeTypeIdentifier) *AttributeDisjunction {
	for _, disjunction := range dl {
		for _, attr := range disjunction.Attributes {
			if attr == ai {
				return disjunction
			}
		}
	}
	return nil
}

// MarshalJSON marshals the disjunction to JSON.
func (disjunction *AttributeDisjunction) MarshalJSON() ([]byte, error) {
	if !disjunction.HasValues() {
		temp := struct {
			Label      string                    `json:"label"`
			Attributes []AttributeTypeIdentifier `json:"attributes"`
		}{
			Label:      disjunction.Label,
			Attributes: disjunction.Attributes,
		}
		return json.Marshal(temp)
	}

	temp := struct {
		Label      string                              `json:"label"`
		Attributes map[AttributeTypeIdentifier]*string `json:"attributes"`
	}{
		Label:      disjunction.Label,
		Attributes: disjunction.Values,
	}
	return json.Marshal(temp)
}

// Since we have a custom MarshalJSON for AttributeDisjunction, we also need one for every struct that extends AttributeDisjunction...
func (disclosedAttributeDisjunction *DisclosedAttributeDisjunction) MarshalJSON() ([]byte, error) {
	temp := struct {
		Label      string                    `json:"label"`
		Attributes []AttributeTypeIdentifier `json:"attributes"`

		DisclosedValue string                  `json:"disclosedValue"`
		DisclosedId    AttributeTypeIdentifier `json:"disclosedId"`
		ProofStatus    AttributeProofStatus    `json:"proofStatus"`
	}{
		Label:      disclosedAttributeDisjunction.Label,
		Attributes: disclosedAttributeDisjunction.Attributes,

		DisclosedValue: disclosedAttributeDisjunction.DisclosedValue,
		DisclosedId:    disclosedAttributeDisjunction.DisclosedId,
		ProofStatus:    disclosedAttributeDisjunction.ProofStatus,
	}

	return json.Marshal(temp)
}

// UnmarshalJSON unmarshals an attribute disjunction from JSON.
func (disjunction *AttributeDisjunction) UnmarshalJSON(bytes []byte) error {
	if disjunction.Values == nil {
		disjunction.Values = make(map[AttributeTypeIdentifier]*string)
	}
	if disjunction.Attributes == nil {
		disjunction.Attributes = make([]AttributeTypeIdentifier, 0, 3)
	}

	// We don't know if the json element "attributes" is a list, or a map.
	// So we unmarshal it into a temporary struct that has interface{} as the
	// type of "attributes", so that we can check which of the two it is.
	temp := struct {
		Label      string      `json:"label"`
		Attributes interface{} `json:"attributes"`
	}{}
	if err := json.Unmarshal(bytes, &temp); err != nil {
		return err
	}
	disjunction.Label = temp.Label

	switch temp.Attributes.(type) {
	case map[string]interface{}:
		temp := struct {
			Label      string             `json:"label"`
			Attributes map[string]*string `json:"attributes"`
		}{}
		if err := json.Unmarshal(bytes, &temp); err != nil {
			return err
		}
		for str, value := range temp.Attributes {
			id := NewAttributeTypeIdentifier(str)
			disjunction.Attributes = append(disjunction.Attributes, id)
			disjunction.Values[id] = value
		}
	case []interface{}:
		temp := struct {
			Label      string   `json:"label"`
			Attributes []string `json:"attributes"`
		}{}
		if err := json.Unmarshal(bytes, &temp); err != nil {
			return err
		}
		for _, str := range temp.Attributes {
			disjunction.Attributes = append(disjunction.Attributes, NewAttributeTypeIdentifier(str))
		}
	default:
		return errors.New("could not parse attribute disjunction: element 'attributes' was incorrect")
	}

	return nil
}

func (al *AttributeResultList) String() string {
	// TODO: pretty print?
	str := "Attribute --- Value --- ProofStatus:"
	for _, v := range *al {
		str = str + "\n" + v.String()
	}
	return str
}

func (ar *AttributeResult) String() string {
	return fmt.Sprintf("%v --- %v --- %v",
		ar.AttributeId,
		ar.AttributeValue,
		ar.AttributeProofStatus)
}
