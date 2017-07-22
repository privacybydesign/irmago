package irmago

import (
	"crypto/sha256"
	"math/big"

	"github.com/mhe/gabi"
)

// AttributeList contains attributes, excluding the secret key,
// providing convenient access to the metadata attribute.
type AttributeList struct {
	Ints    []*big.Int
	strings []string
	*gabi.MetadataAttribute `json:"-"`
}

// NewAttributeListFromInts initializes a new AttributeList from a list of bigints.
func NewAttributeListFromInts(ints []*big.Int) *AttributeList {
	return &AttributeList{
		Ints:              ints,
		MetadataAttribute: gabi.MetadataFromInt(ints[0]),
	}
}

// TODO maybe remove
func (al *AttributeList) hash() string {
	bytes := make([]byte, 20)
	for _, i := range al.Ints {
		bytes = append(bytes, i.Bytes()...)
	}
	shasum := sha256.Sum256(bytes)
	return string(shasum[:])
}

// Strings converts the current instance to human-readable strings.
func (al *AttributeList) Strings() []string {
	if al.strings == nil {
		al.strings = make([]string, len(al.Ints)-1)
		for index, num := range al.Ints[1:] { // skip metadata
			al.strings[index] = string(num.Bytes())
		}
	}
	return al.strings
}
