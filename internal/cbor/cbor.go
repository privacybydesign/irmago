// Package cbor provides helper functions for encoding and decoding CBOR
// by wrapping functions provided by github.com/fxamacker/cbor.
//
// 1. CBOR is encoded using Core Deterministic Encoding defined in
//    RFC 8949, which obsoletes Canonical CBOR defined in RFC 7049.
// 2. CBOR decoder detects and rejects duplicate map keys, which is
//    an important requirement in security sensitive applications.
//
// For more info, see:
//   * https://github.com/fxamacker/cbor
//   * https://github.com/x448/safer-cbor
//   * https://tools.ietf.org/html/rfc8949
//
package cbor

import (
	"io"

	"github.com/fxamacker/cbor/v2" // imports as cbor
)

// Place limits on number of array elements to improve security.
// Increase these limits if you think they're too small.
const MaxArrayElements = 1024 * 256 // this limit can be set as high as 2147483647
const MaxMapPairs = 1024 * 256      // this limit can be set as high as 2147483647

var (

	// encOptions specifies how CBOR should be encoded.
	encOptions = cbor.EncOptions{
		InfConvert:    cbor.InfConvertFloat16,
		IndefLength:   cbor.IndefLengthForbidden,
		NaNConvert:    cbor.NaNConvert7e00,
		ShortestFloat: cbor.ShortestFloat16,
		Sort:          cbor.SortCoreDeterministic, // or cbor.SortNone for faster encoding
		TagsMd:        cbor.TagsAllowed,
		Time:          cbor.TimeUnix,
	}

	// decOptions specifies how CBOR should be decoded.
	decOptions = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF, // or cbor.DupMapKeyQuiet for faster decoding
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		IndefLength:       cbor.IndefLengthForbidden,
		MaxArrayElements:  MaxArrayElements,
		MaxMapPairs:       MaxMapPairs,
		TagsMd:            cbor.TagsAllowed,
		TimeTag:           cbor.DecTagIgnored,
	}

	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	if encMode, err = encOptions.EncMode(); err != nil {
		panic(err)
	}
	if decMode, err = decOptions.DecMode(); err != nil {
		panic(err)
	}
}

// Marshal encodes src into a CBOR-encoded byte slice.
func Marshal(src interface{}) ([]byte, error) {
	return encMode.Marshal(src)
}

// Unmarshal decodes CBOR in data into dst.
// Providing empty data is a no-op without error.
func Unmarshal(data []byte, dst interface{}) error {
	if data == nil {
		return nil
	}

	return decMode.Unmarshal(data, dst)
}

// NewEncoder creates a new CBOR encoder that writes to w.
func NewEncoder(w io.Writer) *cbor.Encoder {
	return encMode.NewEncoder(w)
}

// NewDecoder creates a new CBOR decoder that reads from r.
func NewDecoder(r io.Reader) *cbor.Decoder {
	return decMode.NewDecoder(r)
}
