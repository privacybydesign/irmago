package bitstringstatus

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
)

// MaxBitstringBytes caps the expanded (decompressed) bitstring size as a
// zip-bomb defense. The W3C minimum list is 16 KB / 131,072 single-bit entries
// (§2.1); this leaves generous headroom for larger lists and multi-bit entries.
const MaxBitstringBytes = 4 << 20 // 4 MiB

// multibaseBase64urlPrefix is the Multibase code point for base64url-no-pad
// ("u"); W3C §3.4 mandates it for encodedList.
const multibaseBase64urlPrefix = 'u'

// ExpandBitstring decodes a BitstringStatusListCredential's
// credentialSubject.encodedList into the raw bitstring bytes (W3C §3.4
// Expansion): a Multibase base64url-no-pad string (leading "u") wrapping a
// GZIP-compressed bitstring.
func ExpandBitstring(encodedList string) ([]byte, error) {
	if len(encodedList) == 0 || encodedList[0] != multibaseBase64urlPrefix {
		return nil, fmt.Errorf("%w: encodedList is not Multibase base64url (missing %q prefix)", ErrDecode, string(multibaseBase64urlPrefix))
	}

	compressed, err := base64.RawURLEncoding.DecodeString(encodedList[1:])
	if err != nil {
		return nil, fmt.Errorf("%w: encodedList is not base64url: %v", ErrDecode, err)
	}

	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("%w: gzip reader: %v", ErrDecode, err)
	}
	defer gz.Close()

	// LimitReader+1 detects overflow without buffering the whole payload.
	out, err := io.ReadAll(io.LimitReader(gz, MaxBitstringBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: gzip read: %v", ErrDecode, err)
	}
	if int64(len(out)) > MaxBitstringBytes {
		return nil, fmt.Errorf("%w: expanded bitstring exceeds cap (%d bytes)", ErrDecode, MaxBitstringBytes)
	}
	return out, nil
}

// StatusValueAt reads the statusSize-bit value at entry index idx from an
// expanded bitstring. Bits are packed MSB-first (W3C §3.2): index 0 is the
// most-significant bit of byte 0, and within a multi-bit entry the first bit is
// the most-significant bit of the returned value. For the default statusSize of
// 1 the value is 0 or 1 (e.g. purpose=revocation, 1 = revoked).
func StatusValueAt(bits []byte, statusSize int, idx uint64) (uint, error) {
	if statusSize < 1 || statusSize > 8 {
		return 0, fmt.Errorf("%w: unsupported statusSize %d (want 1..8)", ErrDecode, statusSize)
	}

	// Bound the index by the entry count rather than by its bit position:
	// idx*statusSize can overflow uint64 and wrap to a position in range.
	totalBits := uint64(len(bits)) * 8
	entries := totalBits / uint64(statusSize)
	if idx >= entries {
		return 0, fmt.Errorf("%w: index %d exceeds the list's %d entries", ErrIndexBounds, idx, entries)
	}
	startBit := idx * uint64(statusSize)

	var value uint
	for i := range statusSize {
		p := startBit + uint64(i)
		bit := (bits[p/8] >> (7 - uint(p%8))) & 1 // MSB-first within each byte
		value = value<<1 | uint(bit)
	}
	return value, nil
}
