package statuslist

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"io"
)

// decodeBits decompresses the base64url + zlib encoded `lst` field and
// returns the raw bit-array bytes. maxBytes caps the decompressed size
// to defend against zip bombs; 0 means use MaxBodyDefault.
func decodeBits(lstB64 string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxBodyDefault
	}
	compressed, err := base64.RawURLEncoding.DecodeString(lstB64)
	if err != nil {
		return nil, fmt.Errorf("%w: lst is not base64url: %v", ErrDecode, err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("%w: zlib reader: %v", ErrDecode, err)
	}
	defer zr.Close()

	// LimitReader+1 lets us detect overflow without buffering the
	// whole would-be payload.
	out, err := io.ReadAll(io.LimitReader(zr, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: zlib read: %v", ErrDecode, err)
	}
	if int64(len(out)) > maxBytes {
		return nil, fmt.Errorf("%w: decompressed lst exceeds cap (%d bytes)", ErrDecode, maxBytes)
	}
	return out, nil
}

// statusAtIndex extracts the bits-wide status value at the given
// index from a decoded bit array, then maps the raw value to a Status.
//
// Bit packing per draft-ietf-oauth-status-list-15 §4: the array is
// little-endian within each byte, lowest-order bits first. With
// bits=2, byte 0 holds entries 0..3 in positions [0:2, 2:4, 4:6, 6:8].
func statusAtIndex(bits []byte, bitSize int, idx uint64) (Status, error) {
	if !validBitSize(bitSize) {
		return StatusUnknown, fmt.Errorf("%w: invalid bit size: %d", ErrUnauthorized, bitSize)
	}

	totalBits := uint64(len(bits)) * 8
	startBit := idx * uint64(bitSize)
	if startBit+uint64(bitSize) > totalBits {
		return StatusUnknown, fmt.Errorf("%w: idx %d at bit %d exceeds %d total bits", ErrIndexBounds, idx, startBit, totalBits)
	}

	byteIdx := startBit / 8
	bitOffset := uint(startBit % 8)
	mask := byte((1 << bitSize) - 1)
	raw := (bits[byteIdx] >> bitOffset) & mask

	return statusFromRaw(raw), nil
}
