package iana

import (
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
)

type HashingAlgorithm string

const (
	SHA256     HashingAlgorithm = "sha-256"
	SHA256_128 HashingAlgorithm = "sha-256-128"
	SHA256_120 HashingAlgorithm = "sha-256-120"
	SHA256_96  HashingAlgorithm = "sha-256-96"
	SHA256_64  HashingAlgorithm = "sha-256-64"
	SHA256_32  HashingAlgorithm = "sha-256-32"
	SHA384     HashingAlgorithm = "sha-384"
	SHA512     HashingAlgorithm = "sha-512"
	SHA3_224   HashingAlgorithm = "sha3-224"
	SHA3_256   HashingAlgorithm = "sha3-256"
	SHA3_384   HashingAlgorithm = "sha3-384"
	SHA3_512   HashingAlgorithm = "sha3-512"
)

func IsSupportedHashingAlgorithm(name HashingAlgorithm) bool {
	switch name {
	case SHA256, SHA256_128, SHA256_120, SHA256_96, SHA256_64, SHA256_32,
		SHA384, SHA512,
		SHA3_224, SHA3_256, SHA3_384, SHA3_512:
		return true
	default:
		return false
	}
}

func GetHashByIANA(name HashingAlgorithm) (hash.Hash, error) {
	switch name {
	case SHA256:
		return sha256.New(), nil
	case SHA256_128:
		return sha256.New(), nil
	case SHA256_120:
		return sha256.New(), nil
	case SHA256_96:
		return sha256.New(), nil
	case SHA256_64:
		return sha256.New(), nil
	case SHA256_32:
		return sha256.New(), nil
	case SHA384:
		return sha512.New384(), nil
	case SHA512:
		return sha512.New(), nil
	case SHA3_224:
		return sha3.New224(), nil
	case SHA3_256:
		return sha3.New256(), nil
	case SHA3_384:
		return sha3.New384(), nil
	case SHA3_512:
		return sha3.New512(), nil
	default:
		return nil, fmt.Errorf("unsupported hashing algorithm: %s", name)
	}
}

func Sum(algorithm HashingAlgorithm, content string) ([]byte, error) {
	hasher, err := GetHashByIANA(algorithm)
	if err != nil {
		return nil, err
	}

	io.WriteString(hasher, content)
	hash := hasher.Sum(nil)

	// Truncate hash if needed
	switch algorithm {
	case SHA256_128:
		hash = hash[:16]
	case SHA256_120:
		hash = hash[:15]
	case SHA256_96:
		hash = hash[:12]
	case SHA256_64:
		hash = hash[:8]
	case SHA256_32:
		hash = hash[:4]
	}

	return hash, nil
}
