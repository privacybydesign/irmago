package keyshareCore

import (
	"crypto/rsa"
)

type AesKey [32]byte

var decryptionKeys = map[uint32]AesKey{}
var encryptionKey AesKey
var encryptionKeyID uint32
var signKey *rsa.PrivateKey

func DangerousAddAESKey(keyid uint32, key AesKey) {
	decryptionKeys[keyid] = key
}

func DangerousSetAESEncryptionKey(keyid uint32, key AesKey) {
	decryptionKeys[keyid] = key
	encryptionKey = key
	encryptionKeyID = keyid
}

func DangerousSetSignKey(key *rsa.PrivateKey) {
	signKey = key
}
