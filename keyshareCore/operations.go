package keyshareCore

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
)

var (
	ErrInvalidPin       = errors.New("invalid pin")
	ErrPinTooLong       = errors.New("pin too long")
	ErrInvalidChallenge = errors.New("challenge out of bounds")
	ErrInvalidJWT       = errors.New("invalid jwt token")
	ErrKeyNotFound      = errors.New("public key not found")
	ErrUnknownCommit    = errors.New("unknown commit id")
)

// Generate a new keyshare secret, secured with the given pin
func (c *KeyshareCore) GenerateKeyshareSecret(pinRaw string) (EncryptedKeysharePacket, error) {
	pin, err := padPin(pinRaw)
	if err != nil {
		return EncryptedKeysharePacket{}, err
	}

	keyshareSecret, err := gabi.NewKeyshareSecret()
	if err != nil {
		return EncryptedKeysharePacket{}, err
	}

	// Build unencrypted packet
	var p unencryptedKeysharePacket
	p.setPin(pin)
	err = p.setKeyshareSecret(keyshareSecret)
	if err != nil {
		return EncryptedKeysharePacket{}, err
	}

	// And encrypt
	return c.encryptPacket(p)
}

// Check pin for validity, and generate jwt for future access
//  userid is an extra field added to the jwt for
func (c *KeyshareCore) ValidatePin(ep EncryptedKeysharePacket, pin string, userid string) (string, error) {
	paddedPin, err := padPin(pin)
	if err != nil {
		return "", err
	}

	// decrypt
	p, err := c.decryptPacket(ep)
	if err != nil {
		return "", err
	}

	// verify pin
	refPin := p.getPin()
	if !hmac.Equal(refPin[:], paddedPin[:]) {
		return "", ErrInvalidPin
	}

	// Generate jwt token
	salt := make([]byte, 12)
	_, err = rand.Read(salt)
	if err != nil {
		return "", err
	}
	hashedPin := sha256.Sum256(append(salt, refPin[:]...))
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":        "keyshare_server",
		"sub":        "auth_tok",
		"iat":        time.Now().Unix(),
		"exp":        time.Now().Add(3 * time.Minute).Unix(),
		"user_id":    userid,
		"salt":       base64.StdEncoding.EncodeToString(salt),
		"hashed_pin": base64.StdEncoding.EncodeToString(hashedPin[:]),
	})
	jwtResult, err := token.SignedString(c.signKey)
	if err != nil {
		return "", err
	}

	return jwtResult, nil
}

func (c *KeyshareCore) ValidateJWT(ep EncryptedKeysharePacket, jwt string) error {
	_, err := c.verifyAccess(ep, jwt)
	return err
}

// Change pin in an encrypted keyshare packet to a new value, after validating that the old value is known by caller.
func (c *KeyshareCore) ChangePin(ep EncryptedKeysharePacket, oldpinRaw, newpinRaw string) (EncryptedKeysharePacket, error) {
	oldpin, err := padPin(oldpinRaw)
	if err != nil {
		return EncryptedKeysharePacket{}, err
	}
	newpin, err := padPin(newpinRaw)
	if err != nil {
		return EncryptedKeysharePacket{}, err
	}

	// decrypt
	p, err := c.decryptPacket(ep)
	if err != nil {
		return EncryptedKeysharePacket{}, err
	}

	// verify
	refPin := p.getPin()
	// use hmac equal to make this constant time
	if !hmac.Equal(refPin[:], oldpin[:]) {
		return EncryptedKeysharePacket{}, ErrInvalidPin
	}

	// change and reencrypt
	p.setPin(newpin)
	return c.encryptPacket(p)
}

// Verify that a given access jwt is valid, and if so, return decrypted keyshare packet
//  Note: Although this is an internal function, it is tested directly
func (c *KeyshareCore) verifyAccess(ep EncryptedKeysharePacket, jwtToken string) (unencryptedKeysharePacket, error) {
	// Verify token validity
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, ErrInvalidJWT
		}

		return &c.signKey.PublicKey, nil
	})
	if err != nil {
		return unencryptedKeysharePacket{}, ErrInvalidJWT
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims.Valid() != nil {
		return unencryptedKeysharePacket{}, ErrInvalidJWT
	}
	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		return unencryptedKeysharePacket{}, ErrInvalidJWT
	}
	if _, present := claims["salt"]; !present {
		return unencryptedKeysharePacket{}, ErrInvalidJWT
	}
	if _, present := claims["hashed_pin"]; !present {
		return unencryptedKeysharePacket{}, ErrInvalidJWT
	}
	saltB64, ok := claims["salt"].(string)
	if !ok {
		return unencryptedKeysharePacket{}, ErrInvalidJWT
	}
	hashB64, ok := claims["hashed_pin"].(string)
	if !ok {
		return unencryptedKeysharePacket{}, ErrInvalidJWT
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return unencryptedKeysharePacket{}, ErrInvalidJWT
	}
	hash, err := base64.StdEncoding.DecodeString(hashB64)
	if err != nil {
		return unencryptedKeysharePacket{}, ErrInvalidJWT
	}

	p, err := c.decryptPacket(ep)
	if err != nil {
		return unencryptedKeysharePacket{}, err
	}
	refpin := p.getPin()
	refhash := sha256.Sum256(append(salt, refpin[:]...))

	if !hmac.Equal(refhash[:], hash) {
		return unencryptedKeysharePacket{}, ErrInvalidJWT
	}

	return p, nil
}

// Get keyshare commitment usign given idemix public key(s)
func (c *KeyshareCore) GenerateCommitments(ep EncryptedKeysharePacket, accessToken string, keyids []irma.PublicKeyIdentifier) ([]*gabi.ProofPCommitment, uint64, error) {
	// Validate input request and build key list
	var keylist []*gabi.PublicKey
	for _, keyid := range keyids {
		key, ok := c.trustedKeys[keyid]
		if !ok {
			return nil, 0, ErrKeyNotFound
		}
		keylist = append(keylist, key)
	}

	// verify access and decrypt
	p, err := c.verifyAccess(ep, accessToken)
	if err != nil {
		return nil, 0, err
	}

	// Generate commitment
	commitSecret, commitments, err := gabi.NewKeyshareCommitments(p.getKeyshareSecret(), keylist)
	if err != nil {
		return nil, 0, err
	}

	// Generate commitment id
	var commitId uint64
	binary.Read(rand.Reader, binary.LittleEndian, &commitId)

	// Store commit in backing storage
	c.commitmentMutex.Lock()
	c.commitmentData[commitId] = commitSecret
	c.commitmentMutex.Unlock()

	return commitments, commitId, nil
}

// Generate response for zero-knowledge proof of keyshare secret, for a given previous commit and challenge
func (c *KeyshareCore) GenerateResponse(ep EncryptedKeysharePacket, accessToken string, commitId uint64, challenge *big.Int, keyid irma.PublicKeyIdentifier) (string, error) {
	// Validate request
	if uint(challenge.BitLen()) > gabi.DefaultSystemParameters[1024].Lh || challenge.Cmp(big.NewInt(0)) < 0 {
		return "", ErrInvalidChallenge
	}
	key, ok := c.trustedKeys[keyid]
	if !ok {
		return "", ErrKeyNotFound
	}

	// verify access and decrypt
	p, err := c.verifyAccess(ep, accessToken)
	if err != nil {
		return "", err
	}

	// Fetch commit
	c.commitmentMutex.Lock()
	commit, ok := c.commitmentData[commitId]
	delete(c.commitmentData, commitId)
	c.commitmentMutex.Unlock()
	if !ok {
		return "", ErrUnknownCommit
	}

	// Generate response
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"ProofP": gabi.KeyshareResponse(p.getKeyshareSecret(), commit, challenge, key),
		"iat":    time.Now().Unix(),
		"sub":    "ProofP",
		"iss":    "keyshare_server",
	})
	return token.SignedString(c.signKey)
}

// Pad pin string into 64 bytes, extending it with 0s if neccessary
func padPin(pin string) ([64]byte, error) {
	data := []byte(pin)
	if len(data) > 64 {
		return [64]byte{}, ErrPinTooLong
	}
	res := [64]byte{}
	copy(res[:], data)
	return res, nil
}
