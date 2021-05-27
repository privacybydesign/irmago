package keysharecore

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"time"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	irma "github.com/privacybydesign/irmago"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
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
func (c *Core) NewUser(pinRaw string) (User, error) {
	secret, err := gabi.NewKeyshareSecret()
	if err != nil {
		return User{}, err
	}

	return c.newUserFromSecret(pinRaw, secret)
}

func (c *Core) newUserFromSecret(pinRaw string, secret *big.Int) (User, error) {
	pin, err := padPin(pinRaw)
	if err != nil {
		return User{}, err
	}

	var id [32]byte
	_, err = rand.Read(id[:])
	if err != nil {
		return User{}, err
	}

	// Build unencrypted packet
	var p unencryptedUser
	p.setPin(pin)
	err = p.setKeyshareSecret(secret)
	if err != nil {
		return User{}, err
	}
	p.setID(id)

	// And encrypt
	return c.encryptUser(p)
}

// Check pin for validity, and generate jwt for future access
func (c *Core) ValidatePin(ep User, pin string, userID string) (string, error) {
	p, err := c.decryptUserIfPinOK(ep, pin)
	if err != nil {
		return "", err
	}

	// Generate jwt token
	id := p.id()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":      c.jwtIssuer,
		"sub":      "auth_tok",
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Duration(c.jwtPinExpiry) * time.Second).Unix(),
		"token_id": base64.StdEncoding.EncodeToString(id[:]),
	})
	token.Header["kid"] = c.jwtPrivateKeyID
	return token.SignedString(c.jwtPrivateKey)
}

// Check whether the given JWT is currently valid as an access token for operations on the provided encrypted keyshare packet
func (c *Core) ValidateJWT(ep User, jwt string) error {
	_, err := c.verifyAccess(ep, jwt)
	return err
}

// Change pin in an encrypted keyshare packet to a new value, after validating that the old value is known by caller.
func (c *Core) ChangePin(ep User, oldpinRaw, newpinRaw string) (User, error) {
	p, err := c.decryptUserIfPinOK(ep, oldpinRaw)
	if err != nil {
		return User{}, err
	}

	newpin, err := padPin(newpinRaw)
	if err != nil {
		return User{}, err
	}

	// change and reencrypt
	var id [32]byte
	_, err = rand.Read(id[:])
	if err != nil {
		return User{}, err
	}
	p.setPin(newpin)
	p.setID(id)
	return c.encryptUser(p)
}

// Verify that a given access jwt is valid, and if so, return decrypted keyshare packet
//  Note: Although this is an internal function, it is tested directly
func (c *Core) verifyAccess(ep User, jwtToken string) (unencryptedUser, error) {
	// Verify token validity
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, ErrInvalidJWT
		}

		return &c.jwtPrivateKey.PublicKey, nil
	})
	if err != nil {
		return unencryptedUser{}, ErrInvalidJWT
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims.Valid() != nil {
		return unencryptedUser{}, ErrInvalidJWT
	}
	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		return unencryptedUser{}, ErrInvalidJWT
	}
	if _, present := claims["token_id"]; !present {
		return unencryptedUser{}, ErrInvalidJWT
	}
	tokenIDB64, ok := claims["token_id"].(string)
	if !ok {
		return unencryptedUser{}, ErrInvalidJWT
	}
	tokenID, err := base64.StdEncoding.DecodeString(tokenIDB64)
	if err != nil {
		return unencryptedUser{}, ErrInvalidJWT
	}

	p, err := c.decryptUser(ep)
	if err != nil {
		return unencryptedUser{}, err
	}
	refId := p.id()

	if subtle.ConstantTimeCompare(refId[:], tokenID) != 1 {
		return unencryptedUser{}, ErrInvalidJWT
	}

	return p, nil
}

// Get keyshare commitment usign given idemix public key(s)
func (c *Core) GenerateCommitments(ep User, accessToken string, keyIDs []irma.PublicKeyIdentifier) ([]*gabi.ProofPCommitment, uint64, error) {
	// Validate input request and build key list
	var keyList []*gabikeys.PublicKey
	for _, keyID := range keyIDs {
		key, ok := c.trustedKeys[keyID]
		if !ok {
			return nil, 0, ErrKeyNotFound
		}
		keyList = append(keyList, key)
	}

	// verify access and decrypt
	p, err := c.verifyAccess(ep, accessToken)
	if err != nil {
		return nil, 0, err
	}

	// Generate commitment
	commitSecret, commitments, err := gabi.NewKeyshareCommitments(p.keyshareSecret(), keyList)
	if err != nil {
		return nil, 0, err
	}

	// Generate commitment id
	var commitID uint64
	err = binary.Read(rand.Reader, binary.LittleEndian, &commitID)
	if err != nil {
		return nil, 0, err
	}

	// Store commit in backing storage
	c.commitmentMutex.Lock()
	c.commitmentData[commitID] = commitSecret
	c.commitmentMutex.Unlock()

	return commitments, commitID, nil
}

// Generate response for zero-knowledge proof of keyshare secret, for a given previous commit and challenge
func (c *Core) GenerateResponse(ep User, accessToken string, commitID uint64, challenge *big.Int, keyID irma.PublicKeyIdentifier) (string, error) {
	// Validate request
	if uint(challenge.BitLen()) > gabikeys.DefaultSystemParameters[1024].Lh || challenge.Cmp(big.NewInt(0)) < 0 {
		return "", ErrInvalidChallenge
	}
	key, ok := c.trustedKeys[keyID]
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
	commit, ok := c.commitmentData[commitID]
	delete(c.commitmentData, commitID)
	c.commitmentMutex.Unlock()
	if !ok {
		return "", ErrUnknownCommit
	}

	// Generate response
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"ProofP": gabi.KeyshareResponse(p.keyshareSecret(), commit, challenge, key),
		"iat":    time.Now().Unix(),
		"sub":    "ProofP",
		"iss":    c.jwtIssuer,
	})
	token.Header["kid"] = c.jwtPrivateKeyID
	return token.SignedString(c.jwtPrivateKey)
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
