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

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v4"
)

var (
	ErrInvalidPin       = errors.New("invalid pin")
	ErrPinTooLong       = errors.New("pin too long")
	ErrInvalidChallenge = errors.New("challenge out of bounds")
	ErrInvalidJWT       = errors.New("invalid jwt token")
	ErrKeyNotFound      = errors.New("public key not found")
	ErrUnknownCommit    = errors.New("unknown commit id")
)

// NewUserSecrets generates a new keyshare secret, secured with the given pin.
func (c *Core) NewUserSecrets(pin string) (UserSecrets, error) {
	secret, err := gabi.NewKeyshareSecret()
	if err != nil {
		return nil, err
	}

	id := make([]byte, 32)
	_, err = rand.Read(id)
	if err != nil {
		return nil, err
	}

	// Build unencrypted secrets
	var s unencryptedUserSecrets
	if err = s.setPin(pin); err != nil {
		return nil, err
	}
	if err = s.setKeyshareSecret(secret); err != nil {
		return nil, err
	}
	if err = s.setID(id); err != nil {
		return nil, err
	}

	// And encrypt
	return c.encryptUserSecrets(s)
}

// ValidatePin checks pin for validity and generates JWT for future access.
func (c *Core) ValidatePin(secrets UserSecrets, pin string) (string, error) {
	s, err := c.decryptUserSecretsIfPinOK(secrets, pin)
	if err != nil {
		return "", err
	}

	// Generate jwt token
	t := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":      c.jwtIssuer,
		"sub":      "auth_tok",
		"iat":      t.Unix(),
		"exp":      t.Add(time.Duration(c.jwtPinExpiry) * time.Second).Unix(),
		"token_id": base64.StdEncoding.EncodeToString(s.ID),
	})
	token.Header["kid"] = c.jwtPrivateKeyID
	return token.SignedString(c.jwtPrivateKey)
}

// ValidateJWT checks whether the given JWT is currently valid as an access token for operations
// on the provided encrypted keyshare user secrets.
func (c *Core) ValidateJWT(secrets UserSecrets, jwt string) error {
	_, err := c.verifyAccess(secrets, jwt)
	return err
}

// ChangePin changes the pin in an encrypted keyshare user secret to a new value, after validating that
// the old value is known by the caller.
func (c *Core) ChangePin(secrets UserSecrets, oldpinRaw, newpinRaw string) (UserSecrets, error) {
	s, err := c.decryptUserSecretsIfPinOK(secrets, oldpinRaw)
	if err != nil {
		return nil, err
	}

	// change and reencrypt
	id := make([]byte, 32)
	_, err = rand.Read(id)
	if err != nil {
		return nil, err
	}
	if err = s.setPin(newpinRaw); err != nil {
		return nil, err
	}
	if err = s.setID(id); err != nil {
		return nil, err
	}
	return c.encryptUserSecrets(s)
}

// verifyAccess checks that a given access jwt is valid, and if so, return decrypted keyshare user secrets.
// Note: Although this is an internal function, it is tested directly
func (c *Core) verifyAccess(secrets UserSecrets, jwtToken string) (unencryptedUserSecrets, error) {
	// Verify token validity
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, ErrInvalidJWT
		}

		return &c.jwtPrivateKey.PublicKey, nil
	})
	if err != nil {
		return unencryptedUserSecrets{}, ErrInvalidJWT
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims.Valid() != nil {
		return unencryptedUserSecrets{}, ErrInvalidJWT
	}
	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		return unencryptedUserSecrets{}, ErrInvalidJWT
	}
	if _, present := claims["token_id"]; !present {
		return unencryptedUserSecrets{}, ErrInvalidJWT
	}
	tokenIDB64, ok := claims["token_id"].(string)
	if !ok {
		return unencryptedUserSecrets{}, ErrInvalidJWT
	}
	tokenID, err := base64.StdEncoding.DecodeString(tokenIDB64)
	if err != nil {
		return unencryptedUserSecrets{}, ErrInvalidJWT
	}

	s, err := c.decryptUserSecrets(secrets)
	if err != nil {
		return unencryptedUserSecrets{}, err
	}

	if subtle.ConstantTimeCompare(s.ID, tokenID) != 1 {
		return unencryptedUserSecrets{}, ErrInvalidJWT
	}

	return s, nil
}

// GenerateCommitments generates keyshare commitments using the specified Idemix public key(s).
func (c *Core) GenerateCommitments(secrets UserSecrets, accessToken string, keyIDs []irma.PublicKeyIdentifier) ([]*gabi.ProofPCommitment, uint64, error) {
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
	s, err := c.verifyAccess(secrets, accessToken)
	if err != nil {
		return nil, 0, err
	}

	// Generate commitment
	commitSecret, commitments, err := gabi.NewKeyshareCommitments(s.KeyshareSecret, keyList)
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

// GenerateResponse generates the response of a zero-knowledge proof of the keyshare secret, for a given previous commit and challenge.
func (c *Core) GenerateResponse(secrets UserSecrets, accessToken string, commitID uint64, challenge *big.Int, keyID irma.PublicKeyIdentifier) (string, error) {
	// Validate request
	if uint(challenge.BitLen()) > gabikeys.DefaultSystemParameters[1024].Lh || challenge.Cmp(big.NewInt(0)) < 0 {
		return "", ErrInvalidChallenge
	}
	key, ok := c.trustedKeys[keyID]
	if !ok {
		return "", ErrKeyNotFound
	}

	// verify access and decrypt
	s, err := c.verifyAccess(secrets, accessToken)
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
		"ProofP": gabi.KeyshareResponse(s.KeyshareSecret, commit, challenge, key),
		"iat":    time.Now().Unix(),
		"sub":    "ProofP",
		"iss":    c.jwtIssuer,
	})
	token.Header["kid"] = c.jwtPrivateKeyID
	return token.SignedString(c.jwtPrivateKey)
}
