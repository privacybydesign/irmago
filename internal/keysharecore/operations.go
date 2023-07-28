package keysharecore

import (
	"crypto/ecdsa"
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
	ErrInvalidPin                = errors.New("invalid pin")
	ErrPinTooLong                = errors.New("pin too long")
	ErrInvalidChallenge          = errors.New("challenge out of bounds")
	ErrInvalidJWT                = errors.New("invalid jwt token")
	ErrExpiredJWT                = errors.New("jwt expired")
	ErrKeyNotFound               = errors.New("public key not found")
	ErrUnknownCommit             = errors.New("unknown commit id")
	ErrChallengeResponseRequired = errors.New("challenge-response authentication required")
	ErrWrongChallenge            = errors.New("wrong challenge")
)

// ChallengeJWTMaxExpiry is the maximum exp (expiry) that we allow JWTs to have with which calls to
// GenerateChallenge() (i.e. /users/verify_start) are authenticated.
const ChallengeJWTMaxExpiry = 6 * time.Minute

// NewUserSecrets generates a new keyshare secret, secured with the given pin.
func (c *Core) NewUserSecrets(pin string, pk *ecdsa.PublicKey) (UserSecrets, error) {
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
	s.PublicKey = pk

	// And encrypt
	return c.encryptUserSecrets(s)
}

// ValidateAuth checks pin for validity and generates JWT for future access.
func (c *Core) ValidateAuth(secrets UserSecrets, jwtt string) (string, error) {
	s, err := c.decryptUserSecrets(secrets)
	if err != nil {
		return "", err
	}

	pin, err := c.verifyChallengeResponse(s, jwtt)
	if err != nil {
		return "", err
	}

	if err = s.verifyPin(pin); err != nil {
		return "", err
	}

	return c.authJWT(&s)
}

func (c *Core) authJWT(s *unencryptedUserSecrets) (string, error) {
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

func (c *Core) verifyChallengeResponse(s unencryptedUserSecrets, jwtt string) (string, error) {
	challenge := c.consumeChallenge(s.ID)
	if challenge == nil {
		return "", ErrChallengeResponseRequired
	}

	claims := &irma.KeyshareAuthResponseClaims{}
	if _, err := jwt.ParseWithClaims(jwtt, claims, s.publicKey); err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare(challenge, claims.Challenge) != 1 {
		return "", ErrWrongChallenge
	}

	return claims.Pin, nil
}

// ValidateJWT checks whether the given JWT is currently valid as an access token for operations
// on the provided encrypted keyshare user secrets.
func (c *Core) ValidateJWT(secrets UserSecrets, jwt string) error {
	_, err := c.verifyAccess(secrets, jwt)
	return err
}

// ChangePin changes the pin in an encrypted keyshare user secret to a new value, after validating that
// the request was validly signed and that the old value is known by the caller.
func (c *Core) ChangePin(secrets UserSecrets, jwtt string) (UserSecrets, error) {
	s, err := c.decryptUserSecrets(secrets)
	if err != nil {
		return nil, err
	}

	claims := &irma.KeyshareChangePinClaims{}
	if _, err = jwt.ParseWithClaims(jwtt, claims, s.publicKey); err != nil {
		return nil, err
	}

	if err = s.verifyPin(claims.OldPin); err != nil {
		return nil, err
	}

	// change and reencrypt
	id := make([]byte, 32)
	_, err = rand.Read(id)
	if err != nil {
		return nil, err
	}
	if err = s.setPin(claims.NewPin); err != nil {
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
		return unencryptedUserSecrets{}, ErrExpiredJWT
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

// GeneratePs generates a list of keyshare server P's, i.e. a list of R_0^keyshareSecret.
func (c *Core) GeneratePs(secrets UserSecrets, accessToken string, keyIDs []irma.PublicKeyIdentifier) ([]*big.Int, error) {
	// Validate input request and build key list
	var keyList []*gabikeys.PublicKey
	for _, keyID := range keyIDs {
		key, ok := c.trustedKeys[keyID]
		if !ok {
			return nil, ErrKeyNotFound
		}
		keyList = append(keyList, key)
	}

	// Use verifyAccess to get the decrypted secrets. The access has already been verified in the
	// middleware. We use the call merely to fetch the unencryptedUserSecrets here.
	s, err := c.verifyAccess(secrets, accessToken)
	if err != nil {
		return nil, err
	}

	var ps []*big.Int

	for _, key := range keyList {
		ps = append(ps,
			new(big.Int).Exp(key.R[0], s.KeyshareSecret, key.N))
	}

	return ps, nil
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

	// Use verifyAccess to get the decrypted secrets. The access has already been verified in the
	// middleware. We use the call merely to fetch the unencryptedUserSecrets here.
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

	// Use verifyAccess to get the decrypted secrets. The access has already been verified in the
	// middleware. We use the call merely to fetch the unencryptedUserSecrets here.
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
		"ProofP": gabi.KeyshareResponseLegacy(s.KeyshareSecret, commit, challenge, key),
		"iat":    time.Now().Unix(),
		"sub":    "ProofP",
		"iss":    c.jwtIssuer,
	})
	token.Header["kid"] = c.jwtPrivateKeyID
	return token.SignedString(c.jwtPrivateKey)
}

// GenerateResponseV2 generates the response of a zero-knowledge proof of the keyshare secret, for a given previous commit and response request.
// In older versions of the IRMA protocol (2.8 or below), issuers need a response that is linkable to earlier issuance sessions. In this case,
// the ProofP.P will be set as well. The linkable parameter indicates whether the ProofP.P should be included.
func (c *Core) GenerateResponseV2(
	secrets UserSecrets,
	accessToken string,
	commitID uint64,
	hashedComms gabi.KeyshareCommitmentRequest,
	req gabi.KeyshareResponseRequest[irma.PublicKeyIdentifier],
	keyID irma.PublicKeyIdentifier,
	linkable bool) (string, error) {
	// Validate request
	key, ok := c.trustedKeys[keyID]
	if !ok {
		return "", ErrKeyNotFound
	}

	// Use verifyAccess to get the decrypted secrets. The access has already been verified in the
	// middleware. We use the call merely to fetch the unencryptedUserSecrets here.
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

	proofP, err := gabi.KeyshareResponse(s.KeyshareSecret, commit, hashedComms, req, c.trustedKeys)
	if err != nil {
		return "", err
	}

	if uint(proofP.C.BitLen()) > gabikeys.DefaultSystemParameters[1024].Lh || proofP.C.Cmp(big.NewInt(0)) < 0 {
		return "", ErrInvalidChallenge
	}

	// Set Proof.P to R_0^userSecret if the response should be linkable.
	if linkable {
		proofP.P = new(big.Int).Exp(key.R[0], s.KeyshareSecret, key.N)
	}

	// Generate response
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"ProofP": proofP,
		"iat":    time.Now().Unix(),
		"sub":    "ProofP",
		"iss":    c.jwtIssuer,
	})
	token.Header["kid"] = c.jwtPrivateKeyID
	return token.SignedString(c.jwtPrivateKey)
}

func (c *Core) GenerateChallenge(secrets UserSecrets, jwtt string) ([]byte, error) {
	s, err := c.decryptUserSecrets(secrets)
	if err != nil {
		return nil, err
	}

	if s.PublicKey == nil {
		return nil, errors.New("can't do challenge-response: no public key associated to account")
	}

	claims := &irma.KeyshareAuthRequestClaims{}
	if _, err = jwt.ParseWithClaims(jwtt, claims, s.publicKey); err != nil {
		return nil, err
	}
	// Impose explicit maximum on JWT expiry; we don't want eternally valid JWTs.
	if claims.ExpiresAt == nil || claims.ExpiresAt.After(time.Now().Add(ChallengeJWTMaxExpiry)) {
		return nil, errors.Errorf("JWT expiry may not be more than %s from now", ChallengeJWTMaxExpiry)
	}

	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	if err != nil {
		return nil, err
	}

	c.authChallengesMutex.Lock()
	defer c.authChallengesMutex.Unlock()
	c.authChallenges[string(s.ID)] = challenge
	return challenge, nil
}

func (c *Core) consumeChallenge(id []byte) []byte {
	c.authChallengesMutex.Lock()
	defer c.authChallengesMutex.Unlock()
	stringID := string(id)
	challenge := c.authChallenges[stringID]
	delete(c.authChallenges, stringID)
	return challenge
}

func (c *Core) SetUserPublicKey(secrets UserSecrets, pin string, pk *ecdsa.PublicKey) (string, UserSecrets, error) {
	s, err := c.decryptUserSecretsIfPinOK(secrets, pin)
	if err != nil {
		return "", nil, err
	}

	if s.PublicKey != nil {
		return "", nil, errors.New("user already has public key")
	}

	s.PublicKey = pk
	secrets, err = c.encryptUserSecrets(s)
	if err != nil {
		return "", nil, err
	}
	jwtt, err := c.authJWT(&s)
	if err != nil {
		return "", nil, err
	}
	return jwtt, secrets, nil
}
