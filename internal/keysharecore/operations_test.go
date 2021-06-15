package keysharecore

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
)

func TestPinFunctionality(t *testing.T) {
	// Setup keys for test
	var key AESKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c := NewKeyshareCore(&Configuration{DecryptionKeyID: 1, DecryptionKey: key, JWTPrivateKeyID: 1, JWTPrivateKey: jwtTestKey})

	// generate test pin
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	require.NoError(t, err)
	pin := string(bpin[:])

	// Generate package
	ep, err := c.NewUserSecrets(pin)
	require.NoError(t, err)

	// Test with correct pin
	j, err := c.ValidatePin(ep, pin)
	assert.NoError(t, err)
	var claims jwt.StandardClaims
	_, err = jwt.ParseWithClaims(j, &claims, func(_ *jwt.Token) (interface{}, error) {
		return &jwtTestKey.PublicKey, nil
	})
	assert.NoError(t, err)
	assert.Equal(t, "auth_tok", claims.Subject)
	assert.Equal(t, time.Now().Unix()+JWTPinExpiryDefault, claims.ExpiresAt)
	assert.Equal(t, JWTIssuerDefault, claims.Issuer)

	// test change pin
	var bnewpin [64]byte
	_, err = rand.Read(bnewpin[:])
	require.NoError(t, err)
	newpin := string(bnewpin[:])
	ep, err = c.ChangePin(ep, pin, newpin)
	require.NoError(t, err)

	// test correct pin
	_, err = c.ValidatePin(ep, newpin)
	assert.NoError(t, err)

	// Test incorrect pin
	_, err = c.ValidatePin(ep, pin)
	assert.Error(t, err)
}

func TestVerifyAccess(t *testing.T) {
	// Setup keys for test
	var key AESKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c := NewKeyshareCore(&Configuration{DecryptionKeyID: 1, DecryptionKey: key, JWTPrivateKeyID: 1, JWTPrivateKey: jwtTestKey})

	// Generate test pins
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	require.NoError(t, err)
	pin1 := string(bpin[:])
	_, err = rand.Read(bpin[:])
	require.NoError(t, err)
	pin2 := string(bpin[:])

	// and test keyshare secrets
	ep1, err := c.NewUserSecrets(pin1)
	require.NoError(t, err)
	ep2, err := c.NewUserSecrets(pin2)
	require.NoError(t, err)

	// Test use jwt on wrong packet
	jwtt, err := c.ValidatePin(ep1, pin1)
	require.NoError(t, err)
	_, err = c.verifyAccess(ep2, jwtt)
	assert.Error(t, err)

	// Test incorrectly constructed jwts
	p, err := c.verifyAccess(ep1, jwtt)
	require.NoError(t, err)
	id := p.id()
	tokenID := base64.StdEncoding.EncodeToString(id[:])

	// incorrect exp
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat":      time.Now().Add(-6 * time.Minute).Unix(),
		"exp":      time.Now().Add(-3 * time.Minute).Unix(),
		"token_id": tokenID,
	})
	jwtt, err = token.SignedString(c.jwtPrivateKey)
	require.NoError(t, err)
	_, err = c.verifyAccess(ep1, jwtt)
	assert.Error(t, err)

	// missing exp
	token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat":      time.Now().Unix(),
		"token_id": tokenID,
	})
	jwtt, err = token.SignedString(c.jwtPrivateKey)
	require.NoError(t, err)
	_, err = c.verifyAccess(ep1, jwtt)
	assert.Error(t, err)

	// Incorrectly typed exp
	token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat":      time.Now().Unix(),
		"exp":      "test",
		"token_id": tokenID,
	})
	jwtt, err = token.SignedString(c.jwtPrivateKey)
	require.NoError(t, err)
	_, err = c.verifyAccess(ep1, jwtt)
	assert.Error(t, err)

	// missing token_id
	token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(3 * time.Minute).Unix(),
	})
	jwtt, err = token.SignedString(c.jwtPrivateKey)
	require.NoError(t, err)
	_, err = c.verifyAccess(ep1, jwtt)
	assert.Error(t, err)

	// mistyped token_id
	token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(3 * time.Minute).Unix(),
		"token_id": 7,
	})
	jwtt, err = token.SignedString(c.jwtPrivateKey)
	require.NoError(t, err)
	_, err = c.verifyAccess(ep1, jwtt)
	assert.Error(t, err)

	// Incorrect signing method
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(3 * time.Minute).Unix(),
		"token_id": tokenID,
	})
	jwtt, err = token.SignedString([]byte("bla"))
	require.NoError(t, err)
	_, err = c.verifyAccess(ep1, jwtt)
	assert.Error(t, err)
}

func TestProofFunctionality(t *testing.T) {
	// Setup keys for test
	var key AESKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c := NewKeyshareCore(&Configuration{DecryptionKeyID: 1, DecryptionKey: key, JWTPrivateKeyID: 1, JWTPrivateKey: jwtTestKey})
	c.DangerousAddTrustedPublicKey(irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}, testPubK1)

	// generate test pin
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	require.NoError(t, err)
	pin := string(bpin[:])

	// generate keyshare secret
	ep, err := c.NewUserSecrets(pin)
	require.NoError(t, err)

	// Validate pin
	jwtt, err := c.ValidatePin(ep, pin)
	require.NoError(t, err)

	// Get keyshare commitment
	W, commitID, err := c.GenerateCommitments(ep, jwtt, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	require.NoError(t, err)

	// Get keyshare response
	Rjwt, err := c.GenerateResponse(ep, jwtt, commitID, big.NewInt(12345), irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1})
	require.NoError(t, err)

	// Decode jwt
	claims := &struct {
		jwt.StandardClaims
		ProofP *gabi.ProofP
	}{}
	fmt.Println(Rjwt)
	_, err = jwt.ParseWithClaims(Rjwt, claims, func(tok *jwt.Token) (interface{}, error) {
		return &c.jwtPrivateKey.PublicKey, nil
	})
	require.NoError(t, err)

	// Validate protocol execution
	assert.Equal(t, 0, new(big.Int).Exp(testPubK1.R[0], claims.ProofP.SResponse, testPubK1.N).Cmp(
		new(big.Int).Mod(
			new(big.Int).Mul(
				W[0].Pcommit,
				new(big.Int).Exp(W[0].P, big.NewInt(12345), testPubK1.N)),
			testPubK1.N)), "Crypto result off")
}

func TestCorruptedPacket(t *testing.T) {
	// Setup keys for test
	var key AESKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c := NewKeyshareCore(&Configuration{DecryptionKeyID: 1, DecryptionKey: key, JWTPrivateKeyID: 1, JWTPrivateKey: jwtTestKey})
	c.DangerousAddTrustedPublicKey(irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}, testPubK1)

	// Test parameters
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	require.NoError(t, err)
	pin := string(bpin[:])

	// Generate packet
	ep, err := c.NewUserSecrets(pin)
	require.NoError(t, err)

	jwtt, err := c.ValidatePin(ep, pin)
	require.NoError(t, err)

	_, commitID, err := c.GenerateCommitments(ep, jwtt, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	require.NoError(t, err)

	// Corrupt packet
	ep[12] = ep[12] + 1

	// Verify pin
	_, err = c.ValidatePin(ep, pin)
	assert.Error(t, err, "ValidatePin accepts corrupted keyshare packet")

	// Change pin
	_, err = c.ChangePin(ep, pin, pin)
	assert.Error(t, err, "ChangePin accepts corrupted keyshare packet")

	// GenerateCommitments
	_, _, err = c.GenerateCommitments(ep, jwtt, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	assert.Error(t, err, "GenerateCommitments accepts corrupted keyshare packet")

	// GetResponse
	_, err = c.GenerateResponse(ep, jwtt, commitID, big.NewInt(12345), irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1})
	assert.Error(t, err, "GenerateResponse accepts corrupted keyshare packet")
}

func TestIncorrectPin(t *testing.T) {
	// Setup keys for test
	var key AESKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c := NewKeyshareCore(&Configuration{DecryptionKeyID: 1, DecryptionKey: key, JWTPrivateKeyID: 1, JWTPrivateKey: jwtTestKey})
	c.DangerousAddTrustedPublicKey(irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}, testPubK1)

	// Test parameters
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	require.NoError(t, err)
	pin := string(bpin[:])

	// Generate packet
	ep, err := c.NewUserSecrets(pin)
	require.NoError(t, err)

	// validate pin
	jwtt, err := c.ValidatePin(ep, pin)
	require.NoError(t, err)

	// Corrupt pin
	bpin[12] = bpin[12] + 1
	pin = string(bpin[:])

	// Change pin
	_, err = c.ChangePin(ep, pin, pin)
	assert.Error(t, err, "ChangePin accepts incorrect pin")

	// GetResponse
	_, commitID, err := c.GenerateCommitments(ep, jwtt, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	require.NoError(t, err)
	_, err = c.GenerateResponse(ep, "pin", commitID, big.NewInt(12345), irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1})
	assert.Error(t, err, "GenerateResponse accepts incorrect pin")
}

func TestMissingKey(t *testing.T) {
	// Setup keys for test
	var key AESKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c := NewKeyshareCore(&Configuration{DecryptionKeyID: 1, DecryptionKey: key, JWTPrivateKeyID: 1, JWTPrivateKey: jwtTestKey})
	c.DangerousAddTrustedPublicKey(irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}, testPubK1)

	// Test parameters
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	require.NoError(t, err)
	pin := string(bpin[:])

	// Generate packet
	ep, err := c.NewUserSecrets(pin)
	require.NoError(t, err)

	// Generate jwt
	jwtt, err := c.ValidatePin(ep, pin)
	require.NoError(t, err)

	// GenerateCommitments
	_, _, err = c.GenerateCommitments(ep, jwtt, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("DNE"), Counter: 1}})
	assert.Error(t, err, "Missing key not detected by generateCommitments")

	// GenerateResponse
	_, commitID, err := c.GenerateCommitments(ep, jwtt, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	require.NoError(t, err)
	_, err = c.GenerateResponse(ep, jwtt, commitID, big.NewInt(12345), irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("DNE"), Counter: 1})
	assert.Error(t, err, "Missing key not detected by generateresponse")
}

func TestInvalidChallenge(t *testing.T) {
	// Setup keys for test
	var key AESKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c := NewKeyshareCore(&Configuration{DecryptionKeyID: 1, DecryptionKey: key, JWTPrivateKeyID: 1, JWTPrivateKey: jwtTestKey})
	c.DangerousAddTrustedPublicKey(irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}, testPubK1)

	// Test parameters
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	require.NoError(t, err)
	pin := string(bpin[:])

	// Generate packet
	ep, err := c.NewUserSecrets(pin)
	require.NoError(t, err)

	// Validate pin
	jwtt, err := c.ValidatePin(ep, pin)
	require.NoError(t, err)

	// Test negative challenge
	_, commitID, err := c.GenerateCommitments(ep, jwtt, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	require.NoError(t, err)
	_, err = c.GenerateResponse(ep, jwtt, commitID, big.NewInt(-1), irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1})
	assert.Error(t, err, "GenerateResponse incorrectly accepts negative challenge")

	// Test too large challenge
	_, commitID, err = c.GenerateCommitments(ep, jwtt, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	require.NoError(t, err)
	_, err = c.GenerateResponse(ep, jwtt, commitID, new(big.Int).Lsh(big.NewInt(1), 256), irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1})
	assert.Error(t, err, "GenerateResponse accepts challenge that is too small")

	// Test just-right challenge
	_, commitID, err = c.GenerateCommitments(ep, jwtt, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	require.NoError(t, err)
	_, err = c.GenerateResponse(ep, jwtt, commitID, new(big.Int).Lsh(big.NewInt(1), 255), irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1})
	assert.NoError(t, err, "GenerateResponse does not accept challenge of 256 bits")
}

func TestDoubleCommitUse(t *testing.T) {
	// Setup keys for test
	var key AESKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c := NewKeyshareCore(&Configuration{DecryptionKeyID: 1, DecryptionKey: key, JWTPrivateKeyID: 1, JWTPrivateKey: jwtTestKey})
	c.DangerousAddTrustedPublicKey(irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}, testPubK1)

	// Test parameters
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	require.NoError(t, err)
	pin := string(bpin[:])

	// Generate packet
	ep, err := c.NewUserSecrets(pin)
	require.NoError(t, err)

	// validate pin
	jwtt, err := c.ValidatePin(ep, pin)
	require.NoError(t, err)

	// Use commit double
	_, commitID, err := c.GenerateCommitments(ep, jwtt, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	require.NoError(t, err)
	_, err = c.GenerateResponse(ep, jwtt, commitID, big.NewInt(12345), irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1})
	require.NoError(t, err)
	_, err = c.GenerateResponse(ep, jwtt, commitID, big.NewInt(12346), irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1})
	assert.Error(t, err, "GenerateResponse incorrectly allows double use of commit")
}

func TestNonExistingCommit(t *testing.T) {
	// Setup keys for test
	var key AESKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c := NewKeyshareCore(&Configuration{DecryptionKeyID: 1, DecryptionKey: key, JWTPrivateKeyID: 1, JWTPrivateKey: jwtTestKey})
	c.DangerousAddTrustedPublicKey(irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}, testPubK1)

	// Test parameters
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	require.NoError(t, err)
	pin := string(bpin[:])

	// Generate packet
	ep, err := c.NewUserSecrets(pin)
	require.NoError(t, err)

	// Generate jwt
	jwtt, err := c.ValidatePin(ep, pin)
	require.NoError(t, err)

	// test
	_, err = c.GenerateResponse(ep, jwtt, 2364, big.NewInt(12345), irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1})
	assert.Error(t, err, "GenerateResponse failed to detect non-existing commit")
}

// Test data
const xmlPubKey1 = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<IssuerPublicKey xmlns="http://www.zurich.ibm.com/security/idemix">
   <Counter>0</Counter>
   <ExpiryDate>1700000000</ExpiryDate>
   <Elements>
      <n>164849270410462350104130325681247905590883554049096338805080434441472785625514686982133223499269392762578795730418568510961568211704176723141852210985181059718962898851826265731600544499072072429389241617421101776748772563983535569756524904424870652659455911012103327708213798899264261222168033763550010103177</n>
      <Z>85612209073231549357971504917706448448632620481242156140921956689865243071517333286408980597347754869291449755693386875207418733579434926868804114639149514414312088911027338251870409643059636340634892197874721564672349336579075665489514404442681614964231517891268285775435774878821304200809336437001672124945</Z>
      <S>95431387101397795194125116418957121488151703839429468857058760824105489778492929250965841783742048628875926892511288385484169300700205687919208898288594042075246841706909674758503593474606503299796011177189518412713004451163324915669592252022175131604797186534801966982736645522331999047305414834481507220892</S>
      <Bases num="6">
         <Base_0>15948796959221892486955992453179199515496923441128830967123361439118018661581037984810048354811434050038778558011395590650011565629310700360843433067202313291361609843998531962373969946197182940391414711398289105131565252299185121868561402842968555939684308560329951491463967030905495360286851791764439565922</Base_0>
         <Base_1>119523438901119086528333705353116973341573129722743063979885442255495816390473126070276442804547475203517104656193873407665058481273192071865721910619056848142740067272069428460724210705091048104466624895000063564223095487133194907203681789863578060886235105842841954519189942453426975057803871974937309502784</Base_1>
         <Base_2>21036812778930907905009726679774009067486097699134635274413938052367886222555608567065065339702690960558290977766511663461460906408225144877806673612081001465755091058944847078216758263034300782760502281865270151054157854728772298542643419836244547728225955304279190350362963560596454003412543292789187837679</Base_2>
         <Base_3>2507221674373339204944916721547102290807064604358409729371715856726643784893285066715992395214052930640947278288383410209092118436778149456628267900567208684458410552361708506911626161349456189054709967676518205745736652492505957876189855916223094854626710186459345996698113370306994139940441752005221653088</Base_3>
         <Base_4>43215325590379490852400435325847836613513274803460964568083232110934910151335113918829588414147781676586145312074043749201037447486205927144941119404243266454032858201713735324770837218773739346063812751896736791478531103409536739098007890723770126159814845238386299865793353073058783010002988453373168625327</Base_4>
         <Base_5>61146634020942775692657595021461289090915429142715194304483397998858712705680675945417056124974172620475325240482216550923967273908399017396442709297466408094303826941548068001214817725191465207971123378222070812822903173820970991987799984521470178624084174451047081964996323127069438975310975798326710264763</Base_5>
      </Bases>
   </Elements>
   <Features>
      <Epoch length="432000"></Epoch>
   </Features>
</IssuerPublicKey>`
const jwtTestKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAupnB9rJjQ15cWWPJdOagkcii6kB2w7ojAoPidWQLR4dxhd4z
LeDAkPqgGiBAEL84bZwwv2pfLiTDd+ks20nS4gYC9UAVVKfP+mf99I3fyzCLmMvq
toFqJkH7Xm0UYuko1HaUdXpZMCbqUa/snmwzYHtUgxu7SPqW7Ywuai4jPgmDW0pX
Fqi4BRX8VNbmbd9Ck9OvnymA1VYsfTqublIvoQy7B70srKV8dl2w2pdL64dDSqwM
+wDuO/vnfzeGbtQ/VVfS8YoLHawtWV4Jwqa3CjjpuyFFoC/4pL/izpzEqNFK0Xs5
opr9FezghpxK6uQ18JfXTeJqAioLUtWmAMABuQIDAQABAoIBAQC4kg3BLoHwyQ0f
fgxujRCWIpbCjjDrONoYSstcwjBF+DrZ5wdIgd73iG+EaBH2fq4Z/TxamaS7x7Fw
kjvETClDWB7k5xYyPisBzIrtsseB++qYoFrxWuDcJre0lsBrdaTlQsVlzjcZ4eQ0
GIc7zFqlPFhDttJxRSy0msvuSuShHqdCpNFXyMvPCqesUt+sbdl6NXVQvb3I2IS3
1rKdWR7ta1ZjZmMpMgMZ6ovsI2gN1TfKfHVky2cZ2b4lvNaCugVLdn+0rjTpowa5
jupKiyruN1zbeqoYiZadxsnm+vvLarUWb18/DwomXLfWOhMxRZoFr+DtHB3Umasm
WDsiIrGBAoGBAOA5Ts9ybNbHpbFCHAxxPqeRIGnZ58/QhKe1/P7muh2cQJLl8B0Z
ak5R31sChRJMObWRGoBLQhV6lo9g7x3BXKeSIjopylRQaineK1VbCT6fR7khyL71
+jtr536HsDWpIsv3ziiaPBfGy8QyN37LV2G9b9Wq+PLVD/kSvRmEtKEtAoGBANUL
gO6uNXvboc4QEOVMyghSqr6G6Tx6GWckdYhmuOkUZUYuo/7M/qmHvLV7YRjKwSGN
AVvGdTgVRchW6vB3kSbTn3QGV+R0YuaWQE5iaYqD5EmkJw+DnroQs1WIJRFj7tE9
rsAIqWtelTkRYH68+eAxOLmFWjXOk6y1rC2ZyEI9AoGAXckaocJmq9+N+nqAaOPl
JQma2St/vnilQ9DnJWc0abY1fDwZFtLOmDu+hL6lEmY3rS4oO4k+9uTznL0axwNd
0elZz6IzMtj/zstSrL0LPNo6kcEDynvwUnJrvYzbs1Yva8kWvfzlLbzE9ida9vnu
br9hy6lbv5ZGvBOObOII+3ECgYEAwBWEJS87F7ZZ9+GyahvHGKP4QJqBFj78Qmuz
8My1Malq+lE5GZYYkh/JPFPGosTERwzMScPwkiVT6qK7Zx5W6Avr+39wpZFuTnrv
9fxzLilmniL7+NfyN86w8pAy47AXdd7IfWoR3rXDk1WgjAS0wrd+bn7WbCcaLKEM
YX0C+v0CgYAzlSjQztVCaKu1fghDEPk6C0frcDlqzhKYCEDs19sA34Clb1wCefnA
bZZZrudDjQx3an4epG7FCKkCcE4WMNOdhl0zDbcvbTV2pP21dcof3x4xmCjDCV6I
ZAS54R1mcyP67iBPxixiKeFqajUS+C4GFBrNSXbQTWf+jTyWkgfNSg==
-----END RSA PRIVATE KEY-----`

var jwtTestKey *rsa.PrivateKey
var testPubK1 *gabikeys.PublicKey

func setupParameters() error {
	var err error
	testPubK1, err = gabikeys.NewPublicKeyFromXML(xmlPubKey1)
	if err != nil {
		return err
	}
	jwtTestKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(jwtTestKeyPem))
	if err != nil {
		return err
	}
	return nil
}

func TestMain(m *testing.M) {
	err := setupParameters()
	if err != nil {
		os.Exit(1)
	}
	os.Exit(m.Run())
}
