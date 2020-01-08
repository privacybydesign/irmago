package keyshareCore

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
)

func TestPinFunctionality(t *testing.T) {
	// Setup keys for test
	_, err := rand.Read(encryptionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptionKeyID = 1
	decryptionKeys[encryptionKeyID] = encryptionKey

	// generate test pin
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	if err != nil {
		t.Fatal(err)
	}
	pin := string(bpin[:])

	// Generate package
	ep, err := GenerateKeyshareSecret(pin)
	if err != nil {
		t.Fatal(err)
	}

	// Test with correct pin
	_, err = ValidatePin(ep, pin, "testid")
	if err != nil {
		t.Error(err)
	}

	// test change pin
	var bnewpin [64]byte
	_, err = rand.Read(bnewpin[:])
	if err != nil {
		t.Fatal(err)
	}
	newpin := string(bnewpin[:])
	ep, err = ChangePin(ep, pin, newpin)
	if err != nil {
		t.Fatal(err)
	}

	// test correct pin
	_, err = ValidatePin(ep, newpin, "testid")
	if err != nil {
		t.Error(err)
	}

	// Test incorrect pin
	_, err = ValidatePin(ep, pin, "testid")
	if err != ErrInvalidPin {
		t.Error(err)
	}
}

func TestVerifyAccess(t *testing.T) {
	// Setup keys for test
	_, err := rand.Read(encryptionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptionKeyID = 1
	decryptionKeys[encryptionKeyID] = encryptionKey

	// Generate test pins
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	require.NoError(t, err)
	pin1 := string(bpin[:])
	_, err = rand.Read(bpin[:])
	require.NoError(t, err)
	pin2 := string(bpin[:])

	// and test keyshare secrets
	ep1, err := GenerateKeyshareSecret(pin1)
	require.NoError(t, err)
	ep2, err := GenerateKeyshareSecret(pin2)
	require.NoError(t, err)

	// Test use jwt on wrong packet
	jwtt, err := ValidatePin(ep1, pin1, "testid")
	require.NoError(t, err)
	_, err = verifyAccess(ep2, jwtt)
	assert.Error(t, err)

	// Test incorrectly constructed jwts
	salt := make([]byte, 12)
	_, err = rand.Read(salt)
	require.NoError(t, err)
	paddedPin1, err := padPin(pin1)
	require.NoError(t, err)
	hashedPin := sha256.Sum256(append(salt, paddedPin1[:]...))

	// incorrect exp
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat":        time.Now().Add(-6 * time.Minute).Unix(),
		"exp":        time.Now().Add(-3 * time.Minute).Unix(),
		"salt":       base64.StdEncoding.EncodeToString(salt),
		"hashed_pin": base64.StdEncoding.EncodeToString(hashedPin[:]),
	})
	jwtt, err = token.SignedString(signKey)
	require.NoError(t, err)
	_, err = verifyAccess(ep1, jwtt)
	assert.Error(t, err)

	// missing exp
	token = jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat":        time.Now().Unix(),
		"salt":       base64.StdEncoding.EncodeToString(salt),
		"hashed_pin": base64.StdEncoding.EncodeToString(hashedPin[:]),
	})
	jwtt, err = token.SignedString(signKey)
	require.NoError(t, err)
	_, err = verifyAccess(ep1, jwtt)
	assert.Error(t, err)

	// Incorrectly typed exp
	token = jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat":        time.Now().Unix(),
		"exp":        "test",
		"salt":       base64.StdEncoding.EncodeToString(salt),
		"hashed_pin": base64.StdEncoding.EncodeToString(hashedPin[:]),
	})
	jwtt, err = token.SignedString(signKey)
	require.NoError(t, err)
	_, err = verifyAccess(ep1, jwtt)
	assert.Error(t, err)

	// missing salt
	token = jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat":        time.Now().Unix(),
		"exp":        time.Now().Add(3 * time.Minute).Unix(),
		"hashed_pin": base64.StdEncoding.EncodeToString(hashedPin[:]),
	})
	jwtt, err = token.SignedString(signKey)
	require.NoError(t, err)
	_, err = verifyAccess(ep1, jwtt)
	assert.Error(t, err)

	// incorrectly typed salt
	token = jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat":        time.Now().Unix(),
		"exp":        time.Now().Add(3 * time.Minute).Unix(),
		"salt":       5,
		"hashed_pin": base64.StdEncoding.EncodeToString(hashedPin[:]),
	})
	jwtt, err = token.SignedString(signKey)
	require.NoError(t, err)
	_, err = verifyAccess(ep1, jwtt)
	assert.Error(t, err)

	// missing hash
	token = jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(3 * time.Minute).Unix(),
		"salt": base64.StdEncoding.EncodeToString(salt),
	})
	jwtt, err = token.SignedString(signKey)
	require.NoError(t, err)
	_, err = verifyAccess(ep1, jwtt)
	assert.Error(t, err)

	// mistyped hash
	token = jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat":        time.Now().Unix(),
		"exp":        time.Now().Add(3 * time.Minute).Unix(),
		"salt":       base64.StdEncoding.EncodeToString(salt),
		"hashed_pin": 7,
	})
	jwtt, err = token.SignedString(signKey)
	require.NoError(t, err)
	_, err = verifyAccess(ep1, jwtt)
	assert.Error(t, err)

	// Incorrect signing method
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat":        time.Now().Unix(),
		"exp":        time.Now().Add(3 * time.Minute).Unix(),
		"salt":       base64.StdEncoding.EncodeToString(salt),
		"hashed_pin": base64.StdEncoding.EncodeToString(hashedPin[:]),
	})
	jwtt, err = token.SignedString([]byte("bla"))
	require.NoError(t, err)
	_, err = verifyAccess(ep1, jwtt)
	assert.Error(t, err)
}

func TestProofFunctionality(t *testing.T) {
	// Setup keys for test
	_, err := rand.Read(encryptionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptionKeyID = 1
	decryptionKeys[encryptionKeyID] = encryptionKey

	// generate test pin
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	if err != nil {
		t.Fatal(err)
	}
	pin := string(bpin[:])

	// generate keyshare secret
	ep, err := GenerateKeyshareSecret(pin)
	if err != nil {
		t.Fatal(err)
	}

	// Validate pin
	jwtt, err := ValidatePin(ep, pin, "testid")
	if err != nil {
		t.Fatal(err)
	}

	// Get keyshare P
	P, err := GetKeyshareP(ep, jwtt, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	if err != nil {
		t.Fatal(err)
	}

	// Get keyshare commitment
	W, commitID, err := GenerateCommitments([]irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	if err != nil {
		t.Fatal(err)
	}

	// Get keyshare response
	R, err := GenerateResponse(ep, jwtt, commitID, big.NewInt(12345))
	if err != nil {
		t.Fatal(err)
	}

	// Validate protocol execution
	if new(big.Int).Exp(testPubK1.R[0], R, testPubK1.N).Cmp(
		new(big.Int).Mod(
			new(big.Int).Mul(
				W[0],
				new(big.Int).Exp(P[0], big.NewInt(12345), testPubK1.N)),
			testPubK1.N)) != 0 {
		t.Error("Crypto result off")
	}
}

func TestCorruptedPacket(t *testing.T) {
	// Setup keys for test
	_, err := rand.Read(encryptionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptionKeyID = 1
	decryptionKeys[encryptionKeyID] = encryptionKey

	// Test parameters
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	if err != nil {
		t.Fatal(err)
	}
	pin := string(bpin[:])

	// Generate packet
	ep, err := GenerateKeyshareSecret(pin)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt packet
	ep[12] = ep[12] + 1

	// Verify pin
	_, err = ValidatePin(ep, pin, "testid")
	if err == nil {
		t.Error("ValidatePin accepts corrupted keyshare packet")
	}

	// Change pin
	_, err = ChangePin(ep, pin, pin)
	if err == nil {
		t.Error("ChangePin accepts corrupted keyshare packet")
	}

	// GetKeyshareP
	_, err = GetKeyshareP(ep, pin, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	if err == nil {
		t.Error("GetKeyshareP accepts corrupted keyshare packet")
	}

	// GetResponse
	_, commitID, err := GenerateCommitments([]irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	if err != nil {
		t.Error(err)
	}
	_, err = GenerateResponse(ep, pin, commitID, big.NewInt(12345))
	if err == nil {
		t.Error("GenerateResponse accepts corrupted keyshare packet")
	}
}

func TestIncorrectPin(t *testing.T) {
	// Setup keys for test
	_, err := rand.Read(encryptionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptionKeyID = 1
	decryptionKeys[encryptionKeyID] = encryptionKey

	// Test parameters
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	if err != nil {
		t.Fatal(err)
	}
	pin := string(bpin[:])

	// Generate packet
	ep, err := GenerateKeyshareSecret(pin)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt pin
	bpin[12] = bpin[12] + 1
	pin = string(bpin[:])

	// Change pin
	_, err = ChangePin(ep, pin, pin)
	if err == nil {
		t.Error("ChangePin accepts incorrect pin")
	}

	// GetKeyshareP
	_, err = GetKeyshareP(ep, pin, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	if err == nil {
		t.Error("GetKeyshareP accepts incorrect pin")
	}

	// GetResponse
	_, commitID, err := GenerateCommitments([]irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	if err != nil {
		t.Error(err)
	}
	_, err = GenerateResponse(ep, pin, commitID, big.NewInt(12345))
	if err == nil {
		t.Error("GenerateResponse accepts incorrect pin")
	}
}

func TestMissingKey(t *testing.T) {
	// Setup keys for test
	_, err := rand.Read(encryptionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptionKeyID = 1
	decryptionKeys[encryptionKeyID] = encryptionKey

	// Test parameters
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	if err != nil {
		t.Fatal(err)
	}
	pin := string(bpin[:])

	// Generate packet
	ep, err := GenerateKeyshareSecret(pin)
	if err != nil {
		t.Fatal(err)
	}

	// GenerateCommitments
	_, _, err = GenerateCommitments([]irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("DNE"), Counter: 1}})
	if err == nil {
		t.Error("Missing key not detected by generateCommitments")
	}

	// GetKeyshareP
	_, err = GetKeyshareP(ep, pin, []irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("DNE"), Counter: 1}})
	if err == nil {
		t.Error("Missing key not detected by GetKeyshareP")
	}
}

func TestInvalidChallenge(t *testing.T) {
	// Setup keys for test
	_, err := rand.Read(encryptionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptionKeyID = 1
	decryptionKeys[encryptionKeyID] = encryptionKey

	// Test parameters
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	if err != nil {
		t.Fatal(err)
	}
	pin := string(bpin[:])

	// Generate packet
	ep, err := GenerateKeyshareSecret(pin)
	if err != nil {
		t.Fatal(err)
	}

	// Validate pin
	jwtt, err := ValidatePin(ep, pin, "testid")
	require.NoError(t, err)

	// Test negative challenge
	_, commitID, err := GenerateCommitments([]irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = GenerateResponse(ep, jwtt, commitID, big.NewInt(-1))
	if err == nil {
		t.Error("GenerateResponse incorrectly accepts negative challenge")
	}

	// Test too large challenge
	_, commitID, err = GenerateCommitments([]irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = GenerateResponse(ep, jwtt, commitID, new(big.Int).Lsh(big.NewInt(1), 256))
	if err == nil {
		t.Error("GenerateResponse accepts challenge that is too small")
	}

	// Test just-right challenge
	_, commitID, err = GenerateCommitments([]irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = GenerateResponse(ep, jwtt, commitID, new(big.Int).Lsh(big.NewInt(1), 255))
	if err != nil {
		t.Error("GenerateResponse does not accept challenge of 256 bits")
	}
}

func TestDoubleCommitUse(t *testing.T) {
	// Setup keys for test
	_, err := rand.Read(encryptionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptionKeyID = 1
	decryptionKeys[encryptionKeyID] = encryptionKey

	// Test parameters
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	if err != nil {
		t.Fatal(err)
	}
	pin := string(bpin[:])

	// Generate packet
	ep, err := GenerateKeyshareSecret(pin)
	if err != nil {
		t.Fatal(err)
	}

	// validate pin
	jwtt, err := ValidatePin(ep, pin, "testid")
	require.NoError(t, err)

	// Use commit double
	_, commitID, err := GenerateCommitments([]irma.PublicKeyIdentifier{irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = GenerateResponse(ep, jwtt, commitID, big.NewInt(12345))
	if err != nil {
		t.Fatal(err)
	}
	_, err = GenerateResponse(ep, jwtt, commitID, big.NewInt(12346))
	if err == nil {
		t.Error("GenerateResponse incorrectly allows double use of commit")
	}
}

func TestNonExistingCommit(t *testing.T) {
	// Setup keys for test
	_, err := rand.Read(encryptionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptionKeyID = 1
	decryptionKeys[encryptionKeyID] = encryptionKey

	// Test parameters
	var bpin [64]byte
	_, err = rand.Read(bpin[:])
	if err != nil {
		t.Fatal(err)
	}
	pin := string(bpin[:])

	// Generate packet
	ep, err := GenerateKeyshareSecret(pin)
	if err != nil {
		t.Fatal(err)
	}

	// test
	_, err = GenerateResponse(ep, pin, 2364, big.NewInt(12345))
	if err == nil {
		t.Error("GenerateResponse failed to detect non-existing commit")
	}
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
const jwtTestKeyPem = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDn/6NIL1rT9jnZ176Yjy7I1ANphC034yaTviIbo4GoToAoGCCqGSM49
AwEHoUQDQgAEcdDWu6mXTtobMuYWuLNtQHpg27qF7G+mNdgGsP6Ff5caCh8GGM63
i6QFZGBa5D1tKJ0rN5Sh/18IzBdtFHpWhA==
-----END EC PRIVATE KEY-----`

var jwtTestKey *ecdsa.PrivateKey
var testPubK1 *gabi.PublicKey

func setupParameters() error {
	var err error
	testPubK1, err = gabi.NewPublicKeyFromXML(xmlPubKey1)
	if err != nil {
		return err
	}
	DangerousAddTrustedPublicKey(irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test"), Counter: 1}, testPubK1)
	jwtTestKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(jwtTestKeyPem))
	if err != nil {
		return err
	}
	DangerousSetSignKey(jwtTestKey)
	return nil
}

func TestMain(m *testing.M) {
	err := setupParameters()
	if err != nil {
		os.Exit(1)
	}
	os.Exit(m.Run())
}
