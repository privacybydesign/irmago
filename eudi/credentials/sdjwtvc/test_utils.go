package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"testing"
	"time"

	_ "embed"

	"github.com/lestrrat-go/jwx/v3/jwk"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func createDefaultTestingSdJwt(t *testing.T, keyBinder KeyBinder) SdJwtVc {
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	issuer := "https://irma.app"
	disclosures, err := MultipleNewDisclosureContents(map[string]string{
		"family_name": "Yivi",
		"location":    "Utrecht",
	})
	require.NoError(t, err)
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()

	holderKey, err := keyBinder.CreateKeyPairs(1)
	require.NoError(t, err)

	sdJwt, err := NewSdJwtVcBuilder().
		WithHolderKey(holderKey[0]).
		WithIssuerUrl(issuer).
		WithDisclosures(disclosures).
		WithVerifiableCredentialType("pbdf.pbdf.email").
		WithHashingAlgorithm(HashAlg_Sha256).
		WithIssuerCertificateChain(irmaAppCert).
		Build(jwtCreator)

	require.NoError(t, err)

	return sdJwt
}

func createKbJwt(t *testing.T, sdjwt SdJwtVc, keyBinder KeyBinder) KeyBindingJwt {
	kbjwt, err := CreateKbJwt(sdjwt, keyBinder, "nonce", "Verifier")
	require.NoError(t, err)
	return kbjwt
}

func jsonToMap(t *testing.T, js string) map[string]interface{} {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(js), &result)
	require.NoError(t, err)
	return result
}

func NewEcdsaJwtCreatorWithIssuerTestkey() *DefaultEcdsaJwtCreator {
	key, err := readTestIssuerPrivateKey()
	if err != nil {
		return nil
	}

	return &DefaultEcdsaJwtCreator{privateKey: key}
}

func readTestHolderPrivateKey() (*ecdsa.PrivateKey, error) {
	key, err := DecodeEcdsaPrivateKey(testdata.HolderPrivKeyBytes)
	if err != nil || key == nil {
		return nil, fmt.Errorf("failed to read ecdsa private key: %v", err)
	}
	return key, nil
}

func readTestIssuerPrivateKey() (*ecdsa.PrivateKey, error) {
	key, err := DecodeEcdsaPrivateKey(testdata.IssuerPrivKeyBytes)
	if err != nil || key == nil {
		return nil, fmt.Errorf("failed to read ecdsa private key: %v", err)
	}
	return key, nil
}

func NewEcdsaJwtCreatorWithHolderTestKey() (*DefaultEcdsaJwtCreator, error) {
	key, err := readTestHolderPrivateKey()
	if err != nil {
		return nil, err
	}
	return &DefaultEcdsaJwtCreator{privateKey: key}, nil
}

func readHolderPublicJwk() (CnfField, error) {
	key, err := jwk.ParseKey(testdata.HolderPubJwkBytes)
	return CnfField{Jwk: key}, err
}

// =======================================================================

func CreateTestVerificationContext() SdJwtVcVerificationContext {
	irmaAppCertChain, err := utils.ParsePemCertificateChain(testdata.IssuerCertChain_irma_app_Bytes)
	if err != nil {
		log.Fatalf("failed to parse issuer cert chain: %v", err)
	}

	roots := x509.NewCertPool()
	im := x509.NewCertPool()

	roots.AddCert(irmaAppCertChain[0])
	im.AddCert(irmaAppCertChain[1])

	return SdJwtVcVerificationContext{
		VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: x509.VerifyOptions{
				Roots:         roots,
				Intermediates: im,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
		Clock:       &testClock{},
		JwtVerifier: NewJwxJwtVerifier(),
	}
}

type testClock struct{ time int64 }

func (c *testClock) Now() time.Time { return time.Unix(c.time, 0) }

// =======================================================================

func newEmptyTestConfig() testSdJwtVcConfig {
	return testSdJwtVcConfig{
		issuerUrl:        nil,
		issuedAt:         nil,
		expiryTime:       nil,
		notBefore:        nil,
		cnfPubKey:        nil,
		sdClaims:         nil,
		vct:              nil,
		sdAlg:            nil,
		typHeader:        nil,
		nonce:            nil,
		sdHash:           nil,
		useActualSdHash:  false,
		audience:         nil,
		kbIssuedAt:       nil,
		kbjwtTypHeader:   nil,
		addKbJwt:         false,
		disclosures:      []DisclosureContent{},
		holderPrivateKey: nil,
		issuerPrivateKey: nil,
	}
}

func createIssuerCnfField() CnfField {
	return CnfField{
		Jwk: testdata.ParseIssuerPubJwk(),
	}
}

func createHolderCnfField() CnfField {
	return CnfField{
		Jwk: testdata.ParseHolderPubJwk(),
	}
}

func newWorkingVerifyOptions(trustedChains ...[]byte) x509.VerifyOptions {
	roots := x509.NewCertPool()
	im := x509.NewCertPool()

	for _, trustedChain := range trustedChains {
		appCert, _ := utils.ParsePemCertificateChain(trustedChain)

		if len(appCert) > 0 {
			roots.AddCert(appCert[0])
		}

		for _, cert := range appCert[1:] {
			im.AddCert(cert)
		}
	}

	return x509.VerifyOptions{
		Roots:         roots,
		Intermediates: im,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func newWorkingSdJwtTestConfig() testSdJwtVcConfig {
	disclosures, err := MultipleNewDisclosureContents(map[string]string{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	})
	if err != nil {
		log.Fatalf("failed to create disclosures: %v", err)
	}

	holderKey, err := readTestHolderPrivateKey()
	if err != nil {
		log.Fatalf("failed to read holder priv key: %v", err)
	}

	issuerKey, err := readTestIssuerPrivateKey()
	if err != nil {
		log.Fatalf("failed to read issuer priv key: %v", err)
	}

	return newEmptyTestConfig().
		withHolderPrivateKey(holderKey).
		withIssuerPrivateKey(issuerKey).
		withVct("test.test.email").
		withIssuerUrl("https://openid4vc.staging.yivi.app", false).
		withIssuedAt(1745394126).
		withExpiryTime(1945394126).
		withNotBefore(50).
		withCnf(createHolderCnfField()).
		withSdAlg(HashAlg_Sha256).
		withSdClaims(disclosures).
		withDisclosures(disclosures).
		withTypHeader(SdJwtVcTyp).
		withKbJwt().
		withKbTypHeader(KbJwtTyp).
		withAudience("Verifier").
		withKbNonce("nonce").
		withValidSdHash().
		withKbIssuedAt(1745394126)
}

func (c testSdJwtVcConfig) withHolderPrivateKey(key *ecdsa.PrivateKey) testSdJwtVcConfig {
	c.holderPrivateKey = key
	return c
}

func (c testSdJwtVcConfig) withIssuerPrivateKey(key *ecdsa.PrivateKey) testSdJwtVcConfig {
	c.issuerPrivateKey = key
	return c
}

func (c testSdJwtVcConfig) withIssuerUrl(url string, allowNonHttps bool) testSdJwtVcConfig {
	c.issuerUrl = &url
	c.allowNonHttps = allowNonHttps
	return c
}

func (c testSdJwtVcConfig) withVct(vct string) testSdJwtVcConfig {
	c.vct = &vct
	return c
}

func (c testSdJwtVcConfig) withIssuedAt(time int64) testSdJwtVcConfig {
	c.issuedAt = &time
	return c
}

func (c testSdJwtVcConfig) withExpiryTime(time int64) testSdJwtVcConfig {
	c.expiryTime = &time
	return c
}

func (c testSdJwtVcConfig) withCnf(field CnfField) testSdJwtVcConfig {
	c.cnfPubKey = &field
	return c
}

func (c testSdJwtVcConfig) withSdAlg(alg HashingAlgorithm) testSdJwtVcConfig {
	c.sdAlg = &alg
	return c
}

func (c testSdJwtVcConfig) withNotBefore(time int64) testSdJwtVcConfig {
	c.notBefore = &time
	return c
}

func (c testSdJwtVcConfig) withSdClaims(claims []DisclosureContent) testSdJwtVcConfig {
	alg := HashAlg_Sha256
	hashes, err := HashDisclosures(alg, claims)
	if err != nil {
		log.Fatalf("failed to create hashes: %v", err)
	}
	c.sdClaims = &hashes
	return c
}

func (c testSdJwtVcConfig) withTypHeader(value string) testSdJwtVcConfig {
	c.typHeader = &value
	return c
}

func (c testSdJwtVcConfig) withKbNonce(nonce string) testSdJwtVcConfig {
	c.nonce = &nonce
	return c
}

func (c testSdJwtVcConfig) withValidSdHash() testSdJwtVcConfig {
	c.useActualSdHash = true
	return c
}

func (c testSdJwtVcConfig) withoutAnySdHash() testSdJwtVcConfig {
	c.useActualSdHash = false
	c.sdHash = nil
	return c
}

func (c testSdJwtVcConfig) withSdHash(hash string) testSdJwtVcConfig {
	c.sdHash = &hash
	return c
}

func (c testSdJwtVcConfig) withAudience(aud string) testSdJwtVcConfig {
	c.audience = &aud
	return c
}

func (c testSdJwtVcConfig) withKbIssuedAt(time int64) testSdJwtVcConfig {
	c.kbIssuedAt = &time
	return c
}

func (c testSdJwtVcConfig) withKbTypHeader(value string) testSdJwtVcConfig {
	c.kbjwtTypHeader = &value
	return c
}

func (c testSdJwtVcConfig) withIssuerCertificateChainBytes(value []byte) testSdJwtVcConfig {
	appCert, err := utils.ParsePemCertificateChainToX5cFormat(value)
	if err != nil {
		panic(err)
	}

	c.x5cHeader = appCert

	return c
}

func (c testSdJwtVcConfig) withKbJwt() testSdJwtVcConfig {
	c.addKbJwt = true
	return c
}

func (c testSdJwtVcConfig) withoutKbJwt() testSdJwtVcConfig {
	c.addKbJwt = false
	return c
}

func (c testSdJwtVcConfig) withDisclosures(disclosures []DisclosureContent) testSdJwtVcConfig {
	c.disclosures = disclosures
	return c
}

type testSdJwtVcConfig struct {
	// stuff inside the issuer signed payload
	issuerUrl     *string
	allowNonHttps bool
	issuedAt      *int64
	expiryTime    *int64
	notBefore     *int64
	cnfPubKey     *CnfField
	sdClaims      *[]HashedDisclosure
	sdAlg         *HashingAlgorithm
	vct           *string

	// stuff inside the issuer signed header
	typHeader *string
	x5cHeader []string

	// stuff inside the kbjwt payload
	nonce           *string
	sdHash          *string
	useActualSdHash bool
	audience        *string
	kbIssuedAt      *int64

	// stuff inside the kbjwt header
	kbjwtTypHeader *string

	// whether to add the kbjwt
	addKbJwt    bool
	disclosures []DisclosureContent

	// general signing stuff
	holderPrivateKey *ecdsa.PrivateKey
	issuerPrivateKey *ecdsa.PrivateKey
}

func addTestKbJwt(config testSdJwtVcConfig, sdjwtvc SdJwtVc) (SdJwtVc, error) {
	payload := map[string]any{}
	if config.nonce != nil {
		payload[Key_Nonce] = *config.nonce
	}
	if config.useActualSdHash {
		hash, err := CreateHash(HashAlg_Sha256, string(sdjwtvc))
		if err != nil {
			return "", err
		}
		payload[Key_SdHash] = hash
	}

	if config.sdHash != nil {
		payload[Key_SdHash] = *config.sdHash
	}

	if config.audience != nil {
		payload[Key_Audience] = *config.audience
	}
	if config.kbIssuedAt != nil {
		payload[Key_IssuedAt] = *config.kbIssuedAt
	}

	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	header := map[string]any{}
	if config.kbjwtTypHeader != nil {
		header[Key_Typ] = *config.kbjwtTypHeader
	}

	jwtCreator := DefaultEcdsaJwtCreator{privateKey: config.holderPrivateKey}
	jwt, err := jwtCreator.CreateSignedJwt(header, string(payloadJson))

	return AddKeyBindingJwtToSdJwtVc(sdjwtvc, KeyBindingJwt(jwt)), err
}

func createTestIssuerSignedJwt(config testSdJwtVcConfig) (IssuerSignedJwt, error) {
	issuerPayload := map[string]any{}

	if config.vct != nil {
		issuerPayload[Key_VerifiableCredentialType] = *config.vct
	}
	if config.issuerUrl != nil {
		issuerPayload[Key_Issuer] = *config.issuerUrl
	}
	if config.issuedAt != nil {
		issuerPayload[Key_IssuedAt] = *config.issuedAt
	}
	if config.expiryTime != nil {
		issuerPayload[Key_ExpiryTime] = *config.expiryTime
	}
	if config.notBefore != nil {
		issuerPayload[Key_NotBefore] = *config.notBefore
	}
	if config.cnfPubKey != nil {
		issuerPayload[Key_Confirmationkey] = *config.cnfPubKey
	}
	if config.sdClaims != nil {
		issuerPayload[Key_Sd] = *config.sdClaims
	}
	if config.sdAlg != nil {
		issuerPayload[Key_SdAlg] = *config.sdAlg
	}

	issuerHeader := map[string]any{}

	if config.typHeader != nil {
		issuerHeader[Key_Typ] = *config.typHeader
	}

	if config.x5cHeader != nil {
		issuerHeader[Key_X5c] = config.x5cHeader
	}

	jwtCreator := DefaultEcdsaJwtCreator{privateKey: config.issuerPrivateKey}

	payloadJson, err := json.Marshal(issuerPayload)
	if err != nil {
		return "", err
	}
	jwt, err := jwtCreator.CreateSignedJwt(issuerHeader, string(payloadJson))
	return IssuerSignedJwt(jwt), err
}

func createTestSdJwtVc(t *testing.T, config testSdJwtVcConfig) SdJwtVc {
	issuerJwt, err := createTestIssuerSignedJwt(config)
	require.NoError(t, err)

	encodedDisclosures, err := EncodeDisclosures(config.disclosures)
	require.NoError(t, err)
	sdjwt := CreateSdJwtVc(issuerJwt, encodedDisclosures)

	if config.addKbJwt {
		sdjwt, err = addTestKbJwt(config, sdjwt)
		require.NoError(t, err)
	}

	return sdjwt
}
