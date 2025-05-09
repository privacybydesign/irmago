package sdjwtvc

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func createDefaultTestingSdJwt(t *testing.T) SdJwtVc {
	issuer := "https://example.com"
	disclosures, err := MultipleNewDisclosureContents(map[string]any{
		"family_name": "Yivi",
		"locality":    "Utrecht",
	})
	requireNoErr(t, err)
	jwtCreator := newEcdsaJwtCreatorWithIssuerTestkey()
	sdJwt, err := CreateSdJwtVcForIssuance(issuer, disclosures, jwtCreator)
	requireNoErr(t, err)
	return sdJwt
}

func createKbJwtWithTestHolderKey(t *testing.T, sdjwt SdJwtVc) KeyBindingJwt {
	kbJwtCreator, err := NewKbJwtCreatorWithHolderTestKey()
	requireNoErr(t, err)

	kbjwt, err := CreateKbJwt(sdjwt, kbJwtCreator)
	requireNoErr(t, err)
	return kbjwt
}

func requirePresentWithValue[T comparable](t *testing.T, values map[string]any, key string, expectedValue T) {
	val, ok := values[key]
	if !ok {
		t.Fatalf("map should contain value for '%s', but doesn't", key)
	} else {
		casted, ok := val.(T)
		if !ok {
			t.Fatalf("value for '%s' in map not of expected type", key)
		}
		if casted != expectedValue {
			t.Fatalf("value for '%s' in map doesn't have the expected value (%v != %v)", key, casted, expectedValue)
		}
	}
}

func requireNotPresent(t *testing.T, values map[string]any, key string) {
	if _, ok := values[key]; ok {
		t.Fatalf("map may not contain '%v' field, but does", key)
	}
}

func requireNoErr(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("expected no err, but got: %v", err)
	}
}

func requireErr(t *testing.T, err error) {
	if err == nil {
		t.Fatal("expected err, but didn't get one")
	}
}

func jsonToMap(js string) map[string]interface{} {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(js), &result)
	if err != nil {
		log.Fatalf("failed to parse json to map: %v", err)
	}
	return result
}

func newEcdsaJwtCreatorWithIssuerTestkey() *DefaultEcdsaJwtCreator {
	key, err := readTestIssuerPrivateKey()
	if err != nil {
		return nil
	}

	return &DefaultEcdsaJwtCreator{key: key}
}

func getTestFilePath(name string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to find working directory: %v", err)
	}
	root, err := findGoModRoot(wd)
	if err != nil {
		return "", fmt.Errorf("failed to find go mod root: %v", err)
	}
	keyPath := fmt.Sprintf("%s/test_keys/%s", root, name)
	return keyPath, nil
}

func readTestHolderPrivateKey() (*ecdsa.PrivateKey, error) {
	keyPath, err := getTestFilePath("holder_ec_priv.pem")
	if err != nil {
		return nil, err
	}
	key, err := ReadEcdsaPrivateKey(keyPath)
	if err != nil || key == nil {
		return nil, fmt.Errorf("failed to read ecdsa private key: %v", err)
	}
	return key, nil
}

func readTestIssuerPrivateKey() (*ecdsa.PrivateKey, error) {
	keyPath, err := getTestFilePath("issuer_ec_priv.pem")
	if err != nil {
		return nil, err
	}
	key, err := ReadEcdsaPrivateKey(keyPath)
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
	return &DefaultEcdsaJwtCreator{key: key}, nil
}

func NewKbJwtCreatorWithHolderTestKey() (*DefaultKbJwtCreator, error) {
	jwtCreator, err := NewEcdsaJwtCreatorWithHolderTestKey()
	if err != nil {
		return nil, err
	}

	return &DefaultKbJwtCreator{
		Clock:      &SystemClock{},
		JwtCreator: jwtCreator,
	}, nil
}

func readHolderPublicJwk() (CnfField, error) {
	key, err := os.ReadFile("test_keys/holder_ec_pub.jwk")
	if err != nil {
		return CnfField{}, err
	}
	var jwk map[string]interface{}
	err = json.Unmarshal(key, &jwk)
	if err != nil {
		return CnfField{}, err
	}
	return CnfField{Jwk: jwk}, nil
}

func findGoModRoot(start string) (string, error) {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}

// =======================================================================

func createProductionVerificationContext() VerificationContext {
	return VerificationContext{
		IssuerMetadataFetcher: NewHttpIssuerMetadataFetcher(),
		Clock:                 NewSystemClock(),
		JwtVerifier:           NewJwxJwtVerifier(),
	}
}

func createTestVerificationContext() VerificationContext {
	return VerificationContext{
		Clock:                 &testClock{},
		IssuerMetadataFetcher: &validTestMetadataFetcher{},
		JwtVerifier:           &JwxJwtVerifier{},
	}
}

type testClock struct{ time int64 }

func (c *testClock) Now() int64 { return c.time }

type failingMetadataFetcherNetworkError struct{}

func (f *failingMetadataFetcherNetworkError) FetchIssuerMetadata(url string) (IssuerMetadata, error) {
	return IssuerMetadata{}, errors.New("some error")
}

type failingMetadataFetcherWrongIssuerKeys struct{}

func (f *failingMetadataFetcherWrongIssuerKeys) FetchIssuerMetadata(url string) (IssuerMetadata, error) {
	return IssuerMetadata{
		Issuer: "https://openid4vc.staging.yivi.app",
		Jwks: []any{
			// public key corresponsing to the test issuer private key in the test files
			map[string]string{
				"crv": "P-256",
				"kty": "EC",
				"x":   "r7bMrDTDe-R_HI1wywYtEYr-DJa5HdTnI8dsjZer6g",
				"y":   "Kz8meL8U3jpnY1PcKdFpM3zjZspPMbD3j6J-AIcAivk",
			},
		},
	}, nil
}

type validTestMetadataFetcher struct{}

func (f *validTestMetadataFetcher) FetchIssuerMetadata(url string) (IssuerMetadata, error) {
	return IssuerMetadata{
		Issuer: "https://openid4vc.staging.yivi.app",
		Jwks: []any{
			// public key corresponsing to the test issuer private key in the test files
			map[string]string{
				"crv": "P-256",
				"kty": "EC",
				"x":   "Sr7bMrDTDe-R_HI1wywYtEYr-DJa5HdTnI8dsjZer6g",
				"y":   "Kz8meL8U3jpnY1PcKdFpM3zjZspPMbD3j6J-AIcAivk",
			},
		},
	}, nil
}

type validTestMetadataFetcherMultipleKeys struct{}

func (f *validTestMetadataFetcherMultipleKeys) FetchIssuerMetadata(url string) (IssuerMetadata, error) {
	return IssuerMetadata{
		Issuer: "https://openid4vc.staging.yivi.app",
		Jwks: []any{
			map[string]string{
				"crv": "P-256",
				"kty": "EC",
				"x":   "-R_HI1wywYtEYr-DJa5HdTnI8dsjZer6g",
				"y":   "meL8U3jpnY1PcKdFpM3zjZspPMbD3j6J-AIcAivk",
			},
			// public key corresponsing to the test issuer private key in the test files
			map[string]string{
				"crv": "P-256",
				"kty": "EC",
				"x":   "Sr7bMrDTDe-R_HI1wywYtEYr-DJa5HdTnI8dsjZer6g",
				"y":   "Kz8meL8U3jpnY1PcKdFpM3zjZspPMbD3j6J-AIcAivk",
			},
		},
	}, nil
}

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
	holderPubKey := map[string]any{
		"crv": "P-256",
		"kty": "EC",
		"x":   "Sr7bMrDTDe-R_HI1wywYtEYr-DJa5HdTnI8dsjZer6g",
		"y":   "Kz8meL8U3jpnY1PcKdFpM3zjZspPMbD3j6J-AIcAivk",
	}
	return CnfField{
		Jwk: holderPubKey,
	}
}

func createHolderCnfField() CnfField {
	holderPubKey := map[string]any{
		"crv": "P-256",
		"kty": "EC",
		"x":   "JD5EI6ijOi69WvYGjUWxJngbRDBwBwsOF7j1ERDWOJ4",
		"y":   "64ugJiqHoqtotdJda9QUUUDsovVXOlSttxGCfKM1yqQ",
	}
	return CnfField{
		Jwk: holderPubKey,
	}
}

func newWorkingSdJwtTestConfig() testSdJwtVcConfig {
	disclosures, err := MultipleNewDisclosureContents(map[string]any{
		"name":     "Yivi",
		"location": "Utrecht",
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
		withVct(DefaultVerifiableCredentialType).
		withIssuerUrl("https://openid4vc.staging.yivi.app").
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

func (c testSdJwtVcConfig) withIssuerUrl(url string) testSdJwtVcConfig {
	c.issuerUrl = &url
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
	issuerUrl  *string
	issuedAt   *int64
	expiryTime *int64
	notBefore  *int64
	cnfPubKey  *CnfField
	sdClaims   *[]HashedDisclosure
	sdAlg      *HashingAlgorithm
	vct        *string

	// stuff inside the issuer signed header
	typHeader *string

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

	header := map[string]string{}
	if config.kbjwtTypHeader != nil {
		header[Key_Typ] = *config.kbjwtTypHeader
	}

	jwtCreator := DefaultEcdsaJwtCreator{key: config.holderPrivateKey}
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

	issuerHeader := map[string]string{}

	if config.typHeader != nil {
		issuerHeader[Key_Typ] = *config.typHeader
	}

	jwtCreator := DefaultEcdsaJwtCreator{key: config.issuerPrivateKey}

	payloadJson, err := json.Marshal(issuerPayload)
	if err != nil {
		return "", err
	}
	jwt, err := jwtCreator.CreateSignedJwt(issuerHeader, string(payloadJson))
	return IssuerSignedJwt(jwt), err
}

func createTestSdJwtVc(t *testing.T, config testSdJwtVcConfig) SdJwtVc {
	issuerJwt, err := createTestIssuerSignedJwt(config)
	requireNoErr(t, err)

	encodedDisclosures, err := EncodeDisclosures(config.disclosures)
	requireNoErr(t, err)
	sdjwt := CreateSdJwtVc(issuerJwt, encodedDisclosures)

	if config.addKbJwt {
		sdjwt, err = addTestKbJwt(config, sdjwt)
		requireNoErr(t, err)
	}

	return sdjwt
}
