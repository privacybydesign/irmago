package irma

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/privacybydesign/gabi/big"

	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func parseConfiguration(t *testing.T) *Configuration {
	conf, err := NewConfiguration("testdata/irma_configuration")
	require.NoError(t, err)
	require.NoError(t, conf.ParseFolder())
	return conf
}

// A convenience function for initializing big integers from known correct (10
// base) strings. Use with care, errors are ignored.
func s2big(s string) (r *big.Int) {
	r, _ = new(big.Int).SetString(s, 10)
	return
}

func TestConfigurationAutocopy(t *testing.T) {
	test.CreateTestStorage(t)
	defer test.ClearTestStorage(t)

	path := filepath.Join("testdata", "storage", "test", "irma_configuration")
	require.NoError(t, fs.CopyDirectory(filepath.Join("testdata", "irma_configuration"), path))
	conf, err := NewConfigurationFromAssets(path, filepath.Join("testdata", "irma_configuration_updated"))
	require.NoError(t, err)
	require.NoError(t, conf.ParseFolder())

	credid := NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")
	require.True(t, conf.CredentialTypes[credid].ContainsAttribute(attrid))
}

func TestParseInvalidIrmaConfiguration(t *testing.T) {
	// The description.xml of the scheme manager under this folder has been edited
	// to invalidate the scheme manager signature
	conf, err := NewConfigurationReadOnly("testdata/irma_configuration_invalid")
	require.NoError(t, err)

	// Parsing it should return a SchemeManagerError
	err = conf.ParseFolder()
	require.Error(t, err)
	smerr, ok := err.(*SchemeManagerError)
	require.True(t, ok)
	require.Equal(t, SchemeManagerStatusInvalidSignature, smerr.Status)

	// The manager should still be in conf.SchemeManagers, but also in DisabledSchemeManagers
	require.Contains(t, conf.SchemeManagers, smerr.Manager)
	require.Contains(t, conf.DisabledSchemeManagers, smerr.Manager)
	require.Equal(t, SchemeManagerStatusInvalidSignature, conf.SchemeManagers[smerr.Manager].Status)
	require.Equal(t, false, conf.SchemeManagers[smerr.Manager].Valid)
}

func TestRetryHTTPRequest(t *testing.T) {
	test.StartBadHttpServer(3, 1*time.Second, "42")
	defer test.StopBadHttpServer()

	transport := NewHTTPTransport("http://localhost:48682")
	transport.client.HTTPClient.Timeout = 500 * time.Millisecond
	bts, err := transport.GetBytes("")
	require.NoError(t, err)
	require.Equal(t, "42\n", string(bts))
}

func TestInvalidIrmaConfigurationRestoreFromRemote(t *testing.T) {
	test.StartSchemeManagerHttpServer()
	defer test.StopSchemeManagerHttpServer()

	test.CreateTestStorage(t)
	defer test.ClearTestStorage(t)

	conf, err := NewConfigurationFromAssets("testdata/storage/test/irma_configuration", "testdata/irma_configuration_invalid")
	require.NoError(t, err)

	err = conf.ParseOrRestoreFolder()
	require.NoError(t, err)
	require.Empty(t, conf.DisabledSchemeManagers)
	require.Contains(t, conf.SchemeManagers, NewSchemeManagerIdentifier("irma-demo"))
	require.Contains(t, conf.CredentialTypes, NewCredentialTypeIdentifier("irma-demo.RU.studentCard"))
}

func TestInvalidIrmaConfigurationRestoreFromAssets(t *testing.T) {
	test.CreateTestStorage(t)
	defer test.ClearTestStorage(t)

	conf, err := NewConfigurationFromAssets("testdata/storage/test/irma_configuration", "testdata/irma_configuration_invalid")
	require.NoError(t, err)

	// Fails: no remote and the version in the assets is broken
	err = conf.ParseOrRestoreFolder()
	require.Error(t, err)
	require.NotEmpty(t, conf.DisabledSchemeManagers)

	// Try again from correct assets
	conf.assets = "testdata/irma_configuration"
	err = conf.ParseOrRestoreFolder()
	require.NoError(t, err)
	require.Empty(t, conf.DisabledSchemeManagers)
	require.Contains(t, conf.SchemeManagers, NewSchemeManagerIdentifier("irma-demo"))
	require.Contains(t, conf.CredentialTypes, NewCredentialTypeIdentifier("irma-demo.RU.studentCard"))
}

func TestParseIrmaConfiguration(t *testing.T) {
	conf := parseConfiguration(t)

	require.Contains(t, conf.SchemeManagers, NewSchemeManagerIdentifier("irma-demo"))
	require.Contains(t, conf.SchemeManagers, NewSchemeManagerIdentifier("test"))

	pk, err := conf.PublicKey(NewIssuerIdentifier("irma-demo.RU"), 0)
	require.NoError(t, err)
	require.NotNil(t, pk)
	require.NotNil(t, pk.N, "irma-demo.RU public key has no modulus")
	require.Equal(t,
		"Irma Demo",
		conf.SchemeManagers[NewSchemeManagerIdentifier("irma-demo")].Name["en"],
		"irma-demo scheme manager has unexpected name")
	require.Equal(t,
		"Radboud University Nijmegen",
		conf.Issuers[NewIssuerIdentifier("irma-demo.RU")].Name["en"],
		"irma-demo.RU issuer has unexpected name")
	require.Equal(t,
		"Student Card",
		conf.CredentialTypes[NewCredentialTypeIdentifier("irma-demo.RU.studentCard")].ShortName["en"],
		"irma-demo.RU.studentCard has unexpected name")

	require.Equal(t,
		"studentID",
		conf.CredentialTypes[NewCredentialTypeIdentifier("irma-demo.RU.studentCard")].AttributeTypes[2].ID,
		"irma-demo.RU.studentCard.studentID has unexpected name")

	// Hash algorithm pseudocode:
	// Base64(SHA256("irma-demo.RU.studentCard")[0:16])
	//require.Contains(t, conf.reverseHashes, "1stqlPad5edpfS1Na1U+DA==",
	//	"irma-demo.RU.studentCard had improper hash")
	//require.Contains(t, conf.reverseHashes, "CLjnADMBYlFcuGOT7Z0xRg==",
	//	"irma-demo.MijnOverheid.root had improper hash")
}

func TestMetadataAttribute(t *testing.T) {
	metadata := NewMetadataAttribute(0x02)
	if metadata.Version() != 0x02 {
		t.Errorf("Unexpected metadata version: %d", metadata.Version())
	}

	expiry := metadata.SigningDate().Unix() + int64(metadata.ValidityDuration()*ExpiryFactor)
	if !time.Unix(expiry, 0).Equal(metadata.Expiry()) {
		t.Errorf("Invalid signing date")
	}

	if metadata.KeyCounter() != 0 {
		t.Errorf("Unexpected key counter")
	}
}

func TestMetadataCompatibility(t *testing.T) {
	conf, err := NewConfigurationReadOnly("testdata/irma_configuration")
	require.NoError(t, err)
	require.NoError(t, conf.ParseFolder())

	// An actual metadata attribute of an IRMA credential extracted from the IRMA app
	attr := MetadataFromInt(s2big("49043481832371145193140299771658227036446546573739245068"), conf)
	require.NotNil(t, attr.CredentialType(), "attr.CredentialType() should not be nil")

	require.Equal(t,
		NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
		attr.CredentialType().Identifier(),
		"Metadata credential type was not irma-demo.RU.studentCard",
	)
	require.Equal(t, byte(0x02), attr.Version(), "Unexpected metadata version")
	require.Equal(t, time.Unix(1499904000, 0), attr.SigningDate(), "Unexpected signing date")
	require.Equal(t, time.Unix(1516233600, 0), attr.Expiry(), "Unexpected expiry date")
	require.Equal(t, 2, attr.KeyCounter(), "Unexpected key counter")
}

func TestTimestamp(t *testing.T) {
	mytime := Timestamp(time.Unix(1500000000, 0))
	timestruct := struct{ Time *Timestamp }{Time: &mytime}
	bytes, err := json.Marshal(timestruct)
	require.NoError(t, err)

	timestruct = struct{ Time *Timestamp }{}
	require.NoError(t, json.Unmarshal(bytes, &timestruct))
	require.Equal(t, time.Time(*timestruct.Time).Unix(), int64(1500000000))
}

func TestVerifyValidSig(t *testing.T) {
	conf := parseConfiguration(t)

	irmaSignedMessageJson := "{\"signature\":[{\"c\":\"pliyrSE7wXcDcKXuBtZW5bnucvBSXpILIRvnNBgx7hQ=\",\"A\":\"D/8wLPq9860bpXZ5c+VYyoPJ+Z8CWDZNQ0jXvst8qnPRdivy/GQIfJHjVnpOPlHbguphb/7JVbfcV3bZeybA3bCF/4UesjRUZlMf/iJ/QgKHbt41ogN1PPT5z7qBJpkxuNTIkHxaUPoDvhouHmuC9pNj4afRUyLJerxKPkpdBw0=\",\"e_response\":\"YOrKTrMSs4/QOUtPkT0YaYNEmW7Cs+cu624zr2xrHodyL88ub6yaXB7MGHAcQ1+iXsGN8jkfxB/0\",\"v_response\":\"AYSa1p8ISs//MsocJjODwWuPB/z6+iKHHi+sTToRs0eJ2X1gwmWoA5QB0aHjRkWye3/+2rtosfUzI77FlPQVnrbMERwcuYM/fx3fpNCpjm2qcs3AOJRcSRxcNFMe1+4ECsmJhByMDutS1KXAAKiNvnhEXx9f0JrQGwQFtpSFPh8dOuvEKUZHAUALr4FcHCa2HL9nDRiqy2KAOxE0nAANAcMaBo/ed+WZeHtv4CTB7egyYs27cklVbwlBzmRrbjNZk57ICd0jVd6SZ2Ir93r/aPejkyhQ03xh9RVVyhOn4bkbjKIBzEybXTJAXgNmvd6F8Ds00srBZVWlo7Z23JZ7\",\"a_responses\":{\"0\":\"QHTznWWrECRNNmUNcy0yGu2L6qsZU6qkvaII8QB8QjbUxpwHzSeJWkzrn/Kk1KIowfoqB1DKGaFLATvuBl+bCoJjea+2VfK9Ns8=\",\"2\":\"H57Y9CTXJ5MAVo+aFfNSbmRMFQpraBIZVOXiRxCD/P7Aw4fW8r9P5l9pO9DTUeExaqFzsLyF5i5EridVWxlP2Wv0zbH8ku9Sg9w=\",\"3\":\"joggAmOhqM4QsKdoLHAfaslzXqJswS7MwZ/5+AKYdkMaHQ45biMdZU/6R+B7bjvsumg2f6KyTyg0G+BI+wVdJOjh3kGezdANB7Y=\",\"5\":\"5YP4A82WWeqc33e5Zg/Q8lqQQ1amLE8mOxMwCXb3N4J0UJRfV9lUFvbH1Q3Yb3YHAZpzGvhN/pBacwqktMkP4L71PnMldqA+nqA=\"},\"a_disclosed\":{\"1\":\"AgAJuwB+AALWy2qU9p3l52l9LU1rVT4M\",\"4\":\"NDU2\"}}],\"nonce\":\"Kg==\",\"context\":\"BTk=\",\"message\":\"I owe you everything\",\"timestamp\":{\"Time\":1527196489,\"ServerUrl\":\"https://metrics.privacybydesign.foundation/atum\",\"Sig\":{\"Alg\":\"ed25519\",\"Data\":\"ZV1qkvDrFK14QrUSC66xTNr9HitCOV4vwfGX0bh3iwY7qyHCi9rIOE97KY8CZifU5oLgVhFWy5E+ALR+gEpACw==\",\"PublicKey\":\"e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8=\"}}}"
	irmaSignedMessage := &SignedMessage{}
	err := json.Unmarshal([]byte(irmaSignedMessageJson), irmaSignedMessage)
	require.NoError(t, err)

	attrs, status, err := irmaSignedMessage.Verify(conf, nil)
	require.NoError(t, err)
	require.Equal(t, ProofStatusValid, status)
	require.Len(t, attrs, 1)
	require.Equal(t, "456", attrs[0][0].Value["en"])
}

func TestVerifyInValidSig(t *testing.T) {
	conf := parseConfiguration(t)

	// Same json as valid case, but has modified c
	irmaSignedMessageJson := "{\"signature\":[{\"c\":\"blablaE7wXcDcKXuBtZW5bnucvBSXpILIRvnNBgx7hQ=\",\"A\":\"D/8wLPq9860bpXZ5c+VYyoPJ+Z8CWDZNQ0jXvst8qnPRdivy/GQIfJHjVnpOPlHbguphb/7JVbfcV3bZeybA3bCF/4UesjRUZlMf/iJ/QgKHbt41ogN1PPT5z7qBJpkxuNTIkHxaUPoDvhouHmuC9pNj4afRUyLJerxKPkpdBw0=\",\"e_response\":\"YOrKTrMSs4/QOUtPkT0YaYNEmW7Cs+cu624zr2xrHodyL88ub6yaXB7MGHAcQ1+iXsGN8jkfxB/0\",\"v_response\":\"AYSa1p8ISs//MsocJjODwWuPB/z6+iKHHi+sTToRs0eJ2X1gwmWoA5QB0aHjRkWye3/+2rtosfUzI77FlPQVnrbMERwcuYM/fx3fpNCpjm2qcs3AOJRcSRxcNFMe1+4ECsmJhByMDutS1KXAAKiNvnhEXx9f0JrQGwQFtpSFPh8dOuvEKUZHAUALr4FcHCa2HL9nDRiqy2KAOxE0nAANAcMaBo/ed+WZeHtv4CTB7egyYs27cklVbwlBzmRrbjNZk57ICd0jVd6SZ2Ir93r/aPejkyhQ03xh9RVVyhOn4bkbjKIBzEybXTJAXgNmvd6F8Ds00srBZVWlo7Z23JZ7\",\"a_responses\":{\"0\":\"QHTznWWrECRNNmUNcy0yGu2L6qsZU6qkvaII8QB8QjbUxpwHzSeJWkzrn/Kk1KIowfoqB1DKGaFLATvuBl+bCoJjea+2VfK9Ns8=\",\"2\":\"H57Y9CTXJ5MAVo+aFfNSbmRMFQpraBIZVOXiRxCD/P7Aw4fW8r9P5l9pO9DTUeExaqFzsLyF5i5EridVWxlP2Wv0zbH8ku9Sg9w=\",\"3\":\"joggAmOhqM4QsKdoLHAfaslzXqJswS7MwZ/5+AKYdkMaHQ45biMdZU/6R+B7bjvsumg2f6KyTyg0G+BI+wVdJOjh3kGezdANB7Y=\",\"5\":\"5YP4A82WWeqc33e5Zg/Q8lqQQ1amLE8mOxMwCXb3N4J0UJRfV9lUFvbH1Q3Yb3YHAZpzGvhN/pBacwqktMkP4L71PnMldqA+nqA=\"},\"a_disclosed\":{\"1\":\"AgAJuwB+AALWy2qU9p3l52l9LU1rVT4M\",\"4\":\"NDU2\"}}],\"nonce\":\"Kg==\",\"context\":\"BTk=\",\"message\":\"I owe you everything\",\"timestamp\":{\"Time\":1527196489,\"ServerUrl\":\"https://metrics.privacybydesign.foundation/atum\",\"Sig\":{\"Alg\":\"ed25519\",\"Data\":\"ZV1qkvDrFK14QrUSC66xTNr9HitCOV4vwfGX0bh3iwY7qyHCi9rIOE97KY8CZifU5oLgVhFWy5E+ALR+gEpACw==\",\"PublicKey\":\"e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8=\"}}}"
	irmaSignedMessage := &SignedMessage{}
	err := json.Unmarshal([]byte(irmaSignedMessageJson), irmaSignedMessage)
	require.NoError(t, err)

	_, status, err := irmaSignedMessage.Verify(conf, nil)
	require.NoError(t, err)
	require.Equal(t, status, ProofStatusInvalid)
}

func TestVerifyInValidNonce(t *testing.T) {
	conf := parseConfiguration(t)

	// Same json as valid case, but with modified nonce
	irmaSignedMessageJson := "{\"signature\":[{\"c\":\"pliyrSE7wXcDcKXuBtZW5bnucvBSXpILIRvnNBgx7hQ=\",\"A\":\"D/8wLPq9860bpXZ5c+VYyoPJ+Z8CWDZNQ0jXvst8qnPRdivy/GQIfJHjVnpOPlHbguphb/7JVbfcV3bZeybA3bCF/4UesjRUZlMf/iJ/QgKHbt41ogN1PPT5z7qBJpkxuNTIkHxaUPoDvhouHmuC9pNj4afRUyLJerxKPkpdBw0=\",\"e_response\":\"YOrKTrMSs4/QOUtPkT0YaYNEmW7Cs+cu624zr2xrHodyL88ub6yaXB7MGHAcQ1+iXsGN8jkfxB/0\",\"v_response\":\"AYSa1p8ISs//MsocJjODwWuPB/z6+iKHHi+sTToRs0eJ2X1gwmWoA5QB0aHjRkWye3/+2rtosfUzI77FlPQVnrbMERwcuYM/fx3fpNCpjm2qcs3AOJRcSRxcNFMe1+4ECsmJhByMDutS1KXAAKiNvnhEXx9f0JrQGwQFtpSFPh8dOuvEKUZHAUALr4FcHCa2HL9nDRiqy2KAOxE0nAANAcMaBo/ed+WZeHtv4CTB7egyYs27cklVbwlBzmRrbjNZk57ICd0jVd6SZ2Ir93r/aPejkyhQ03xh9RVVyhOn4bkbjKIBzEybXTJAXgNmvd6F8Ds00srBZVWlo7Z23JZ7\",\"a_responses\":{\"0\":\"QHTznWWrECRNNmUNcy0yGu2L6qsZU6qkvaII8QB8QjbUxpwHzSeJWkzrn/Kk1KIowfoqB1DKGaFLATvuBl+bCoJjea+2VfK9Ns8=\",\"2\":\"H57Y9CTXJ5MAVo+aFfNSbmRMFQpraBIZVOXiRxCD/P7Aw4fW8r9P5l9pO9DTUeExaqFzsLyF5i5EridVWxlP2Wv0zbH8ku9Sg9w=\",\"3\":\"joggAmOhqM4QsKdoLHAfaslzXqJswS7MwZ/5+AKYdkMaHQ45biMdZU/6R+B7bjvsumg2f6KyTyg0G+BI+wVdJOjh3kGezdANB7Y=\",\"5\":\"5YP4A82WWeqc33e5Zg/Q8lqQQ1amLE8mOxMwCXb3N4J0UJRfV9lUFvbH1Q3Yb3YHAZpzGvhN/pBacwqktMkP4L71PnMldqA+nqA=\"},\"a_disclosed\":{\"1\":\"AgAJuwB+AALWy2qU9p3l52l9LU1rVT4M\",\"4\":\"NDU2\"}}],\"nonce\":\"aa==\",\"context\":\"BTk=\",\"message\":\"I owe you everything\",\"timestamp\":{\"Time\":1527196489,\"ServerUrl\":\"https://metrics.privacybydesign.foundation/atum\",\"Sig\":{\"Alg\":\"ed25519\",\"Data\":\"ZV1qkvDrFK14QrUSC66xTNr9HitCOV4vwfGX0bh3iwY7qyHCi9rIOE97KY8CZifU5oLgVhFWy5E+ALR+gEpACw==\",\"PublicKey\":\"e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8=\"}}}"
	irmaSignedMessage := &SignedMessage{}
	require.NoError(t, json.Unmarshal([]byte(irmaSignedMessageJson), irmaSignedMessage))

	_, status, err := irmaSignedMessage.Verify(conf, nil)
	require.NoError(t, err)
	require.Equal(t, status, ProofStatusInvalid)
}

func TestEmptySignature(t *testing.T) {
	msg := &SignedMessage{}
	_, status, _ := msg.Verify(&Configuration{}, nil)
	require.NotEqual(t, ProofStatusValid, status)
}

// Test attribute decoding with both old and new metadata versions
func TestAttributeDecoding(t *testing.T) {
	expected := "male"

	newAttribute, _ := new(big.Int).SetString("3670202571", 10)
	newString := decodeAttribute(newAttribute, 3)
	require.Equal(t, *newString, expected)

	oldAttribute, _ := new(big.Int).SetString("1835101285", 10)
	oldString := decodeAttribute(oldAttribute, 2)
	require.Equal(t, *oldString, expected)
}

func TestSessionRequests(t *testing.T) {
	attrval := "hello"
	sigMessage := "message to be signed"

	base := &DisclosureRequest{
		BaseRequest: BaseRequest{Type: ActionDisclosing, Version: 2},
		Disclose: AttributeConDisCon{
			AttributeDisCon{
				AttributeCon{NewAttributeRequest("irma-demo.MijnOverheid.ageLimits.over18")},
				AttributeCon{NewAttributeRequest("irma-demo.MijnOverheid.ageLimits.over21")},
			},
			AttributeDisCon{
				AttributeCon{AttributeRequest{Type: NewAttributeTypeIdentifier("irma-demo.MijnOverheid.fullName.firstname"), Value: &attrval}},
			},
		},
		Labels: map[int]TranslatedString{0: trivialTranslation("Age limit"), 1: trivialTranslation("First name")},
	}

	tests := []struct {
		oldJson, currentJson   string
		old, current, expected SessionRequest
	}{
		{
			expected: base,
			old:      &DisclosureRequest{},
			oldJson: `{
				"type": "disclosing",
				"content": [{
					"label": "Age limit",
					"attributes": [
						"irma-demo.MijnOverheid.ageLimits.over18",
						"irma-demo.MijnOverheid.ageLimits.over21"
					]
				},
				{
					"label": "First name",
					"attributes": {
						"irma-demo.MijnOverheid.fullName.firstname": "hello"
					}
				}]
			}`,
			current: &DisclosureRequest{},
			currentJson: `{
				"type": "disclosing",
				"v": 2,
				"disclose": [
					[
						[
							"irma-demo.MijnOverheid.ageLimits.over18"
						],
						[
							"irma-demo.MijnOverheid.ageLimits.over21"
						]
					],
					[
						[
							{ "type": "irma-demo.MijnOverheid.fullName.firstname", "value": "hello" }
						]
					]
				],
				"labels": {
					"0": {
						"en": "Age limit",
						"nl": "Age limit"
					},
					"1": {
						"en": "First name",
						"nl": "First name"
					}
				}
			}`,
		},

		{
			expected: &SignatureRequest{
				DisclosureRequest{BaseRequest{Type: ActionSigning, Version: 2}, base.Disclose, base.Labels},
				sigMessage,
			},
			old: &SignatureRequest{},
			oldJson: `{
				"type": "signing",
				"message": "message to be signed",
				"content": [{
					"label": "Age limit",
					"attributes": [
						"irma-demo.MijnOverheid.ageLimits.over18",
						"irma-demo.MijnOverheid.ageLimits.over21"
					]
				},
				{
					"label": "First name",
					"attributes": {
						"irma-demo.MijnOverheid.fullName.firstname": "hello"
					}
				}]
			}`,
			current: &SignatureRequest{},
			currentJson: `{
				"type": "signing",
				"v": 2,
				"disclose": [
					[
						[
							"irma-demo.MijnOverheid.ageLimits.over18"
						],
						[
							"irma-demo.MijnOverheid.ageLimits.over21"
						]
					],
					[
						[
							{ "type": "irma-demo.MijnOverheid.fullName.firstname", "value": "hello" }
						]
					]
				],
				"labels": {
					"0": {
						"en": "Age limit",
						"nl": "Age limit"
					},
					"1": {
						"en": "First name",
						"nl": "First name"
					}
				},
				"message": "message to be signed"
			}`,
		},

		{
			expected: &IssuanceRequest{
				DisclosureRequest: DisclosureRequest{BaseRequest{Type: ActionIssuing, Version: 2}, base.Disclose, base.Labels},
				Credentials: []*CredentialRequest{
					{
						CredentialTypeID: NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root"),
						Attributes:       map[string]string{"BSN": "12345"},
					},
				},
			},
			old: &IssuanceRequest{},
			oldJson: `{
				"type": "issuing",
				"credentials": [{
					"credential": "irma-demo.MijnOverheid.root",
					"attributes": { "BSN": "12345" }
				}],
				"disclose": [{
					"label": "Age limit",
					"attributes": [
						"irma-demo.MijnOverheid.ageLimits.over18",
						"irma-demo.MijnOverheid.ageLimits.over21"
					]
				},
				{
					"label": "First name",
					"attributes": {
						"irma-demo.MijnOverheid.fullName.firstname": "hello"
					}
				}]
			}`,
			current: &IssuanceRequest{},
			currentJson: `{
				"type": "issuing",
				"v": 2,
				"credentials": [
					{
						"credential": "irma-demo.MijnOverheid.root",
						"attributes": {
							"BSN": "12345"
						}
					}
				],
				"disclose": [
					[
						[
							"irma-demo.MijnOverheid.ageLimits.over18"
						],
						[
							"irma-demo.MijnOverheid.ageLimits.over21"
						]
					],
					[
						[
							{ "type": "irma-demo.MijnOverheid.fullName.firstname", "value": "hello" }
						]
					]
				],
				"labels": {
					"0": {
						"en": "Age limit",
						"nl": "Age limit"
					},
					"1": {
						"en": "First name",
						"nl": "First name"
					}
				}
			}`,
		},
	}

	for _, tst := range tests {
		require.NoError(t, json.Unmarshal([]byte(tst.oldJson), tst.old))
		require.NoError(t, json.Unmarshal([]byte(tst.currentJson), tst.current))
		require.True(t, reflect.DeepEqual(tst.old, tst.expected), "Legacy %s did not unmarshal to expected value", reflect.TypeOf(tst.old).String())
		require.True(t, reflect.DeepEqual(tst.current, tst.expected), "%s did not unmarshal to expected value", reflect.TypeOf(tst.old).String())

		_, err := tst.expected.Legacy()
		require.NoError(t, err)
	}
}

func trivialTranslation(str string) TranslatedString {
	return TranslatedString{"en": str, "nl": str}
}

func TestConDisconSingletons(t *testing.T) {
	tests := []struct {
		attrs   AttributeConDisCon
		allowed bool
	}{
		{
			AttributeConDisCon{
				AttributeDisCon{
					AttributeCon{
						NewAttributeRequest("irma-demo.RU.studentCard.studentID"), // non singleton
						NewAttributeRequest("test.test.email.email"),              // non singleton
					},
				},
			},
			false, // multiple non-singletons in one inner conjunction is not allowed
		},
		{
			AttributeConDisCon{
				AttributeDisCon{
					AttributeCon{
						NewAttributeRequest("irma-demo.RU.studentCard.studentID"), // non singleton
						NewAttributeRequest("test.test.mijnirma.email"),           // singleton
					},
				},
			},
			true,
		},
		{
			AttributeConDisCon{
				AttributeDisCon{
					AttributeCon{
						NewAttributeRequest("irma-demo.MijnOverheid.root.BSN"), // singleton
						NewAttributeRequest("test.test.mijnirma.email"),        // singleton
					},
				},
			},
			true,
		},
	}

	conf := parseConfiguration(t)
	for _, args := range tests {
		if args.allowed {
			require.NoError(t, args.attrs.Validate(conf))
		} else {
			require.Error(t, args.attrs.Validate(conf))
		}
	}
}
