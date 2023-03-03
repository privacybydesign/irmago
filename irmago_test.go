package irma

import (
	"crypto/rand"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/revocation"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/concmap"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func init() {
	common.ForceHTTPS = false // globally disable https enforcement
	Logger.SetLevel(logrus.FatalLevel)
}

func parseConfiguration(t *testing.T) *Configuration {
	conf, err := NewConfiguration("testdata/irma_configuration", ConfigurationOptions{})
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
	storage := test.CreateTestStorage(t)
	defer test.ClearTestStorage(t, nil, storage)

	require.NoError(t, os.Remove(filepath.Join(storage, "client")))
	require.NoError(t, common.CopyDirectory(filepath.Join("testdata", "irma_configuration"), storage))
	conf, err := NewConfiguration(storage, ConfigurationOptions{Assets: filepath.Join("testdata", "irma_configuration_updated")})
	require.NoError(t, err)
	require.NoError(t, conf.ParseFolder())

	credid := NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")
	require.True(t, conf.CredentialTypes[credid].ContainsAttribute(attrid))
	require.Contains(t, conf.RequestorSchemes, NewRequestorSchemeIdentifier("test-requestors"))
	require.Contains(t, conf.Requestors, "localhost")
}

func TestUpdateConfiguration(t *testing.T) {
	storage := test.SetupTestStorage(t)
	defer test.ClearTestStorage(t, nil, storage)
	test.StartSchemeManagerHttpServer()
	defer test.StopSchemeManagerHttpServer()

	conf, err := NewConfiguration(filepath.Join(storage, "client"), ConfigurationOptions{Assets: filepath.Join("testdata", "irma_configuration")})
	require.NoError(t, err)
	require.NoError(t, conf.ParseFolder())

	// first update just a public key. We don't have such an updated scheme in the testdata
	// so we hackily manipulate scheme state to mark it out of date.
	issuerid := NewIssuerIdentifier("irma-demo.MijnOverheid")
	schemeid := NewSchemeManagerIdentifier("irma-demo")
	scheme := conf.SchemeManagers[schemeid]
	scheme.Timestamp = Timestamp(time.Time(scheme.Timestamp).Add(-1000 * time.Hour))
	// modify hash of a public key in the index so it will update the file
	path := "irma-demo/MijnOverheid/PublicKeys/2.xml"
	scheme.index[path][0] = ^scheme.index[path][0]

	updated := newIrmaIdentifierSet()
	require.NoError(t, conf.UpdateScheme(scheme, updated))
	require.Contains(t, updated.PublicKeys, issuerid)
	require.Contains(t, updated.PublicKeys[issuerid], uint(2))

	// next, update to a copy of the scheme in which a credential type was modified
	scheme.URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	updated = newIrmaIdentifierSet()
	require.NoError(t, conf.UpdateScheme(scheme, updated))
	require.Contains(t, updated.CredentialTypes, NewCredentialTypeIdentifier("irma-demo.RU.studentCard"))

	updated = newIrmaIdentifierSet()
	requestorschemeid := NewRequestorSchemeIdentifier("test-requestors")
	requestorscheme := conf.RequestorSchemes[requestorschemeid]
	requestorscheme.URL = "http://localhost:48681/irma_configuration_updated/test-requestors"
	require.NoError(t, conf.UpdateScheme(requestorscheme, updated))
	require.Contains(t, updated.RequestorSchemes, requestorschemeid)
}

func TestParseInvalidIrmaConfiguration(t *testing.T) {
	// The description.xml of the scheme manager under this folder has been edited
	// to invalidate the scheme manager signature
	conf, err := NewConfiguration(filepath.Join("testdata", "irma_configuration_invalid"), ConfigurationOptions{ReadOnly: true})
	require.NoError(t, err)

	// Parsing it should return a SchemeManagerError
	err = conf.ParseFolder()
	require.Error(t, err)
	smerr, ok := err.(*SchemeManagerError)
	require.True(t, ok)
	require.Equal(t, SchemeManagerStatusInvalidSignature, smerr.Status)

	// The manager should still be in conf.SchemeManagers, but also in DisabledSchemeManagers
	id := NewSchemeManagerIdentifier(smerr.Scheme)
	require.Contains(t, conf.SchemeManagers, id)
	require.Contains(t, conf.DisabledSchemeManagers, id)
	require.Equal(t, SchemeManagerStatusInvalidSignature, conf.SchemeManagers[id].Status)
}

func TestParseIrmaConfigurationLeftoverTempDir(t *testing.T) {
	storage := test.SetupTestStorage(t)
	defer test.ClearTestStorage(t, nil, storage)

	confpath := filepath.Join(storage, "client")
	require.NoError(t, common.EnsureDirectoryExists(filepath.Join(confpath, ".tempscheme")))
	require.NoError(t, common.EnsureDirectoryExists(filepath.Join(confpath, ".oldscheme")))
	require.NoError(t, common.EnsureDirectoryExists(filepath.Join(confpath, "tempscheme")))
	require.NoError(t, common.EnsureDirectoryExists(filepath.Join(confpath, "oldscheme")))
	require.NoError(t, common.EnsureDirectoryExists(filepath.Join(confpath, ".foobar")))

	// Parse configuration, the above folders are ignored
	conf, err := NewConfiguration(confpath, ConfigurationOptions{Assets: filepath.Join("testdata", "irma_configuration")})
	require.NoError(t, err)
	require.NoError(t, conf.ParseFolder())

	// These are removed by ParseFolder()
	require.NoError(t, common.AssertPathNotExists(filepath.Join(confpath, ".tempscheme")))
	require.NoError(t, common.AssertPathNotExists(filepath.Join(confpath, ".oldscheme")))
	require.NoError(t, common.AssertPathNotExists(filepath.Join(confpath, "tempscheme")))
	require.NoError(t, common.AssertPathNotExists(filepath.Join(confpath, "oldscheme")))

	// Other dotted dirs are left in place by ParseFolder()
	require.NoError(t, common.AssertPathExists(filepath.Join(confpath, ".foobar")))
}

func TestRetryHTTPRequest(t *testing.T) {
	test.StartBadHttpServer(2, 1*time.Second, "42")
	defer test.StopBadHttpServer()

	transport := NewHTTPTransport("http://localhost:48682", false)
	transport.client.HTTPClient.Timeout = 500 * time.Millisecond
	bts, err := transport.GetBytes("")
	require.NoError(t, err)
	require.Equal(t, "42\n", string(bts))
}

func TestInvalidIrmaConfigurationRestoreFromRemote(t *testing.T) {
	test.StartSchemeManagerHttpServer()
	defer test.StopSchemeManagerHttpServer()

	storage := test.CreateTestStorage(t)
	defer test.ClearTestStorage(t, nil, storage)
	require.NoError(t, os.Remove(filepath.Join(storage, "client")))

	conf, err := NewConfiguration(storage, ConfigurationOptions{
		Assets: filepath.Join("testdata", "irma_configuration_invalid"),
	})
	require.NoError(t, err)

	// check that restoring works
	err = conf.ParseOrRestoreFolder()
	require.NoError(t, err)
	require.Empty(t, conf.DisabledSchemeManagers)

	// switch to correct assets, and parse again to check that ParseOrRestoreFolder
	// left the folder in a consistent state
	conf.assets = filepath.Join("testdata", "irma_configuration")
	err = conf.ParseFolder()
	require.NoError(t, err)
	require.Empty(t, conf.DisabledSchemeManagers)

	require.Contains(t, conf.SchemeManagers, NewSchemeManagerIdentifier("irma-demo"))
	require.Contains(t, conf.CredentialTypes, NewCredentialTypeIdentifier("irma-demo.RU.studentCard"))
}

func TestInvalidIrmaConfigurationRestoreFromAssets(t *testing.T) {
	storage := test.CreateTestStorage(t)
	defer test.ClearTestStorage(t, nil, storage)

	conf, err := NewConfiguration(filepath.Join(storage, "client", "irma_configuration"), ConfigurationOptions{
		Assets: filepath.Join("testdata", "irma_configuration_invalid"),
	})
	require.NoError(t, err)

	// Fails: no remote and the version in the assets is broken
	err = conf.ParseOrRestoreFolder()
	require.Error(t, err)
	require.NotEmpty(t, conf.DisabledSchemeManagers)

	// Try again from correct assets
	conf.assets = filepath.Join("testdata", "irma_configuration")
	err = conf.ParseOrRestoreFolder()
	require.NoError(t, err)
	require.Empty(t, conf.DisabledSchemeManagers)

	// parse again to check that ParseOrRestoreFolder left the folder in a consistent state
	err = conf.ParseFolder()
	require.NoError(t, err)
	require.Empty(t, conf.DisabledSchemeManagers)

	require.Contains(t, conf.SchemeManagers, NewSchemeManagerIdentifier("irma-demo"))
	require.Contains(t, conf.CredentialTypes, NewCredentialTypeIdentifier("irma-demo.RU.studentCard"))
	require.Contains(t, conf.RequestorSchemes, NewRequestorSchemeIdentifier("test-requestors"))
	require.Contains(t, conf.Requestors, "localhost")
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
		"Demo Radboud University Nijmegen",
		conf.Issuers[NewIssuerIdentifier("irma-demo.RU")].Name["en"],
		"irma-demo.RU issuer has unexpected name")
	require.Equal(t,
		"Demo Student Card",
		conf.CredentialTypes[NewCredentialTypeIdentifier("irma-demo.RU.studentCard")].Name["en"],
		"irma-demo.RU.studentCard has unexpected name")

	require.Equal(t,
		"studentID",
		conf.CredentialTypes[NewCredentialTypeIdentifier("irma-demo.RU.studentCard")].AttributeTypes[2].ID,
		"irma-demo.RU.studentCard.studentID has unexpected name")

	// Hash algorithm pseudocode:
	// Base64(SHA256("irma-demo.RU.studentCard")[0:16])
	require.Contains(t, conf.reverseHashes, "1stqlPad5edpfS1Na1U+DA==",
		"irma-demo.RU.studentCard had improper hash")
	require.Contains(t, conf.reverseHashes, "CLjnADMBYlFcuGOT7Z0xRg==",
		"irma-demo.MijnOverheid.root had improper hash")

	id := NewRequestorSchemeIdentifier("test-requestors")
	require.Contains(t, conf.RequestorSchemes, id)
	require.Equal(t, conf.Requestors["localhost"], conf.RequestorSchemes[id].requestors[0])
}

func TestInstallScheme(t *testing.T) {
	test.StartSchemeManagerHttpServer()
	defer test.StopSchemeManagerHttpServer()

	// setup a new empty Configuration
	storage, err := ioutil.TempDir("", "scheme")
	require.NoError(t, err)
	defer test.ClearTestStorage(t, nil, storage)
	conf, err := NewConfiguration(storage, ConfigurationOptions{})
	require.NoError(t, err)
	require.NoError(t, conf.ParseFolder())

	// install test schemes from remote
	require.NoError(t, conf.DangerousTOFUInstallScheme(
		"http://localhost:48681/irma_configuration/test",
	))
	require.NoError(t, conf.DangerousTOFUInstallScheme(
		"http://localhost:48681/irma_configuration/test-requestors",
	))

	require.Contains(t, conf.SchemeManagers, NewSchemeManagerIdentifier("test"))
	require.Contains(t, conf.CredentialTypes, NewCredentialTypeIdentifier("test.test.email"))
	require.Contains(t, conf.RequestorSchemes, NewRequestorSchemeIdentifier("test-requestors"))
	require.Contains(t, conf.Requestors, "localhost")

	require.NoError(t, conf.DangerousTOFUInstallScheme(
		"http://localhost:48681/irma_configuration/irma-demo",
	))
	require.Contains(t, conf.SchemeManagers, NewSchemeManagerIdentifier("irma-demo"))
	require.Contains(t, conf.Issuers, NewIssuerIdentifier("irma-demo.MijnOverheid"))
	sk, err := conf.PrivateKeys.Get(NewIssuerIdentifier("irma-demo.MijnOverheid"), 2)
	require.NoError(t, err)
	require.NotNil(t, sk)
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
	conf, err := NewConfiguration(filepath.Join("testdata", "irma_configuration"), ConfigurationOptions{ReadOnly: true})
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
	require.Equal(t, uint(2), attr.KeyCounter(), "Unexpected key counter")
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
	newString := DecodeAttribute(newAttribute, 3)
	require.Equal(t, *newString, expected)

	oldAttribute, _ := new(big.Int).SetString("1835101285", 10)
	oldString := DecodeAttribute(oldAttribute, 2)
	require.Equal(t, *oldString, expected)
}

func TestSessionRequests(t *testing.T) {
	attrval := "hello"
	sigMessage := "message to be signed"

	base := &DisclosureRequest{
		BaseRequest: BaseRequest{LDContext: LDContextDisclosureRequest},
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
				"@context": "https://irma.app/ld/request/disclosure/v2",
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
				DisclosureRequest{BaseRequest{LDContext: LDContextSignatureRequest}, base.Disclose, base.Labels},
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
				"@context": "https://irma.app/ld/request/signature/v2",
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
				DisclosureRequest: DisclosureRequest{BaseRequest{LDContext: LDContextIssuanceRequest}, base.Disclose, base.Labels},
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
				"@context": "https://irma.app/ld/request/issuance/v2",
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
		tst.old.Base().legacy = false // We don't care about this field differing, override it
		tst.old.Base().Type = ""      // same
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

func parseDisclosure(t *testing.T) (*Configuration, *DisclosureRequest, *Disclosure) {
	conf := parseConfiguration(t)

	requestJson := `{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"zVQJMG6TKZwfcv5TExFVSQ==","protocolVersion":"2.5","disclose":[[["irma-demo.RU.studentCard.studentID"]]],"labels":{"0":null}}`
	dislosureJson := `{"proofs":[{"c":"o21UPItMKWXmXNhBKsCBHDWjfRoy+uDdbDB1yhhpg3k=","A":"Bl68Ut2nu2nwhIweU9QGoNd6TkjUIRbQ6SDg22m8PzMEgca0KA4/Oy1gaJCUHM3FFJ0Gdj0+6/VpcF85JyuQZou93UXXwzN/Y7ohUw+YxVTQ7WcJmZ/VGDh3SME5KJ9aWjGmq61J2LQiiDSq+XrcWFfKPwad6BkDhV2reo4yo68=","e_response":"VD0pWdeDkd3V+R3734xyRcGeWMMTzpB0ZiJhKMzv37DmHN6RpRzTF/0HroAsMIMz8mBWxYPVRBiw","v_response":"3OWsmIDM7v0ByEXax2YZGp3BnJ5nkCLMcT6/ENU0EcpjrOz+rT+NayQSLgMshxAATpgkgAluFQ3owOoQEL8ZAkZTWUDW5j+qy7GDFd22ZOKEZLWf8Q1XRK3x6exV9CIMkcBQrv5W6EI9XB5OKKNB3Z/VTALY3UW8cQQ0DPHj83YBEL3LJQDxwaxvQeHx4nysJjsEoLJE1KPBynXlfxpk17O3HTg+NuX5gj7+ckiHrmXgthJHvqCTnNpEORtXDJTmKJUccUiyWuftA36cIXIxW4N6I88T4BYctwN+T9NY+hcjYESITtxB+r2elB98bzlWgHF8ohpOkkJGuNjTFjw=","a_responses":{"0":"eDQA3Lrh2WC3o/VP6KD/uaMSRy/em3gEfuqXD9tVT+yJFYb7GT91lle5dB6lg235pUSHzYIOET7FYOHwb4/YSAGQiix0IzqFkLo=","2":"kT3kfcIaPy3UBYPX78X10w/R1Cb5rHqoW5OUd06xqC1V9MqVw3zhtc/nBgWmvVwTgJrl2CyuBjjoF10RJz/FEjYZ0JAF57uUXW8=","3":"4oSBcyUT6mOBhk/Szk/5G5QrgaAADW6wSl91hGwTTNDTIUiK01GE11JozbwDeZsLPoFikzikwkPu9ZsOAtOtb/+IcadB6NP0KXA=","5":"OwUSSCBb9NOMOYYSGSYCrdFUNLKJ/b2YP5LlElFG5r4GPR71zTQsZ4QuJiMIt9iFPRP6PQUvMvjWA59UTQ9AlwKc9JcQzbScYBM="},"a_disclosed":{"1":"AwAKOQIBAALWy2qU9p3l52l9LU1rVT4M","4":"aGpt"}}],"indices":[[{"cred":0,"attr":4}]]}`
	request := &DisclosureRequest{}
	require.NoError(t, json.Unmarshal([]byte(requestJson), request))
	disclosure := &Disclosure{}
	require.NoError(t, json.Unmarshal([]byte(dislosureJson), disclosure))

	return conf, request, disclosure
}

func TestVerify(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		conf, request, disclosure := parseDisclosure(t)
		attr, status, err := disclosure.Verify(conf, request)
		require.NoError(t, err)
		require.Equal(t, ProofStatusValid, status)
		require.Equal(t, "456", *attr[0][0].RawValue)
	})

	t.Run("invalid", func(t *testing.T) {
		conf, request, disclosure := parseDisclosure(t)
		disclosure.Proofs[0].(*gabi.ProofD).AResponses[0] = big.NewInt(100)
		_, status, err := disclosure.Verify(conf, request)
		require.NoError(t, err)
		require.Equal(t, ProofStatusInvalid, status)
	})

	t.Run("wrong attribute", func(t *testing.T) {
		conf, request, disclosure := parseDisclosure(t)
		request.Disclose[0][0][0].Type = NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
		_, status, err := disclosure.Verify(conf, request)
		require.NoError(t, err)
		require.Equal(t, ProofStatusMissingAttributes, status)
	})

	t.Run("wrong nonce", func(t *testing.T) {
		conf, request, disclosure := parseDisclosure(t)
		request.Nonce = big.NewInt(100)
		_, status, err := disclosure.Verify(conf, request)
		require.NoError(t, err)
		require.Equal(t, ProofStatusInvalid, status)
	})
}

var (
	revocationTestCred  = NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")
	revocationPkCounter = uint(2)
)

func TestRevocationMemoryStore(t *testing.T) {
	conf := parseConfiguration(t)
	db := conf.Revocation.memdb
	require.NotNil(t, db)

	// prepare key material
	sk, err := conf.Revocation.Keys.PrivateKey(revocationTestCred.IssuerIdentifier(), revocationPkCounter)
	require.NoError(t, err)
	pk, err := conf.Revocation.Keys.PublicKey(revocationTestCred.IssuerIdentifier(), revocationPkCounter)
	require.NoError(t, err)

	// construct initial update
	update, err := revocation.NewAccumulator(sk)
	require.NoError(t, err)

	// insert and retrieve it and check its validity
	db.Insert(revocationTestCred, update)
	retrieve(t, pk, db, 0, 0)

	// construct new update message with a few revocation events
	update = revokeMultiple(t, sk, update)
	oldupdate := *update // save a copy for below

	// insert it, retrieve it with a varying amount of events, verify
	db.Insert(revocationTestCred, update)
	retrieve(t, pk, db, 4, 3)

	// construct and test against a new update whose events have no overlap with that of our db
	update = revokeMultiple(t, sk, update)
	update.Events = update.Events[4:]
	require.Equal(t, uint64(4), update.Events[0].Index)
	db.Insert(revocationTestCred, update)
	retrieve(t, pk, db, 4, 6)

	// attempt to insert an update that is too new
	update = revokeMultiple(t, sk, update)
	update.Events = update.Events[5:]
	require.Equal(t, uint64(9), update.Events[0].Index)
	db.Insert(revocationTestCred, update)
	retrieve(t, pk, db, 4, 6)

	// attempt to insert an update that is too old
	db.Insert(revocationTestCred, &oldupdate)
	retrieve(t, pk, db, 4, 6)
}

func revokeMultiple(t *testing.T, sk *gabikeys.PrivateKey, update *revocation.Update) *revocation.Update {
	acc := update.SignedAccumulator.Accumulator
	event := update.Events[len(update.Events)-1]
	events := update.Events
	for i := 0; i < 3; i++ {
		acc, event = revoke(t, acc, event, sk)
		events = append(events, event)
	}
	update, err := revocation.NewUpdate(sk, acc, events)
	require.NoError(t, err)
	return update
}

func retrieve(t *testing.T, pk *gabikeys.PublicKey, db *memRevStorage, count uint64, expectedIndex uint64) {
	var updates map[uint]*revocation.Update
	var err error
	for i := uint64(0); i <= count; i++ {
		updates = db.Latest(revocationTestCred, i)
		require.Len(t, updates, 1)
		require.NotNil(t, updates[revocationPkCounter])
		require.Len(t, updates[revocationPkCounter].Events, int(i))
		_, err = updates[revocationPkCounter].Verify(pk)
		require.NoError(t, err)
	}
	sacc := db.SignedAccumulator(revocationTestCred, revocationPkCounter)
	acc, err := sacc.UnmarshalVerify(pk)
	require.NoError(t, err)
	require.Equal(t, expectedIndex, acc.Index)
}

func revoke(t *testing.T, acc *revocation.Accumulator, parent *revocation.Event, sk *gabikeys.PrivateKey) (*revocation.Accumulator, *revocation.Event) {
	e, err := rand.Prime(rand.Reader, 100)
	require.NoError(t, err)
	acc, event, err := acc.Remove(sk, big.Convert(e), parent)
	require.NoError(t, err)
	return acc, event
}

func TestPrivateKeyRings(t *testing.T) {
	conf := parseConfiguration(t)
	mo := NewIssuerIdentifier("irma-demo.MijnOverheid")
	ru := NewIssuerIdentifier("irma-demo.RU")
	tst := NewIssuerIdentifier("test.test")

	schemering, err := newPrivateKeyRingScheme(conf)
	require.NoError(t, err)
	_, err = schemering.Get(mo, 2)
	require.NoError(t, err)
	_, err = schemering.Latest(mo)
	require.NoError(t, err)
	_, err = schemering.Get(ru, 2)
	require.Error(t, err) // not present in scheme
	_, err = schemering.Latest(ru)
	require.Error(t, err) // not present in scheme

	folderring, err := NewPrivateKeyRingFolder(filepath.Join(test.FindTestdataFolder(t), "privatekeys"), conf)
	require.NoError(t, err)
	_, err = folderring.Get(mo, 2)
	require.Error(t, err) // not present in folder
	_, err = folderring.Get(mo, 1)
	require.NoError(t, err) // present in both
	_, err = folderring.Get(ru, 2)
	require.NoError(t, err)
	_, err = folderring.Latest(ru)
	require.NoError(t, err)
	_, err = folderring.Get(tst, 3)
	require.NoError(t, err)
	_, err = folderring.Latest(tst)
	require.NoError(t, err)

	mergedring := privateKeyRingMerge{rings: []PrivateKeyRing{schemering, folderring}}
	_, err = mergedring.Get(mo, 1)
	require.NoError(t, err) // present in both
	_, err = mergedring.Get(mo, 2)
	require.NoError(t, err)
	_, err = mergedring.Latest(mo)
	require.NoError(t, err)
	_, err = mergedring.Get(ru, 2)
	require.NoError(t, err)
	_, err = mergedring.Latest(ru)
	require.NoError(t, err)
}

// Helper functions for wizard tests below
func credid(s string) CredentialTypeIdentifier {
	return NewCredentialTypeIdentifier(s)
}
func credidptr(s string) *CredentialTypeIdentifier {
	id := credid(s)
	return &id
}
func credinfo(id string) *CredentialInfo {
	i := credid(id)
	return &CredentialInfo{
		SchemeManagerID: i.Root(),
		IssuerID:        i.IssuerIdentifier().Name(),
		ID:              i.Name(),
	}
}
func credtype(id string, deps ...string) *CredentialType {
	i := credid(id)
	d := CredentialDependencies{{{}}}
	for _, dep := range deps {
		d[0][0] = append(d[0][0], credid(dep))
	}
	return &CredentialType{
		SchemeManagerID: i.Root(),
		IssuerID:        i.IssuerIdentifier().Name(),
		ID:              i.Name(),
		Dependencies:    d,
	}
}
func credwizarditem(id string) IssueWizardItem {
	return IssueWizardItem{Type: IssueWizardItemTypeCredential, Credential: credidptr(id)}
}

func TestWizardDependencies(t *testing.T) {
	dependencies := CredentialDependencies{
		{
			{credid("a.a.a"), credid("a.a.b")},
			{credid("a.b.a")},
		},
		{
			{credid("b.a.a")},
			{credid("b.b.a"), credid("b.b.b")},
		},
	}

	wizardcontents := dependencies.WizardContents()
	require.Equal(t,
		IssueWizardContents{
			{
				{credwizarditem("a.a.a"), credwizarditem("a.a.b")},
				{credwizarditem("a.b.a")},
			},
			{
				{credwizarditem("b.a.a")},
				{credwizarditem("b.b.a"), credwizarditem("b.b.b")},
			},
		},
		wizardcontents,
	)

	conf := &Configuration{CredentialTypes: map[CredentialTypeIdentifier]*CredentialType{}}
	for _, discon := range dependencies {
		for _, con := range discon {
			for _, cred := range con {
				conf.CredentialTypes[cred] = credtype(cred.String())
			}
		}
	}
	tests := []struct {
		creds  map[CredentialTypeIdentifier]struct{}
		wizard []IssueWizardItem
	}{
		{
			creds: nil,
			wizard: []IssueWizardItem{
				credwizarditem("a.a.a"), credwizarditem("a.a.b"), credwizarditem("b.a.a"),
			},
		},
		{
			creds: map[CredentialTypeIdentifier]struct{}{credid("a.a.a"): {}},
			wizard: []IssueWizardItem{
				credwizarditem("a.a.a"), credwizarditem("a.a.b"), credwizarditem("b.a.a"),
			},
		},
		{
			creds: map[CredentialTypeIdentifier]struct{}{credid("a.b.a"): {}},
			wizard: []IssueWizardItem{
				credwizarditem("a.b.a"), credwizarditem("b.a.a"),
			},
		},
		{
			creds: map[CredentialTypeIdentifier]struct{}{credid("b.b.a"): {}},
			wizard: []IssueWizardItem{
				credwizarditem("a.a.a"), credwizarditem("a.a.b"), credwizarditem("b.a.a"),
			},
		},
		{
			creds: map[CredentialTypeIdentifier]struct{}{credid("b.b.a"): {}, credid("b.b.b"): {}},
			wizard: []IssueWizardItem{
				credwizarditem("a.a.a"), credwizarditem("a.a.b"), credwizarditem("b.b.a"), credwizarditem("b.b.b"),
			},
		},
	}

	for _, tst := range tests {
		require.Equal(t, tst.wizard, wizardcontents.ChoosePath(conf, tst.creds))
	}
}

func TestWizardConstructed(t *testing.T) {
	conf := &Configuration{
		CredentialTypes: map[CredentialTypeIdentifier]*CredentialType{
			credid("scheme.issuer.a"): credtype("scheme.issuer.a"),
			credid("scheme.issuer.b"): credtype("scheme.issuer.b",
				"scheme.issuer.a",
			),
			credid("scheme.issuer.c"): credtype("scheme.issuer.c",
				"scheme.issuer.a", "scheme.issuer.b",
			),
			credid("scheme.issuer.d"): credtype("scheme.issuer.d",
				"scheme.issuer.a",
			),
			credid("scheme.issuer.e"): credtype("scheme.issuer.e",
				"scheme.issuer.d",
			),
		},
	}

	wizard := IssueWizard{
		ID: NewIssueWizardIdentifier("test-requestors.test-requestor.testwizard"),
		Contents: IssueWizardContents{
			{{
				credwizarditem("scheme.issuer.c"),
			}},
			{{{
				Type:       IssueWizardItemTypeCredential,
				Credential: credidptr("scheme.issuer.e"),
				Text:       &TranslatedString{"en": "custom description of credential e"},
			}}},
			{{{
				Type: IssueWizardItemTypeWebsite,
				URL:  &TranslatedString{"en": "https://example.com"},
			}}},
		},
	}

	contents, err := wizard.Path(conf, nil)
	require.NoError(t, err)
	require.Equal(t,
		[]IssueWizardItem{
			credwizarditem("scheme.issuer.a"),
			credwizarditem("scheme.issuer.b"),
			credwizarditem("scheme.issuer.c"),
			credwizarditem("scheme.issuer.d"),
			wizard.Contents[1][0][0],
			wizard.Contents[2][0][0],
		},
		contents,
	)
}

func TestWizardFromScheme(t *testing.T) {
	conf := parseConfiguration(t)
	id := NewIssueWizardIdentifier("test-requestors.test-requestor.testwizard")
	wizard := conf.Requestors["localhost"].Wizards[id]

	var expected []IssueWizardItem
	require.NoError(t, json.Unmarshal(
		[]byte(`[{"type":"credential","credential":"irma-demo.MijnOverheid.fullName","header":{"en":"Full name","nl":"Volledige naam"},"text":{"en":"Lorem ipsum dolor sit amet, consectetur adipiscing elit.","nl":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."},"label":{"en":"Get name data","nl":"Haal naamgegevens op"}},{"type":"credential","credential":"irma-demo.MijnOverheid.singleton","text":{"en":"Lorem ipsum dolor sit amet, consectetur adipiscing elit.","nl":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}},{"type":"session","credential":"irma-demo.RU.studentCard","header":{"en":"Student Card","nl":"Studentpas"},"text":{"en":"Lorem ipsum dolor sit amet, consectetur adipiscing elit.","nl":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."},"label":{"en":"Get Student Card","nl":"Haal studentpas op"},"sessionUrl":"https://example.com/getsession"},{"type":"website","credential":"irma-demo.stemmen.stempas","header":{"en":"Voting Card","nl":"Stempas"},"text":{"en":"Lorem ipsum dolor sit amet, consectetur adipiscing elit.","nl":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."},"label":{"en":"Get Voting Card","nl":"Haal stempas op"},"url":{"en":"https://example.com/en","nl":"https://example.com/nl"},"inapp":true}]`),
		&expected,
	))

	contents, err := wizard.Path(conf, nil)
	require.NoError(t, err)
	require.Equal(t, expected, contents)

	True := true
	wizard.ExpandDependencies = &True
	contents, err = wizard.Path(conf, nil)
	require.NoError(t, err)
	require.Equal(t,
		append([]IssueWizardItem{credwizarditem("irma-demo.MijnOverheid.root")}, expected...),
		contents,
	)
}

func TestWizardValidation(t *testing.T) {
	conf := &Configuration{
		CredentialTypes: map[CredentialTypeIdentifier]*CredentialType{
			credid("scheme.issuer.a"): credtype("scheme.issuer.a"),
			credid("scheme.issuer.b"): credtype("scheme.issuer.b",
				"scheme.issuer.a",
			),
			credid("scheme.issuer.c"): credtype("scheme.issuer.c",
				"scheme.issuer.a", "scheme.issuer.b",
			),
			credid("scheme.issuer.d"): credtype("scheme.issuer.d",
				"scheme.issuer.a",
			),
			credid("scheme.issuer.e"): credtype("scheme.issuer.e",
				"scheme.issuer.d",
			),
		},
	}

	wizard := IssueWizard{
		ID: NewIssueWizardIdentifier("testwizard"),
		Contents: IssueWizardContents{
			{{
				credwizarditem("scheme.issuer.c"),
			}},
			{{{
				Type:       IssueWizardItemTypeCredential,
				Credential: credidptr("scheme.issuer.e"),
				Text:       &TranslatedString{"en": "custom description of credential e"},
			}}},
			{{{
				Type:   IssueWizardItemTypeWebsite,
				Header: &TranslatedString{"en": "header"},
				Label:  &TranslatedString{"en": "label"},
				Text:   &TranslatedString{"en": "text"},
				URL:    &TranslatedString{"en": "https://example.com"},
			}}},
		},
	}

	require.NoError(t, wizard.Validate(conf))

	wizard.SuccessText = (*TranslatedString)(&map[string]string{"en": "foo"})
	wizard.SuccessHeader = nil
	require.EqualError(t, wizard.Validate(conf), "wizard contents must have success header and text either both specified, or both empty")

	wizard.SuccessText = nil
	wizard.SuccessHeader = (*TranslatedString)(&map[string]string{"en": "foo"})
	require.EqualError(t, wizard.Validate(conf), "wizard contents must have success header and text either both specified, or both empty")

	wizard.SuccessText = nil
	wizard.SuccessHeader = nil
	require.NoError(t, wizard.Validate(conf))

	wizard.SuccessText = (*TranslatedString)(&map[string]string{"en": "foo"})
	wizard.SuccessHeader = (*TranslatedString)(&map[string]string{"en": "foo"})
	require.NoError(t, wizard.Validate(conf))

	invalidColor1 := "123"
	wizard.Color = &invalidColor1
	require.EqualError(t, wizard.Validate(conf), "invalid wizard color: must be of the form #RRGGBB")

	invalidColor2 := "123ABC"
	wizard.Color = &invalidColor2
	require.EqualError(t, wizard.Validate(conf), "invalid wizard color: must be of the form #RRGGBB")

	wizard.Color = nil
	require.NoError(t, wizard.Validate(conf))

	validColor := "#123ABC"
	wizard.Color = &validColor
	require.NoError(t, wizard.Validate(conf))

	wizard.TextColor = &invalidColor1
	require.EqualError(t, wizard.Validate(conf), "invalid wizard text color: must be of the form #RRGGBB")

	wizard.TextColor = &invalidColor2
	require.EqualError(t, wizard.Validate(conf), "invalid wizard text color: must be of the form #RRGGBB")

	wizard.TextColor = nil
	require.NoError(t, wizard.Validate(conf))

	wizard.TextColor = &validColor
	require.NoError(t, wizard.Validate(conf))
}

func TestWizardIncorrectContentsOrder(t *testing.T) {
	conf := &Configuration{
		CredentialTypes: map[CredentialTypeIdentifier]*CredentialType{
			credid("scheme.issuer.a"): credtype("scheme.issuer.a"),
			credid("scheme.issuer.b"): credtype("scheme.issuer.b",
				"scheme.issuer.a",
			),
			credid("scheme.issuer.c"): credtype("scheme.issuer.c",
				"scheme.issuer.a", "scheme.issuer.b",
			),
			credid("scheme.issuer.d"): credtype("scheme.issuer.d",
				"scheme.issuer.a",
			),
			credid("scheme.issuer.e"): credtype("scheme.issuer.e",
				"scheme.issuer.d",
			),
		},
	}

	wizard := IssueWizard{
		ID: NewIssueWizardIdentifier("testwizard"),
		Contents: IssueWizardContents{
			{{
				credwizarditem("scheme.issuer.c"),
			}},
			{{{
				Type:   IssueWizardItemTypeWebsite,
				Header: &TranslatedString{"en": "header"},
				Label:  &TranslatedString{"en": "label"},
				Text:   &TranslatedString{"en": "text"},
				URL:    &TranslatedString{"en": "https://example.com"},
			}}},
			{{{
				Type:       IssueWizardItemTypeCredential,
				Credential: credidptr("scheme.issuer.e"),
				Text:       &TranslatedString{"en": "custom description of credential e"},
			}}},
		},
	}

	err := wizard.Validate(conf)
	require.EqualError(t, err, "items having no credential type should come last")
}

func TestWizardComplexity(t *testing.T) {
	conf := &Configuration{
		CredentialTypes: map[CredentialTypeIdentifier]*CredentialType{
			credid("scheme.issuer.a"): credtype("scheme.issuer.a"),
			credid("scheme.issuer.b"): credtype("scheme.issuer.b",
				"scheme.issuer.a",
			),
			credid("scheme.issuer.c"): credtype("scheme.issuer.c",
				"scheme.issuer.a", "scheme.issuer.b",
			),
			credid("scheme.issuer.d"): credtype("scheme.issuer.d",
				"scheme.issuer.a",
			),
			credid("scheme.issuer.e"): credtype("scheme.issuer.e",
				"scheme.issuer.d",
			),
			credid("scheme.issuer.f"): credtype("scheme.issuer.f",
				"scheme.issuer.a",
			),
			credid("scheme.issuer.g"): credtype("scheme.issuer.g",
				"scheme.issuer.a", "scheme.issuer.b",
			),
			credid("scheme.issuer.h"): credtype("scheme.issuer.h",
				"scheme.issuer.a",
			),
			credid("scheme.issuer.i"): credtype("scheme.issuer.i",
				"scheme.issuer.d",
			),
			credid("scheme.issuer.j"): credtype("scheme.issuer.j"),
		},
	}

	wizard := IssueWizard{
		ID: NewIssueWizardIdentifier("testwizard"),
		Contents: IssueWizardContents{
			{{
				credwizarditem("scheme.issuer.c"),
			}},
			{{
				credwizarditem("scheme.issuer.d"),
			}},
			{{
				credwizarditem("scheme.issuer.e"),
			}},
			{{
				credwizarditem("scheme.issuer.f"),
			}},
			{{
				credwizarditem("scheme.issuer.g"),
			}},
			{{
				credwizarditem("scheme.issuer.h"),
			}},
			{{
				credwizarditem("scheme.issuer.i"),
			}},
			{{{
				Type:       IssueWizardItemTypeCredential,
				Credential: credidptr("scheme.issuer.j"),
				Text:       &TranslatedString{"en": "custom description of credential j"},
			}}},
			{{{
				Type:   IssueWizardItemTypeWebsite,
				Header: &TranslatedString{"en": "header"},
				Label:  &TranslatedString{"en": "label"},
				Text:   &TranslatedString{"en": "text"},
				URL:    &TranslatedString{"en": "https://example.com"},
			}}},
		},
	}

	err := wizard.Validate(conf)
	require.EqualError(t, err, "wizard too complex")
}

func TestIssueWizardItemValidation(t *testing.T) {
	conf := &Configuration{CredentialTypes: map[CredentialTypeIdentifier]*CredentialType{}}

	credTypeID := credid("a.a.a")
	conf.CredentialTypes[credTypeID] = credtype(credTypeID.String())
	tester := IssueWizardItem{Type: IssueWizardItemTypeCredential, Credential: &credTypeID, Text: &TranslatedString{"en": "text", "nl": "tekst"}}
	schemeMan := SchemeManager{}
	conf.SchemeManagers = map[SchemeManagerIdentifier]*SchemeManager{credTypeID.SchemeManagerIdentifier(): &schemeMan}

	credTypeID2 := credid("a.b.a")
	conf.CredentialTypes[credTypeID2] = credtype(credTypeID2.String())
	conf.CredentialTypes[credTypeID].Dependencies = CredentialDependencies{
		{
			{credTypeID2},
		},
	}

	translation := trivialTranslation("Age limit")
	conf.CredentialTypes[credTypeID2].FAQSummary = &translation

	require.NoError(t, tester.validate(conf))
}

func TestIssueWizardFAQSummariesValidation(t *testing.T) {
	conf := &Configuration{CredentialTypes: map[CredentialTypeIdentifier]*CredentialType{}}

	credTypeID := credid("a.a.a")
	credTypeID2 := credid("a.b.a")
	conf.CredentialTypes[credTypeID] = credtype(credTypeID.String())
	conf.CredentialTypes[credTypeID2] = credtype(credTypeID2.String())
	tester := IssueWizardItem{
		Type:       IssueWizardItemTypeCredential,
		Credential: &credTypeID,
		languages:  []string{"en", "nl"},
	}
	schemeMan := SchemeManager{}
	conf.SchemeManagers = map[SchemeManagerIdentifier]*SchemeManager{credTypeID.SchemeManagerIdentifier(): &schemeMan}

	require.EqualError(t, tester.validate(conf), "FAQSummary missing for wizard item with credential type: a.a.a")

	tester.Text = &TranslatedString{"en": "text"}
	require.EqualError(t, tester.validate(conf), "Wizard item text field incomplete for item with credential type: a.a.a")

	tester.Text = nil
	conf.CredentialTypes[credTypeID].FAQSummary = &TranslatedString{"en": "text"}
	require.EqualError(t, tester.validate(conf), "FAQSummary missing for: a.a.a")

	tester.Text = &TranslatedString{"en": "text", "nl": "tekst"}
	conf.CredentialTypes[credTypeID].Dependencies = CredentialDependencies{
		{
			{credid("a.b.a")},
		},
	}
	require.EqualError(t, tester.validate(conf), "FAQSummary missing for last item in chain: a.a.a, a.b.a")
}

func TestCircularDependenciesValidation(t *testing.T) {
	credTypeIDA := credid("scheme.issuer.a")
	credTypeA := credtype("scheme.issuer.a")
	conf := &Configuration{
		CredentialTypes: map[CredentialTypeIdentifier]*CredentialType{
			credTypeIDA: credTypeA,
			credid("scheme.issuer.b"): credtype("scheme.issuer.b",
				"scheme.issuer.a",
			),
			credid("scheme.issuer.c"): credtype("scheme.issuer.c",
				"scheme.issuer.a", "scheme.issuer.b",
			),
			credid("scheme.issuer.d"): credtype("scheme.issuer.d",
				"scheme.issuer.a",
			),
			credid("scheme.issuer.e"): credtype("scheme.issuer.e",
				"scheme.issuer.d",
			),
		},
	}

	err := credTypeA.validateDependencies(conf, []CredentialTypeIdentifier{}, credTypeIDA)
	require.NoError(t, err)
}

func TestCircularDependenciesError(t *testing.T) {
	credTypeIDA := credid("scheme.issuer.a")
	credTypeA := credtype("scheme.issuer.a", "scheme.issuer.b")
	conf := &Configuration{
		CredentialTypes: map[CredentialTypeIdentifier]*CredentialType{
			credTypeIDA: credTypeA,
			credid("scheme.issuer.b"): credtype("scheme.issuer.b",
				"scheme.issuer.a",
			),
		},
	}

	err := credTypeA.validateDependencies(conf, []CredentialTypeIdentifier{}, credTypeIDA)
	require.EqualError(t, err, "No valid dependency branch could be built. There might be a circular dependency.")
}

func TestDependencyOfOtherSchemeError(t *testing.T) {
	credTypeIDX := credid("otherScheme.someIssuer.x")
	credTypeX := credtype("otherScheme.someIssuer.x", "scheme.issuer.a")

	conf := &Configuration{
		CredentialTypes: map[CredentialTypeIdentifier]*CredentialType{
			credid("scheme.issuer.a"): credtype("scheme.issuer.a"),
			credTypeIDX:               credTypeX,
		},
	}

	err := credTypeX.validateDependencies(conf, []CredentialTypeIdentifier{}, credTypeIDX)
	require.EqualError(t, err, "credential type otherScheme.someIssuer.x in scheme otherScheme has dependency outside the scheme: scheme.issuer.a")
}

func TestDependencyComplexityError(t *testing.T) {
	credTypeIDZ := credid("scheme.issuer.z")
	credTypeZ := credtype("scheme.issuer.z", "scheme.issuer.y")
	conf := &Configuration{
		CredentialTypes: map[CredentialTypeIdentifier]*CredentialType{
			credid("scheme.issuer.a"): credtype("scheme.issuer.a"),
			credid("scheme.issuer.b"): credtype("scheme.issuer.b",
				"scheme.issuer.a"),
			credid("scheme.issuer.c"): credtype("scheme.issuer.c",
				"scheme.issuer.b"),
			credid("scheme.issuer.d"): credtype("scheme.issuer.d",
				"scheme.issuer.c"),
			credid("scheme.issuer.e"): credtype("scheme.issuer.e",
				"scheme.issuer.d"),
			credid("scheme.issuer.f"): credtype("scheme.issuer.f",
				"scheme.issuer.e"),
			credid("scheme.issuer.g"): credtype("scheme.issuer.g",
				"scheme.issuer.f"),
			credid("scheme.issuer.h"): credtype("scheme.issuer.h",
				"scheme.issuer.g"),
			credid("scheme.issuer.i"): credtype("scheme.issuer.i",
				"scheme.issuer.h"),
			credid("scheme.issuer.j"): credtype("scheme.issuer.j",
				"scheme.issuer.i"),
			credid("scheme.issuer.k"): credtype("scheme.issuer.k",
				"scheme.issuer.j"),
			credid("scheme.issuer.l"): credtype("scheme.issuer.l",
				"scheme.issuer.k"),
			credid("scheme.issuer.m"): credtype("scheme.issuer.m",
				"scheme.issuer.l"),
			credid("scheme.issuer.n"): credtype("scheme.issuer.n",
				"scheme.issuer.m"),
			credid("scheme.issuer.o"): credtype("scheme.issuer.o",
				"scheme.issuer.n"),
			credid("scheme.issuer.p"): credtype("scheme.issuer.p",
				"scheme.issuer.o"),
			credid("scheme.issuer.q"): credtype("scheme.issuer.q",
				"scheme.issuer.p"),
			credid("scheme.issuer.r"): credtype("scheme.issuer.r",
				"scheme.issuer.q"),
			credid("scheme.issuer.s"): credtype("scheme.issuer.s",
				"scheme.issuer.r"),
			credid("scheme.issuer.t"): credtype("scheme.issuer.t",
				"scheme.issuer.s"),
			credid("scheme.issuer.u"): credtype("scheme.issuer.u",
				"scheme.issuer.t"),
			credid("scheme.issuer.v"): credtype("scheme.issuer.v",
				"scheme.issuer.u"),
			credid("scheme.issuer.w"): credtype("scheme.issuer.w",
				"scheme.issuer.v"),
			credid("scheme.issuer.x"): credtype("scheme.issuer.x",
				"scheme.issuer.w"),
			credid("scheme.issuer.y"): credtype("scheme.issuer.y",
				"scheme.issuer.x"),
			credTypeIDZ: credTypeZ,
		},
	}

	err := credTypeZ.validateDependencies(conf, []CredentialTypeIdentifier{}, credTypeIDZ)
	require.EqualError(t, err, "dependency tree too complex: scheme.issuer.y, "+
		"scheme.issuer.x, scheme.issuer.w, scheme.issuer.v, scheme.issuer.u, scheme.issuer.t, "+
		"scheme.issuer.s, scheme.issuer.r, scheme.issuer.q, scheme.issuer.p, scheme.issuer.o, "+
		"scheme.issuer.n, scheme.issuer.m, scheme.issuer.l, scheme.issuer.k, scheme.issuer.j, "+
		"scheme.issuer.i, scheme.issuer.h, scheme.issuer.g, scheme.issuer.f, scheme.issuer.e, "+
		"scheme.issuer.d, scheme.issuer.c, scheme.issuer.b, scheme.issuer.a")
}

func TestCredentialDependencies_UnmarshalXML(t *testing.T) {
	xmlbts := []byte(`<Dependencies>
		<Or>
			<And>
				<CredentialType>a</CredentialType>
				<CredentialType>b</CredentialType>
			</And>
			<And>
				<CredentialType>c</CredentialType>
			</And>
		</Or>
		<Or>
			<And>
				<CredentialType>d</CredentialType>
			</And>
			<And>
				<CredentialType>e</CredentialType>
				<CredentialType>f</CredentialType>
			</And>
		</Or>
	</Dependencies>`)

	var deps CredentialDependencies
	require.NoError(t, xml.Unmarshal(xmlbts, &deps))

	require.Equal(t,
		CredentialDependencies{
			{
				{credid("a"), credid("b")},
				{credid("c")},
			},
			{
				{credid("d")},
				{credid("e"), credid("f")},
			},
		},
		deps,
	)
}

func TestSchemeLanguageValidation(t *testing.T) {
	conf := parseConfiguration(t)
	langs := []string{"en", "nl"}
	testScheme := conf.SchemeManagers[NewSchemeManagerIdentifier("test")]

	// - The test scheme misses some translations but has no languages defined
	// - The irma-demo and test-requestors schemes have en, nl defined and everything is translated
	// So there should be no translation warnings.
	require.Empty(t, conf.Warnings)

	// Override test scheme language and parse again
	testScheme.Languages = langs
	require.NoError(t, testScheme.parseContents(conf))
	require.Equal(t, []string{
		"Credential type test.test.email misses en translation in <IssueURL> tag",
		"Credential type test.test.email misses nl translation in <IssueURL> tag",
		"Credential type test.test.mijnirma misses en translation in <IssueURL> tag",
		"Credential type test.test.mijnirma misses nl translation in <IssueURL> tag",
	}, conf.Warnings)

	// Validate some individual translated strings
	require.Empty(t, testScheme.Description.validate(langs))
	require.Equal(t, langs, conf.CredentialTypes[NewCredentialTypeIdentifier("test.test.email")].IssueURL.validate(langs))
}

func TestDeleteScheme(t *testing.T) {
	test.StartSchemeManagerHttpServer()
	defer test.StopSchemeManagerHttpServer()

	// Select a subset of schemes such that we can add additional schemes later.
	assetsDir := t.TempDir()
	readOnlySchemes := []SchemeManagerIdentifier{
		NewSchemeManagerIdentifier("irma-demo"),
		NewSchemeManagerIdentifier("test"),
	}
	for _, scheme := range readOnlySchemes {
		err := common.CopyDirectory(
			path.Join("testdata/irma_configuration/", scheme.String()),
			path.Join(assetsDir, scheme.String()),
		)
		require.NoError(t, err)
	}

	conf, err := NewConfiguration(t.TempDir(), ConfigurationOptions{Assets: assetsDir})
	require.NoError(t, err)

	err = conf.ParseFolder()
	require.NoError(t, err)
	for _, scheme := range readOnlySchemes {
		require.Contains(t, conf.SchemeManagers, scheme)
	}

	schemeToInstall := NewSchemeManagerIdentifier("test2")
	pkBytes, err := os.ReadFile(fmt.Sprintf("testdata/irma_configuration/%s/pk.pem", schemeToInstall))
	require.NoError(t, err)

	err = conf.InstallScheme("http://localhost:48681/irma_configuration/"+schemeToInstall.String(), pkBytes)
	require.NoError(t, err)
	require.Contains(t, conf.SchemeManagers, schemeToInstall)
	for _, scheme := range readOnlySchemes {
		require.Contains(t, conf.SchemeManagers, scheme)
	}

	// Check that we cannot delete a read-only asset scheme.
	err = conf.DangerousDeleteScheme(conf.SchemeManagers[readOnlySchemes[0]])
	require.Error(t, err)
	require.Contains(t, conf.SchemeManagers, schemeToInstall)
	for _, scheme := range readOnlySchemes {
		require.Contains(t, conf.SchemeManagers, scheme)
	}

	err = conf.DangerousDeleteScheme(conf.SchemeManagers[schemeToInstall])
	require.NoError(t, err)
	require.NotContains(t, conf.SchemeManagers, schemeToInstall)
	for _, scheme := range readOnlySchemes {
		require.Contains(t, conf.SchemeManagers, scheme)
	}
}

func TestParseKeysFolderConcurrency(t *testing.T) {
	conf := parseConfiguration(t)
	grp := sync.WaitGroup{}

	for j := 0; j < 1000; j++ {
		// Clear map for next iteration
		conf.publicKeys = concmap.New[PublicKeyIdentifier, *gabikeys.PublicKey]()

		for i := 0; i < 10; i++ {
			grp.Add(1)
			go func() {
				require.NoError(t, conf.parseKeysFolder(NewIssuerIdentifier("irma-demo.MijnOverheid")))
				grp.Done()
			}()
		}

		grp.Wait()
	}
}

func TestInstallSchemeUnstableRemote(t *testing.T) {
	testSchemeID := NewSchemeManagerIdentifier("test")
	testSchemeURL := "http://localhost:48681/irma_configuration/test"

	// Host test scheme with a directory missing to simulate network issues.
	corruptTestData := t.TempDir()
	err := common.CopyDirectory(test.FindTestdataFolder(t), corruptTestData)
	require.NoError(t, err)
	err = os.RemoveAll(path.Join(corruptTestData, "irma_configuration", "test", "test2"))
	require.NoError(t, err)
	unstableSchemeServer := &http.Server{Addr: "localhost:48681", Handler: http.FileServer(http.Dir(corruptTestData))}
	go func() {
		_ = unstableSchemeServer.ListenAndServe()
	}()
	defer func() {
		require.NoError(t, unstableSchemeServer.Close())
	}()

	// Initialize empty configuration
	conf, err := NewConfiguration(t.TempDir(), ConfigurationOptions{})
	require.NoError(t, err)

	// Check whether installing fails cleanly when using the unstable remote
	pkPath := path.Join(corruptTestData, "irma_configuration", "test", "pk.pem")
	pkBytes, err := os.ReadFile(pkPath)
	require.NoError(t, err)
	err = conf.InstallScheme(testSchemeURL, pkBytes)
	require.Error(t, err)
	require.NotContains(t, conf.SchemeManagers, testSchemeID)

	// Check whether installing fails cleanly when no public key can be found (edge case)
	err = os.Remove(pkPath)
	require.NoError(t, err)
	err = conf.DangerousTOFUInstallScheme(testSchemeURL)
	require.Error(t, err)
	require.NotContains(t, conf.SchemeManagers, testSchemeID)

	// Stop unstable scheme server
	require.NoError(t, unstableSchemeServer.Close())

	// Start stable scheme server
	test.StartSchemeManagerHttpServer()
	defer test.StopSchemeManagerHttpServer()

	// Check whether we can successfully install the scheme using a stable remote
	err = conf.InstallScheme(testSchemeURL, pkBytes)
	require.NoError(t, err)
	require.Contains(t, conf.SchemeManagers, testSchemeID)

	err = conf.ParseFolder()
	require.NoError(t, err)
}
