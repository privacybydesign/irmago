package irma

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	test.ClearTestStorage(nil)
	test.CreateTestStorage(nil)
	retCode := m.Run()
	test.ClearTestStorage(nil)
	os.Exit(retCode)
}

func parseConfiguration(t *testing.T) *Configuration {
	conf, err := NewConfiguration("testdata/irma_configuration", "")
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
	path := filepath.Join("testdata", "storage", "test", "irma_configuration")
	require.NoError(t, fs.CopyDirectory(filepath.Join("testdata", "irma_configuration"), path))
	conf, err := NewConfiguration(path, filepath.Join("testdata", "irma_configuration_updated"))
	require.NoError(t, err)
	require.NoError(t, conf.ParseFolder())

	credid := NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")
	require.True(t, conf.CredentialTypes[credid].ContainsAttribute(attrid))

	test.ClearTestStorage(t)
}

func TestParseInvalidIrmaConfiguration(t *testing.T) {
	// The description.xml of the scheme manager under this folder has been edited
	// to invalidate the scheme manager signature
	conf, err := NewConfiguration("testdata/irma_configuration_invalid", "")
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

	transport := NewHTTPTransport("http://localhost:48682")
	transport.client.HTTPClient.Timeout = 500 * time.Millisecond
	bts, err := transport.GetBytes("")
	require.NoError(t, err)
	require.Equal(t, "42\n", string(bts))

	test.StopBadHttpServer()
}

func TestInvalidIrmaConfigurationRestoreFromRemote(t *testing.T) {
	test.StartSchemeManagerHttpServer()

	require.NoError(t, fs.EnsureDirectoryExists("testdata/storage/test"))
	conf, err := NewConfiguration("testdata/storage/test/irma_configuration", "testdata/irma_configuration_invalid")
	require.NoError(t, err)

	err = conf.ParseOrRestoreFolder()
	require.NoError(t, err)
	require.Empty(t, conf.DisabledSchemeManagers)
	require.Contains(t, conf.SchemeManagers, NewSchemeManagerIdentifier("irma-demo"))
	require.Contains(t, conf.CredentialTypes, NewCredentialTypeIdentifier("irma-demo.RU.studentCard"))

	test.StopSchemeManagerHttpServer()
	test.ClearTestStorage(t)
}

func TestInvalidIrmaConfigurationRestoreFromAssets(t *testing.T) {
	require.NoError(t, fs.EnsureDirectoryExists("testdata/storage/test"))
	conf, err := NewConfiguration("testdata/storage/test/irma_configuration", "testdata/irma_configuration_invalid")
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

	test.ClearTestStorage(t)
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
		conf.CredentialTypes[NewCredentialTypeIdentifier("irma-demo.RU.studentCard")].Attributes[2].ID,
		"irma-demo.RU.studentCard.studentID has unexpected name")

	// Hash algorithm pseudocode:
	// Base64(SHA256("irma-demo.RU.studentCard")[0:16])
	//require.Contains(t, conf.reverseHashes, "1stqlPad5edpfS1Na1U+DA==",
	//	"irma-demo.RU.studentCard had improper hash")
	//require.Contains(t, conf.reverseHashes, "CLjnADMBYlFcuGOT7Z0xRg==",
	//	"irma-demo.MijnOverheid.root had improper hash")
}

func TestAttributeDisjunctionMarshaling(t *testing.T) {
	conf := parseConfiguration(t)
	disjunction := AttributeDisjunction{}

	var _ json.Unmarshaler = &disjunction
	var _ json.Marshaler = &disjunction

	id := NewAttributeTypeIdentifier("MijnOverheid.ageLower.over18")

	attrsjson := `
	{
		"label": "Over 18",
		"attributes": {
			"MijnOverheid.ageLower.over18": "yes",
			"Thalia.age.over18": "Yes"
		}
	}`
	require.NoError(t, json.Unmarshal([]byte(attrsjson), &disjunction))
	require.True(t, disjunction.HasValues())
	require.Contains(t, disjunction.Attributes, id)
	require.Contains(t, disjunction.Values, id)
	require.Equal(t, *disjunction.Values[id], "yes")

	disjunction = AttributeDisjunction{}
	attrsjson = `
	{
		"label": "Over 18",
		"attributes": [
			"MijnOverheid.ageLower.over18",
			"Thalia.age.over18"
		]
	}`
	require.NoError(t, json.Unmarshal([]byte(attrsjson), &disjunction))
	require.False(t, disjunction.HasValues())
	require.Contains(t, disjunction.Attributes, id)

	require.True(t, disjunction.MatchesConfig(conf))

	require.False(t, disjunction.Satisfied())
	disjunction.selected = &disjunction.Attributes[0]
	require.True(t, disjunction.Satisfied())
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
	conf, err := NewConfiguration("testdata/irma_configuration", "")
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

func TestServiceProvider(t *testing.T) {
	var spjwt ServiceProviderJwt

	var spjson = `{
		"sprequest": {
			"validity": 60,
			"timeout": 60,
			"request": {
				"content": [
					{
						"label": "ID",
						"attributes": ["irma-demo.RU.studentCard.studentID"]
					}
				]
			}
		}
	}`

	require.NoError(t, json.Unmarshal([]byte(spjson), &spjwt))
	require.NotEmpty(t, spjwt.Request.Request.Content)
	require.NotEmpty(t, spjwt.Request.Request.Content[0])
	require.NotEmpty(t, spjwt.Request.Request.Content[0].Attributes)
	require.Equal(t, spjwt.Request.Request.Content[0].Attributes[0].Name(), "studentID")

	require.NotNil(t, spjwt.Request.Request.Content.Find(NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")))
}

func TestVerifyValidSig(t *testing.T) {
	conf := parseConfiguration(t)

	irmaSignedMessageJson := "{\"signature\":[{\"c\":75240648584943108131774861418318016950300520060239897966364931555348119154196,\"A\":11233355237638071473355040022601544318931000499058445952330165003155291452882014950229516980087013355670100886267043109889290196460736758722039876324777132864035863434782644494004016849862082847856434105252669649855602233471390863557544150375601234558196514354266223994618716648803629152866318840314101303053,\"e_response\":70443137280413345388921308658326573478731402976627353520789046075581088830468573907219985143735120271295606500225192886734004566649741300,\"v_response\":748547606963016897781947765348570036269181744245969380678378950063447942583654801250902509594049880144606664155188413917858341097638009280073657058659129276453063845565880273889465070847993483844689057977028173394452669902369437344839036235498559251356581938192107900921870473799941106736017886005831516457330023495088373551591149589202496455594271982293348956823683659852274256453778465505025023577967456370086028145603744587324314475916518584158230288021313776814608153663145234741600118368482896288256771513649394113424970805702242999138114099754431573768005053249476064297389050847313658255952687915513714299,\"a_responses\":{\"0\":4081186988971645773885141302777967291858930640684160885316109083415045388256707780194730929186392387906061383128340576948202521359180637178569455985666827436285079935133224351439,\"2\":2002101875939486065896615754953027178193966422837050583457482787068404012970870896083719080233500166329391569749284832041605767056271290452037190009069979873823861447698576212956,\"3\":9024622614267518591475352106643486923661297308724100043388816444935669356409217421617445580684629339630281696726734306159937045856348975488404957001973413528359503266658980267958,\"5\":14532137354231347732013224301661302047284478108130413918974378286885777087212963236903262642952033662174908068223261418379845579509518210263448355072319547079781612856155479908000},\"a_disclosed\":{\"1\":49043497911096929607726931703203423024551950578089278988,\"4\":3421494}}],\"nonce\":42,\"context\":1337,\"message\":\"I owe you everything\",\"timestamp\":{\"Time\":1527196489,\"ServerUrl\":\"https://metrics.privacybydesign.foundation/atum\",\"Sig\":{\"Alg\":\"ed25519\",\"Data\":\"ZV1qkvDrFK14QrUSC66xTNr9HitCOV4vwfGX0bh3iwY7qyHCi9rIOE97KY8CZifU5oLgVhFWy5E+ALR+gEpACw==\",\"PublicKey\":\"e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8=\"}}}"
	irmaSignedMessage := &IrmaSignedMessage{}
	json.Unmarshal([]byte(irmaSignedMessageJson), irmaSignedMessage)

	request := "{\"nonce\": 42, \"context\": 1337, \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	sigRequestJSON := []byte(request)
	sigRequest := &SignatureRequest{}
	json.Unmarshal(sigRequestJSON, sigRequest)
	// Test marshalling of 'string' fields:
	require.Equal(t, sigRequest.Nonce, big.NewInt(42))
	require.Equal(t, sigRequest.Context, big.NewInt(1337))

	// Test if we can verify it with the original request
	sigProofResult := VerifySig(conf, irmaSignedMessage, sigRequest)
	require.Equal(t, sigProofResult.ProofStatus, VALID)
	attributeList := sigProofResult.ToAttributeResultList()
	require.Len(t, attributeList, 1)
	require.Equal(t, attributeList[0].AttributeProofStatus, PRESENT)
	require.Equal(t, attributeList[0].AttributeValue["en"], "456")

	// Test if we can verify it with a request that contains strings instead of ints for nonce and context
	stringRequest := "{\"nonce\": \"42\", \"context\": \"1337\", \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	stringSigRequestJSON := []byte(stringRequest)
	stringSigRequest := &SignatureRequest{}
	json.Unmarshal(stringSigRequestJSON, stringSigRequest)
	// Test marshalling of 'string' fields:
	require.Equal(t, stringSigRequest.Nonce, big.NewInt(42))
	require.Equal(t, stringSigRequest.Context, big.NewInt(1337))

	// Test if we can verify it with the original request
	stringSigProofResult := VerifySig(conf, irmaSignedMessage, sigRequest)
	require.Equal(t, stringSigProofResult.ProofStatus, VALID)
	stringAttributeList := sigProofResult.ToAttributeResultList()
	require.Len(t, stringAttributeList, 1)
	require.Equal(t, stringAttributeList[0].AttributeProofStatus, PRESENT)
	require.Equal(t, stringAttributeList[0].AttributeValue["en"], "456")

	// Test verify against unmatched request (i.e. different nonce, context or message)
	unmatched := "{\"nonce\": 42, \"context\": 1337, \"message\":\"I owe you NOTHING\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	unmatchedSigRequestJSON := []byte(unmatched)
	unmatchedSigRequest := &SignatureRequest{}
	json.Unmarshal(unmatchedSigRequestJSON, unmatchedSigRequest)
	unmatchedResult := VerifySig(conf, irmaSignedMessage, unmatchedSigRequest)
	require.Equal(t, unmatchedResult.ProofStatus, UNMATCHED_REQUEST)

	// Test if we can also verify it without using the original request
	proofStatus, disclosed := VerifySigWithoutRequest(conf, irmaSignedMessage)
	require.Equal(t, proofStatus, VALID)
	require.Len(t, disclosed, 1)
	require.Equal(t, disclosed[0].Attributes[NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")]["en"], "456")
}

func TestVerifyInValidSig(t *testing.T) {
	conf := parseConfiguration(t)

	// Same json as valid case, but starts with c: 74.. instead of c: 84..
	irmaSignedMessageJson := "{\"signature\":[{\"c\":74387860940227163820403495286748244564707922600034683359608691396081567025602,\"A\":88281712394778800408977859704145725624282144718487192171772162550525428429519190981888278801087212465321690290335409063053117882098498400332781065742081358484833309192327120556339332157874905818122935827879129997343067882402015244634759393479031207772945330229833048906663580440236616733112577470729616366786,\"e_response\":158765301676865980664519775970491722252026400039481431972586202039855979595012153817023420279082580759592345985626616023615379719752399328,\"v_response\":6611746513363446317846147623316898858155094502709878009639760817201381076603429289631603604529060691249377615651154531801036452874566979268891286567129727685535821475399052346372076099618720496054457827506328803409424296248607363948476756029304344829069350093632120223961428827899945063479494984026332706037701056800933468297084225080081776744374335801370875205735636759162890211232669349095889736548891226015515520674239004969135762927189899345062330063667418982393995289342139999902051131072263853724059860710122540669055502508808347469655730875919155588858804817423089007580489779129833698002045070596906945040,\"a_responses\":{\"0\":4434835936588491146877061202237807779146602258202436880339162159399867035387373999563459639269288401746730567517727346492632152446746295360674508158204107496002345160420756725205,\"2\":9977462643736893130880681297952480237124511902476432783965737452034254055110952583256642665857196544092176573351041403473080012083097371376185951351204344524454609167069034294004,\"3\":1904659714829479350823098920128825893793063661618141776764549847325998719856920007188109803030455877752450027088898741652270026015791752527030236440389575193675041497254880209617,\"5\":3936452247676614466878886279006122732122146262864401884641740995040119769042022356436514614808831282997701569758564908168629905499336984204831548844404122251651655734975885548663},\"a_disclosed\":{\"1\":49043497911096929607726931703203423024551950578089278988,\"4\":3421494}}],\"nonce\":42,\"context\":1337,\"message\":\"I owe you everything\"}"
	irmaSignedMessage := &IrmaSignedMessage{}
	json.Unmarshal([]byte(irmaSignedMessageJson), irmaSignedMessage)

	request := "{\"nonce\": 42, \"context\": 1337, \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	sigRequestJSON := []byte(request)
	sigRequest := &SignatureRequest{}
	json.Unmarshal(sigRequestJSON, sigRequest)

	sigProofResult := VerifySig(conf, irmaSignedMessage, sigRequest)
	require.Equal(t, sigProofResult.ProofStatus, INVALID_CRYPTO)

	proofStatus, disclosed := VerifySigWithoutRequest(conf, irmaSignedMessage)
	require.Equal(t, proofStatus, INVALID_CRYPTO)
	require.Nil(t, disclosed)
}

func TestVerifyInValidNonce(t *testing.T) {
	conf := parseConfiguration(t)

	// Same json as valid case, has invalid nonce
	irmaSignedMessageJson := "{\"signature\":[{\"c\":84387860940227163820403495286748244564707922600034683359608691396081567025602,\"A\":88281712394778800408977859704145725624282144718487192171772162550525428429519190981888278801087212465321690290335409063053117882098498400332781065742081358484833309192327120556339332157874905818122935827879129997343067882402015244634759393479031207772945330229833048906663580440236616733112577470729616366786,\"e_response\":158765301676865980664519775970491722252026400039481431972586202039855979595012153817023420279082580759592345985626616023615379719752399328,\"v_response\":6611746513363446317846147623316898858155094502709878009639760817201381076603429289631603604529060691249377615651154531801036452874566979268891286567129727685535821475399052346372076099618720496054457827506328803409424296248607363948476756029304344829069350093632120223961428827899945063479494984026332706037701056800933468297084225080081776744374335801370875205735636759162890211232669349095889736548891226015515520674239004969135762927189899345062330063667418982393995289342139999902051131072263853724059860710122540669055502508808347469655730875919155588858804817423089007580489779129833698002045070596906945040,\"a_responses\":{\"0\":4434835936588491146877061202237807779146602258202436880339162159399867035387373999563459639269288401746730567517727346492632152446746295360674508158204107496002345160420756725205,\"2\":9977462643736893130880681297952480237124511902476432783965737452034254055110952583256642665857196544092176573351041403473080012083097371376185951351204344524454609167069034294004,\"3\":1904659714829479350823098920128825893793063661618141776764549847325998719856920007188109803030455877752450027088898741652270026015791752527030236440389575193675041497254880209617,\"5\":3936452247676614466878886279006122732122146262864401884641740995040119769042022356436514614808831282997701569758564908168629905499336984204831548844404122251651655734975885548663},\"a_disclosed\":{\"1\":49043497911096929607726931703203423024551950578089278988,\"4\":3421494}}],\"nonce\":4242,\"context\":1337,\"message\":\"I owe you everything\"}"
	irmaSignedMessage := &IrmaSignedMessage{}
	json.Unmarshal([]byte(irmaSignedMessageJson), irmaSignedMessage)

	// Original request also has the same invalid nonce (otherwise we would get unmatched_request)
	request := "{\"nonce\": 4242, \"context\": 1337, \"message\":\"I owe you everything\",\"content\":[{\"label\":\"Student number (RU)\",\"attributes\":[\"irma-demo.RU.studentCard.studentID\"]}]}"
	sigRequestJSON := []byte(request)
	sigRequest := &SignatureRequest{}
	json.Unmarshal(sigRequestJSON, sigRequest)

	sigProofResult := VerifySig(conf, irmaSignedMessage, sigRequest)
	require.Equal(t, sigProofResult.ProofStatus, INVALID_CRYPTO)

	proofStatus, disclosed := VerifySigWithoutRequest(conf, irmaSignedMessage)
	require.Equal(t, proofStatus, INVALID_CRYPTO)
	require.Nil(t, disclosed)
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
