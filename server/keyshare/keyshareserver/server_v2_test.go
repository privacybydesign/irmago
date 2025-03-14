package keyshareserver

import (
	"crypto/sha256"
	"net/http"
	"testing"
	"time"

	"github.com/fxamacker/cbor"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/require"
)

func TestServerInvalidMessageV2(t *testing.T) {
	keyshareServer, httpServer := StartKeyshareServer(t, NewMemoryDB(), "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getCommitments",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		403, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getCommitments",
		"[]", nil,
		403, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getPs",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		403, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getPs",
		"[]", nil,
		403, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getResponse",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		403, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getResponseLinkable",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		403, nil,
	)
}

func TestMissingUserV2(t *testing.T) {
	keyshareServer, httpServer := StartKeyshareServer(t, NewMemoryDB(), "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getCommitments",
		`["test.test-3"]`, http.Header{
			"X-IRMA-Keyshare-Username": []string{"doesnotexist"},
			"Authorization":            []string{"ey.ey.ey"},
		},
		403, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getPs",
		`["test.test-3"]`, http.Header{
			"X-IRMA-Keyshare-Username": []string{"doesnotexist"},
			"Authorization":            []string{"ey.ey.ey"},
		},
		403, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getResponse",
		"123456789", http.Header{
			"X-IRMA-Keyshare-Username": []string{"doesnotexist"},
			"Authorization":            []string{"ey.ey.ey"},
		},
		403, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getResponseLinkable",
		"123456789", http.Header{
			"X-IRMA-Keyshare-Username": []string{"doesnotexist"},
			"Authorization":            []string{"ey.ey.ey"},
		},
		403, nil,
	)
}

func TestKeyshareSessionsV2(t *testing.T) {
	db := createDB(t)
	keyshareServer, httpServer := StartKeyshareServer(t, db, "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	jwtt := doChallengeResponse(t, loadClientPrivateKey(t), "testusername", "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n")
	var jwtMsg irma.KeysharePinStatus
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify/pin_challengeresponse",
		marshalJSON(t, irma.KeyshareAuthResponse{AuthResponseJWT: jwtt}), nil,
		200, &jwtMsg,
	)
	require.Equal(t, "success", jwtMsg.Status)
	auth1 := jwtMsg.Message

	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify/pin",
		marshalJSON(t, irma.KeyshareAuthResponse{KeyshareAuthResponseData: irma.KeyshareAuthResponseData{
			Username: "legacyuser",
			Pin:      "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n",
		}}), nil,
		200, &jwtMsg,
	)
	auth2 := jwtMsg.Message

	for _, user := range []struct {
		username, auth string
	}{{"testusername", auth1}, {"legacyuser", auth2}} {
		commitmentReq, responseReq := prepareRequests(t)

		// no active session, can't retrieve result
		test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getResponse",
			server.ToJson(responseReq), http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			409, nil,
		)

		test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getResponseLinkable",
			server.ToJson(responseReq), http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			409, nil,
		)

		// can't retrieve commitments with fake authorization
		test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getCommitments",
			`["test.test-3"]`, http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{"fakeauthorization"},
			},
			400, nil,
		)

		// retrieve commitments normally
		test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getCommitments",
			`{"keys":["test.test-3"],"hw":{"hashedComms":"WW91ciBTdHJpbmc="}}`, http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			200, nil,
		)

		// can't retrieve Ps with fake authorization
		test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getPs",
			`["test.test-3"]`, http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{"fakeauthorization"},
			},
			400, nil,
		)

		// retrieve Ps normally
		test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getPs",
			`["test.test-3"]`, http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			200, nil,
		)

		// can't retrieve result with fake authorization
		test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getResponse",
			server.ToJson(responseReq), http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{"fakeauthorization"},
			},
			400, nil,
		)

		test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getResponseLinkable",
			"12345678", http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{"fakeauthorization"},
			},
			400, nil,
		)

		// can start session while another is already active
		test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getCommitments",
			`{"keys":["test.test-3"],"hw":`+server.ToJson(commitmentReq)+`}`, http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			200, nil,
		)

		// finish session
		test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getResponse",
			server.ToJson(responseReq), http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			200, nil,
		)

		// complete session with standard getCommitments call and linkable response call
		commitmentReq2, responseReq2 := prepareRequests(t)

		test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getCommitments",
			`{"keys":["test.test-3"],"hw":`+server.ToJson(commitmentReq2)+`}`, http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			200, nil,
		)

		test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getResponseLinkable",
			server.ToJson(responseReq2), http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			200, nil,
		)
	}
}

func prepareRequests(t *testing.T) (gabi.KeyshareCommitmentRequest, gabi.KeyshareResponseRequest[irma.PublicKeyIdentifier]) {
	challenge := big.NewInt(73645263)
	keyID := irma.PublicKeyIdentifier{Issuer: irma.NewIssuerIdentifier("test.test"), Counter: 3}

	kssSecret, err := gabi.GenerateSecretAttribute()
	require.NoError(t, err)
	userSecret, err := gabi.GenerateSecretAttribute()
	require.NoError(t, err)

	nonce, err := gabi.GenerateNonce()
	require.NoError(t, err)

	n := s2big("96063359353814070257464989369098573470645843347358957127875426328487326540633303185702306359400766259130239226832166456957259123554826741975265634464478609571816663003684533868318795865194004795637221226902067194633407757767792795252414073029114153019362701793292862118990912516058858923030408920700061749321")
	S := s2big("68460510129747727135744503403370273952956360997532594630007762045745171031173231339034881007977792852962667675924510408558639859602742661846943843432940752427075903037429735029814040501385798095836297700111333573975220392538916785564158079116348699773855815825029476864341585033111676283214405517983188761136")
	Z := s2big("44579327840225837958738167571392618381868336415293109834301264408385784355849790902532728798897199236650711385876328647206143271336410651651791998475869027595051047904885044274040212624547595999947339956165755500019260290516022753290814461070607850420459840370288988976468437318992206695361417725670417150636")
	rValues := []string{"75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251",
		"16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766",
		"13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840",
		"86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187",
		"68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513",
		"65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387"}

	// Too bad there is no better way to have big int constants
	R := make([]*big.Int, len(rValues))
	for i, rv := range rValues {
		R[i], _ = new(big.Int).SetString(rv, 10)
	}

	testPubK, _ := gabikeys.NewPublicKey(n, Z, S, nil, nil, R, "", 0, time.Now().AddDate(1, 0, 0))

	testPubK.Issuer = "testPubK"

	keysSlice := []*gabikeys.PublicKey{testPubK}

	_, kssComm, err := gabi.NewKeyshareCommitments(kssSecret, keysSlice)
	require.NoError(t, err)
	userRandomizer, userComm, err := gabi.NewKeyshareCommitments(userSecret, keysSlice)
	require.NoError(t, err)

	totalP := new(big.Int)
	totalP.Mul(userComm[0].P, kssComm[0].P).Mod(totalP, testPubK.N)
	totalW := new(big.Int)
	totalW.Mul(userComm[0].Pcommit, kssComm[0].Pcommit).Mod(totalW, testPubK.N)

	i := []gabi.KeyshareUserChallengeInput[irma.PublicKeyIdentifier]{{
		KeyID:      &keyID,
		Value:      totalP,
		Commitment: userComm[0].Pcommit,
	}}

	resp := gabi.KeyshareResponseRequest[irma.PublicKeyIdentifier]{
		Nonce:              nonce,
		UserResponse:       new(big.Int).Add(userRandomizer, new(big.Int).Mul(challenge, userSecret)),
		IsSignatureSession: false,
		UserChallengeInput: i,
	}

	bts, _ := cbor.Marshal(i, cbor.EncOptions{})
	h := sha256.Sum256(bts)

	req := gabi.KeyshareCommitmentRequest{HashedUserCommitments: h[:]}

	return req, resp
}

// A convenience function for initializing big integers from known correct (10
// base) strings. Use with care, errors are ignored.
func s2big(s string) (r *big.Int) {
	r, _ = new(big.Int).SetString(s, 10)
	return
}
