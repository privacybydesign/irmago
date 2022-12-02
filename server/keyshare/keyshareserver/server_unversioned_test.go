package keyshareserver

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/gabi/signed"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func init() {
	irma.Logger.SetLevel(logrus.FatalLevel)
}

func TestUnversionedServerInvalidMessage(t *testing.T) {
	keyshareServer, httpServer := StartKeyshareServer(t, NewMemoryDB(), "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	test.HTTPPost(t, nil, "http://localhost:8080/client/register",
		"gval;kefsajsdkl;", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/users/verify_start",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/users/verify/pin",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/users/verify/pin_challengeresponse",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/users/change/pin",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/users/register_publickey",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/prove/getCommitments",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		403, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/prove/getCommitments",
		"[]", nil,
		403, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/prove/getResponse",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		403, nil,
	)
}

func TestUnversionedServerHandleRegisterLegacy(t *testing.T) {
	keyshareServer, httpServer := StartKeyshareServer(t, NewMemoryDB(), "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	test.HTTPPost(t, nil, "http://localhost:8080/client/register",
		`{"pin":"testpin","email":"test@example.com","language":"en"}`, nil,
		200, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/client/register",
		`{"pin":"testpin","email":"test@example.com","language":"nonexistinglanguage"}`, nil,
		200, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/client/register",
		`{"pin":"testpin","language":"en"}`, nil,
		200, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/client/register",
		`{"pin":"testpin","language":"nonexistinglanguage"}`, nil,
		200, nil,
	)
}

func TestUnversionedServerHandleRegister(t *testing.T) {
	keyshareServer, httpServer := StartKeyshareServer(t, NewMemoryDB(), "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	var j string

	for _, data := range []irma.KeyshareEnrollmentData{
		{Pin: "testpin", Email: stringPtr("test@test.com"), Language: "en"},
		{Pin: "testpin", Email: stringPtr("test@test.com"), Language: "nonexistinglanguage"},
		{Pin: "testpin", Language: "en"},
		{Pin: "testpin", Language: "nonexistinglanguage"},
	} {
		sk, err := signed.GenerateKey()
		require.NoError(t, err)
		pkbts, err := signed.MarshalPublicKey(&sk.PublicKey)
		require.NoError(t, err)
		data.PublicKey = pkbts

		j, err = jwt.NewWithClaims(jwt.SigningMethodES256, irma.KeyshareEnrollmentClaims{
			KeyshareEnrollmentData: data,
		}).SignedString(sk)
		require.NoError(t, err)

		msg, err := json.Marshal(irma.KeyshareEnrollment{EnrollmentJWT: j})
		require.NoError(t, err)
		test.HTTPPost(t, nil, "http://localhost:8080/client/register", string(msg), nil, 200, nil)
	}

	// Strip off a character to invalidate the JWT signature
	j = j[:len(j)-1]
	msg, err := json.Marshal(irma.KeyshareEnrollment{EnrollmentJWT: j})
	require.NoError(t, err)
	test.HTTPPost(t, nil, "http://localhost:8080/client/register", string(msg), nil, 500, nil)
}

func TestUnversionedPinTries(t *testing.T) {
	db := createDB(t)
	keyshareServer, httpServer := StartKeyshareServer(t, &testDB{db: db, ok: true, tries: 1, wait: 0, err: nil}, "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	var jwtMsg irma.KeysharePinStatus
	test.HTTPPost(t, nil, "http://localhost:8080/users/verify/pin",
		`{"id":"legacyuser","pin":"puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n"}`, nil,
		200, &jwtMsg,
	)
	require.Equal(t, "success", jwtMsg.Status)

	test.HTTPPost(t, nil, "http://localhost:8080/users/verify/pin",
		`{"id":"legacyuser","pin":"puZGbaLDmFywGhFDi4vW2G87Zh"}`, nil,
		200, &jwtMsg,
	)
	require.Equal(t, "failure", jwtMsg.Status)
	require.Equal(t, "1", jwtMsg.Message)

	test.HTTPPost(t, nil, "http://localhost:8080/users/change/pin",
		`{"id":"legacyuser","oldpin":"puZGbaLDmFywGhFDi4vW2G87Zh","newpin":"ljaksdfj;alkf"}`, nil,
		200, &jwtMsg,
	)
	require.Equal(t, "failure", jwtMsg.Status)
	require.Equal(t, "1", jwtMsg.Message)
}

func TestUnversionedPinTryChallengeResponse(t *testing.T) {
	db := createDB(t)
	keyshareServer, httpServer := StartKeyshareServer(t, &testDB{db: db, ok: true, tries: 1, wait: 0, err: nil}, "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	// can't do this directly, challenge-response required
	test.HTTPPost(t, nil, "http://localhost:8080/users/verify/pin",
		`{"id":"testusername","pin":"puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n"}`, nil,
		500, nil,
	)

	sk := loadClientPrivateKey(t)

	jwtt := doUnversionedChallengeResponse(t, sk, "testusername", "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n")
	var jwtMsg irma.KeysharePinStatus
	test.HTTPPost(t, nil, "http://localhost:8080/users/verify/pin_challengeresponse",
		marshalJSON(t, irma.KeyshareAuthResponse{AuthResponseJWT: jwtt}), nil,
		200, &jwtMsg,
	)
	require.Equal(t, "success", jwtMsg.Status)

	// try with an invalid response
	jwtt = doUnversionedChallengeResponse(t, sk, "testusername", "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n")
	jwtt = jwtt[:len(jwtt)-4]
	test.HTTPPost(t, nil, "http://localhost:8080/users/verify/pin_challengeresponse",
		marshalJSON(t, irma.KeyshareAuthResponse{AuthResponseJWT: jwtt}), nil,
		500, nil,
	)
}

func TestUnversionedStartAuth(t *testing.T) {
	db := createDB(t)
	keyshareServer, httpServer := StartKeyshareServer(t, &testDB{db: db, ok: true, tries: 1, wait: 0, err: nil}, "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	sk := loadClientPrivateKey(t)

	// can't do it for users that don't yet have a public key registered
	test.HTTPPost(t, nil, "http://localhost:8080/users/verify_start",
		authJWT(t, sk, "legacyuser"), nil,
		500, nil,
	)

	// normal flow
	auth := &irma.KeyshareAuthChallenge{}
	test.HTTPPost(t, nil, "http://localhost:8080/users/verify_start",
		authJWT(t, sk, "testusername"), nil,
		200, auth,
	)
	require.Contains(t, auth.Candidates, irma.KeyshareAuthMethodChallengeResponse)
	require.NotEmpty(t, auth.Challenge)

	// nonexisting user
	test.HTTPPost(t, nil, "http://localhost:8080/users/verify_start",
		authJWT(t, sk, "doesnotexist"), nil,
		403, nil,
	)
}

func TestUnversionedRegisterPublicKey(t *testing.T) {
	db := createDB(t)
	keyshareServer, httpServer := StartKeyshareServer(t, &testDB{db: db, ok: true, tries: 1, wait: 0, err: nil}, "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	sk := loadClientPrivateKey(t)
	pk, err := signed.MarshalPublicKey(&sk.PublicKey)
	require.NoError(t, err)

	// first try with nonexisting user
	jwtt := registrationJWT(t, sk, irma.KeyshareKeyRegistrationData{
		Username:  "doesnotexist",
		Pin:       "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n",
		PublicKey: pk,
	})
	test.HTTPPost(t, nil, "http://localhost:8080/users/register_publickey",
		fmt.Sprintf(`{"jwt":"%s"}`, jwtt), nil,
		403, nil,
	)

	// then try with invalid jwt
	jwtt = registrationJWT(t, sk, irma.KeyshareKeyRegistrationData{
		Username:  "legacyuser",
		Pin:       "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n",
		PublicKey: pk,
	})
	test.HTTPPost(t, nil, "http://localhost:8080/users/register_publickey",
		fmt.Sprintf(`{"jwt":"%s"}`, jwtt[:len(jwtt)-1]), nil,
		400, nil,
	)

	// then try with wrong pin
	jwtt = registrationJWT(t, sk, irma.KeyshareKeyRegistrationData{
		Username:  "legacyuser",
		Pin:       "puZGbaLDmFywGhFDi4vW2G87Zh",
		PublicKey: pk,
	})
	res := &irma.KeysharePinStatus{}
	test.HTTPPost(t, nil, "http://localhost:8080/users/register_publickey",
		fmt.Sprintf(`{"jwt":"%s"}`, jwtt), nil,
		200, res,
	)
	require.Equal(t, res.Message, "1") // one try left

	// normal flow
	jwtt = registrationJWT(t, sk, irma.KeyshareKeyRegistrationData{
		Username:  "legacyuser",
		Pin:       "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n",
		PublicKey: pk,
	})
	test.HTTPPost(t, nil, "http://localhost:8080/users/register_publickey",
		fmt.Sprintf(`{"jwt":"%s"}`, jwtt), nil,
		200, nil,
	)

	// challenge-response should work now
	_ = doUnversionedChallengeResponse(t, loadClientPrivateKey(t), "legacyuser", "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n")

	// can't do it a second time
	test.HTTPPost(t, nil, "http://localhost:8080/users/register_publickey",
		fmt.Sprintf(`{"jwt":"%s"}`, jwtt), nil,
		500, nil,
	)
}

func TestUnversionedRegisterPublicKeyBlockedUser(t *testing.T) {
	db := createDB(t)
	keyshareServer, httpServer := StartKeyshareServer(t, &testDB{db: db, ok: false, tries: 0, wait: 5, err: nil}, "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	sk := loadClientPrivateKey(t)
	pk, err := signed.MarshalPublicKey(&sk.PublicKey)
	require.NoError(t, err)

	// submit wrong pin, blocking user
	var jwtMsg irma.KeysharePinStatus
	test.HTTPPost(t, nil, "http://localhost:8080/users/verify/pin",
		`{"id":"legacyuser","pin":"puZGbaLDmFywGhFDi4vW2G87Zh"}`, nil,
		200, &jwtMsg,
	)
	require.Equal(t, "error", jwtMsg.Status)
	require.Equal(t, "5", jwtMsg.Message)

	// try to register public key
	jwtt := registrationJWT(t, sk, irma.KeyshareKeyRegistrationData{
		Username:  "legacyuser",
		Pin:       "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n",
		PublicKey: pk,
	})
	test.HTTPPost(t, nil, "http://localhost:8080/users/register_publickey",
		fmt.Sprintf(`{"jwt":"%s"}`, jwtt), nil,
		200, &jwtMsg,
	)
	require.Equal(t, "error", jwtMsg.Status)
}

func TestUnversionedPinNoRemainingTries(t *testing.T) {
	db := createDB(t)

	for _, ok := range []bool{true, false} {
		keyshareServer, httpServer := StartKeyshareServer(t, &testDB{db: db, ok: ok, tries: 0, wait: 5, err: nil}, "")

		var jwtMsg irma.KeysharePinStatus
		test.HTTPPost(t, nil, "http://localhost:8080/users/verify/pin",
			`{"id":"testusername","pin":"puZGbaLDmFywGhFDi4vW2G87Zh"}`, nil,
			200, &jwtMsg,
		)
		require.Equal(t, "error", jwtMsg.Status)
		require.Equal(t, "5", jwtMsg.Message)

		test.HTTPPost(t, nil, "http://localhost:8080/users/change/pin",
			`{"id":"testusername","oldpin":"puZGbaLDmFywGhFDi4vW2G87Zh","newpin":"ljaksdfj;alkf"}`, nil,
			200, &jwtMsg,
		)
		require.Equal(t, "error", jwtMsg.Status)
		require.Equal(t, "5", jwtMsg.Message)

		StopKeyshareServer(t, keyshareServer, httpServer)
	}
}

func TestUnversionedMissingUser(t *testing.T) {
	keyshareServer, httpServer := StartKeyshareServer(t, NewMemoryDB(), "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	test.HTTPPost(t, nil, "http://localhost:8080/users/verify/pin",
		`{"id":"doesnotexist","pin":"bla"}`, nil,
		403, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/users/change/pin",
		`{"id":"doesnotexist","oldpin":"old","newpin":"new"}`, nil,
		403, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/prove/getCommitments",
		`["test.test-3"]`, http.Header{
			"X-IRMA-Keyshare-Username": []string{"doesnotexist"},
			"Authorization":            []string{"ey.ey.ey"},
		},
		403, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/prove/getResponse",
		"123456789", http.Header{
			"X-IRMA-Keyshare-Username": []string{"doesnotexist"},
			"Authorization":            []string{"ey.ey.ey"},
		},
		403, nil,
	)
}

func TestUnversionedKeyshareSessions(t *testing.T) {
	db := createDB(t)
	keyshareServer, httpServer := StartKeyshareServer(t, db, "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	jwtt := doUnversionedChallengeResponse(t, loadClientPrivateKey(t), "testusername", "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n")
	var jwtMsg irma.KeysharePinStatus
	test.HTTPPost(t, nil, "http://localhost:8080/users/verify/pin_challengeresponse",
		marshalJSON(t, irma.KeyshareAuthResponse{AuthResponseJWT: jwtt}), nil,
		200, &jwtMsg,
	)
	require.Equal(t, "success", jwtMsg.Status)
	auth1 := jwtMsg.Message

	test.HTTPPost(t, nil, "http://localhost:8080/users/verify/pin",
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
		// no active session, can't retrieve result
		test.HTTPPost(t, nil, "http://localhost:8080/prove/getResponse",
			"12345678", http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			400, nil,
		)

		// can't retrieve commitments with fake authorization
		test.HTTPPost(t, nil, "http://localhost:8080/prove/getCommitments",
			`["test.test-3"]`, http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{"fakeauthorization"},
			},
			400, nil,
		)

		// retrieve commitments normally
		test.HTTPPost(t, nil, "http://localhost:8080/prove/getCommitments",
			`["test.test-3"]`, http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			200, nil,
		)

		// can't retrieve resukt with fake authorization
		test.HTTPPost(t, nil, "http://localhost:8080/prove/getResponse",
			"12345678", http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{"fakeauthorization"},
			},
			400, nil,
		)

		// can start session while another is already active
		test.HTTPPost(t, nil, "http://localhost:8080/prove/getCommitments",
			`["test.test-3"]`, http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			200, nil,
		)

		// finish session
		test.HTTPPost(t, nil, "http://localhost:8080/prove/getResponse",
			"12345678", http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			200, nil,
		)
	}
}

func doUnversionedChallengeResponse(t *testing.T, sk *ecdsa.PrivateKey, username, pin string) string {
	// retrieve a challenge
	auth := &irma.KeyshareAuthChallenge{}
	test.HTTPPost(t, nil, "http://localhost:8080/users/verify_start",
		authJWT(t, sk, username), nil,
		200, auth,
	)
	require.Contains(t, auth.Candidates, irma.KeyshareAuthMethodChallengeResponse)
	require.NotEmpty(t, auth.Challenge)

	jwtt, err := jwt.NewWithClaims(jwt.SigningMethodES256, irma.KeyshareAuthResponseClaims{
		KeyshareAuthResponseData: irma.KeyshareAuthResponseData{
			Username:  username,
			Pin:       pin,
			Challenge: auth.Challenge,
		},
	}).SignedString(sk)
	require.NoError(t, err)

	return jwtt
}
