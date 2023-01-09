package keyshareserver

import (
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
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

		// can start session while another is already active
		test.HTTPPost(t, nil, "http://localhost:8080/api/v2/prove/getCommitments",
			`{"keys":["test.test-3"],"hw":{"hashedComms":"WW91ciBTdHJpbmc="}}`, http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			200, nil,
		)

	}
}
