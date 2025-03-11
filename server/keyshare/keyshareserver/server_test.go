package keyshareserver

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/gabi/signed"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	irma.Logger.SetLevel(logrus.FatalLevel)
}

func TestServerInvalidMessage(t *testing.T) {
	keyshareServer, httpServer := StartKeyshareServer(t, NewMemoryDB(), "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/client/register",
		"gval;kefsajsdkl;", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify_start",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify/pin",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify/pin_challengeresponse",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/change/pin",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/register_publickey",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/prove/getCommitments",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		403, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/prove/getCommitments",
		"[]", nil,
		403, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/prove/getResponse",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		403, nil,
	)
}

func TestServerHandleRegisterLegacy(t *testing.T) {
	keyshareServer, httpServer := StartKeyshareServer(t, NewMemoryDB(), "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/client/register",
		`{"pin":"testpin","email":"test@example.com","language":"en"}`, nil,
		200, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/client/register",
		`{"pin":"testpin","email":"test@example.com","language":"nonexistinglanguage"}`, nil,
		200, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/client/register",
		`{"pin":"testpin","language":"en"}`, nil,
		200, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/client/register",
		`{"pin":"testpin","language":"nonexistinglanguage"}`, nil,
		200, nil,
	)
}

func stringPtr(s string) *string {
	return &s
}

func TestServerHandleRegister(t *testing.T) {
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
		test.HTTPPost(t, nil, "http://localhost:8080/api/v1/client/register", string(msg), nil, 200, nil)
	}

	// Strip off a character to invalidate the JWT signature
	j = j[:len(j)-1]
	msg, err := json.Marshal(irma.KeyshareEnrollment{EnrollmentJWT: j})
	require.NoError(t, err)
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/client/register", string(msg), nil, 500, nil)
}

func TestPinTries(t *testing.T) {
	db := createDB(t)
	keyshareServer, httpServer := StartKeyshareServer(t, &testDB{db: db, ok: true, tries: 1, wait: 0, err: nil}, "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	var jwtMsg irma.KeysharePinStatus
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify/pin",
		`{"id":"legacyuser","pin":"puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n"}`, nil,
		200, &jwtMsg,
	)
	require.Equal(t, "success", jwtMsg.Status)

	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify/pin",
		`{"id":"legacyuser","pin":"puZGbaLDmFywGhFDi4vW2G87Zh"}`, nil,
		200, &jwtMsg,
	)
	require.Equal(t, "failure", jwtMsg.Status)
	require.Equal(t, "1", jwtMsg.Message)

	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/change/pin",
		`{"id":"legacyuser","oldpin":"puZGbaLDmFywGhFDi4vW2G87Zh","newpin":"ljaksdfj;alkf"}`, nil,
		200, &jwtMsg,
	)
	require.Equal(t, "failure", jwtMsg.Status)
	require.Equal(t, "1", jwtMsg.Message)
}

func TestPinTryChallengeResponse(t *testing.T) {
	db := createDB(t)
	keyshareServer, httpServer := StartKeyshareServer(t, &testDB{db: db, ok: true, tries: 1, wait: 0, err: nil}, "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	// can't do this directly, challenge-response required
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify/pin",
		`{"id":"testusername","pin":"puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n"}`, nil,
		403, nil,
	)

	sk := loadClientPrivateKey(t)

	jwtt := doChallengeResponse(t, sk, "testusername", "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n")
	var jwtMsg irma.KeysharePinStatus
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify/pin_challengeresponse",
		marshalJSON(t, irma.KeyshareAuthResponse{AuthResponseJWT: jwtt}), nil,
		200, &jwtMsg,
	)
	require.Equal(t, "success", jwtMsg.Status)

	// try with an invalid response
	jwtt = doChallengeResponse(t, sk, "testusername", "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n")
	jwtt = jwtt[:len(jwtt)-4]
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify/pin_challengeresponse",
		marshalJSON(t, irma.KeyshareAuthResponse{AuthResponseJWT: jwtt}), nil,
		500, nil,
	)
}

func marshalJSON(t *testing.T, v interface{}) string {
	j, err := json.Marshal(v)
	require.NoError(t, err)
	return string(j)
}

func authJWT(t *testing.T, sk *ecdsa.PrivateKey, username string) string {
	jwtt, err := jwt.NewWithClaims(jwt.SigningMethodES256, irma.KeyshareAuthRequestClaims{
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(3 * time.Minute))},
		Username:         username,
	}).SignedString(sk)
	require.NoError(t, err)
	x := marshalJSON(t, irma.KeyshareAuthRequest{AuthRequestJWT: jwtt})
	return x
}

func TestStartAuth(t *testing.T) {
	db := createDB(t)
	keyshareServer, httpServer := StartKeyshareServer(t, &testDB{db: db, ok: true, tries: 1, wait: 0, err: nil}, "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	sk := loadClientPrivateKey(t)

	// can't do it for users that don't yet have a public key registered
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify_start",
		authJWT(t, sk, "legacyuser"), nil,
		500, nil,
	)

	// normal flow
	auth := &irma.KeyshareAuthChallenge{}
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify_start",
		authJWT(t, sk, "testusername"), nil,
		200, auth,
	)
	require.Contains(t, auth.Candidates, irma.KeyshareAuthMethodChallengeResponse)
	require.NotEmpty(t, auth.Challenge)

	// nonexisting user
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify_start",
		authJWT(t, sk, "doesnotexist"), nil,
		403, nil,
	)
}

func TestRegisterPublicKey(t *testing.T) {
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
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/register_publickey",
		fmt.Sprintf(`{"jwt":"%s"}`, jwtt), nil,
		403, nil,
	)

	// then try with invalid jwt
	jwtt = registrationJWT(t, sk, irma.KeyshareKeyRegistrationData{
		Username:  "legacyuser",
		Pin:       "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n",
		PublicKey: pk,
	})
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/register_publickey",
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
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/register_publickey",
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
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/register_publickey",
		fmt.Sprintf(`{"jwt":"%s"}`, jwtt), nil,
		200, nil,
	)

	// challenge-response should work now
	_ = doChallengeResponse(t, loadClientPrivateKey(t), "legacyuser", "puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n")

	// can't do it a second time
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/register_publickey",
		fmt.Sprintf(`{"jwt":"%s"}`, jwtt), nil,
		500, nil,
	)
}

func TestRegisterPublicKeyBlockedUser(t *testing.T) {
	db := createDB(t)
	keyshareServer, httpServer := StartKeyshareServer(t, &testDB{db: db, ok: false, tries: 0, wait: 5, err: nil}, "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	sk := loadClientPrivateKey(t)
	pk, err := signed.MarshalPublicKey(&sk.PublicKey)
	require.NoError(t, err)

	// submit wrong pin, blocking user
	var jwtMsg irma.KeysharePinStatus
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify/pin",
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
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/register_publickey",
		fmt.Sprintf(`{"jwt":"%s"}`, jwtt), nil,
		200, &jwtMsg,
	)
	require.Equal(t, "error", jwtMsg.Status)
}

func TestPinNoRemainingTries(t *testing.T) {
	db := createDB(t)

	for _, ok := range []bool{true, false} {
		keyshareServer, httpServer := StartKeyshareServer(t, &testDB{db: db, ok: ok, tries: 0, wait: 5, err: nil}, "")

		var jwtMsg irma.KeysharePinStatus
		test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify/pin",
			`{"id":"testusername","pin":"puZGbaLDmFywGhFDi4vW2G87Zh"}`, nil,
			200, &jwtMsg,
		)
		require.Equal(t, "error", jwtMsg.Status)
		require.Equal(t, "5", jwtMsg.Message)

		test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/change/pin",
			`{"id":"testusername","oldpin":"puZGbaLDmFywGhFDi4vW2G87Zh","newpin":"ljaksdfj;alkf"}`, nil,
			200, &jwtMsg,
		)
		require.Equal(t, "error", jwtMsg.Status)
		require.Equal(t, "5", jwtMsg.Message)

		StopKeyshareServer(t, keyshareServer, httpServer)
	}
}

func TestMissingUser(t *testing.T) {
	keyshareServer, httpServer := StartKeyshareServer(t, NewMemoryDB(), "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify/pin",
		`{"id":"doesnotexist","pin":"bla"}`, nil,
		403, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/change/pin",
		`{"id":"doesnotexist","oldpin":"old","newpin":"new"}`, nil,
		403, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/prove/getCommitments",
		`["test.test-3"]`, http.Header{
			"X-IRMA-Keyshare-Username": []string{"doesnotexist"},
			"Authorization":            []string{"ey.ey.ey"},
		},
		403, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/prove/getResponse",
		"123456789", http.Header{
			"X-IRMA-Keyshare-Username": []string{"doesnotexist"},
			"Authorization":            []string{"ey.ey.ey"},
		},
		403, nil,
	)
}

func TestKeyshareSessions(t *testing.T) {
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
		// no active session, can't retrieve result
		test.HTTPPost(t, nil, "http://localhost:8080/api/v1/prove/getResponse",
			"12345678", http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			400, nil,
		)

		// can't retrieve commitments with fake authorization
		test.HTTPPost(t, nil, "http://localhost:8080/api/v1/prove/getCommitments",
			`["test.test-3"]`, http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{"fakeauthorization"},
			},
			400, nil,
		)

		// retrieve commitments normally
		test.HTTPPost(t, nil, "http://localhost:8080/api/v1/prove/getCommitments",
			`["test.test-3"]`, http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			200, nil,
		)

		// can't retrieve resukt with fake authorization
		test.HTTPPost(t, nil, "http://localhost:8080/api/v1/prove/getResponse",
			"12345678", http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{"fakeauthorization"},
			},
			400, nil,
		)

		// can start session while another is already active
		test.HTTPPost(t, nil, "http://localhost:8080/api/v1/prove/getCommitments",
			`["test.test-3"]`, http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			200, nil,
		)

		// finish session
		test.HTTPPost(t, nil, "http://localhost:8080/api/v1/prove/getResponse",
			"12345678", http.Header{
				"X-IRMA-Keyshare-Username": []string{user.username},
				"Authorization":            []string{user.auth},
			},
			200, nil,
		)
	}
}

func StartKeyshareServer(t *testing.T, db DB, emailserver string) (*Server, *http.Server) {
	testdataPath := test.FindTestdataFolder(t)
	s, err := New(&Configuration{
		Configuration: &server.Configuration{
			SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
			IssuerPrivateKeysPath: filepath.Join(testdataPath, "privatekeys"),
			Logger:                irma.Logger,
		},
		EmailConfiguration: keyshare.EmailConfiguration{
			EmailServer:     emailserver,
			EmailFrom:       "test@example.com",
			DefaultLanguage: "en",
		},
		DB:                    db,
		JwtKeyID:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "test-kss-sk-0.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareAttribute:     irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"),
		EmailTokenValidity:    168,
		RegistrationEmailFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		RegistrationEmailSubjects: map[string]string{
			"en": "testsubject",
		},
		VerificationURL: map[string]string{
			"en": "http://example.com/verify/",
		},
	})
	require.NoError(t, err)

	serv := &http.Server{
		Addr:    "localhost:8080",
		Handler: s.Handler(),
	}

	go func() {
		err := serv.ListenAndServe()
		if err == http.ErrServerClosed {
			err = nil
		}
		assert.NoError(t, err)
	}()
	time.Sleep(200 * time.Millisecond) // Give server time to start

	return s, serv
}

func StopKeyshareServer(t *testing.T, keyshareServer *Server, httpServer *http.Server) {
	keyshareServer.Stop()
	err := httpServer.Shutdown(context.Background())
	assert.NoError(t, err)
}

type testDB struct {
	db    DB
	ok    bool
	tries int
	wait  int64
	err   error
}

func (db *testDB) AddUser(ctx context.Context, user *User) error {
	return db.db.AddUser(ctx, user)
}

func (db *testDB) user(ctx context.Context, username string) (*User, error) {
	return db.db.user(ctx, username)
}

func (db *testDB) updateUser(ctx context.Context, user *User) error {
	return db.db.updateUser(ctx, user)
}

func (db *testDB) reservePinTry(_ context.Context, _ *User) (bool, int, int64, error) {
	return db.ok, db.tries, db.wait, db.err
}

func (db *testDB) resetPinTries(ctx context.Context, user *User) error {
	return db.db.resetPinTries(ctx, user)
}

func (db *testDB) setSeen(ctx context.Context, user *User) error {
	return db.db.setSeen(ctx, user)
}

func (db *testDB) addLog(ctx context.Context, user *User, entrytype eventType, params interface{}) error {
	return db.db.addLog(ctx, user, entrytype, params)
}

func (db *testDB) addEmailVerification(ctx context.Context, user *User, email, token string, validity int) error {
	return db.db.addEmailVerification(ctx, user, email, token, validity)
}

func createDB(t *testing.T) DB {
	db := NewMemoryDB()
	err := db.AddUser(context.Background(), &User{
		Username: "",
		Secrets:  UserSecrets{},
	})
	require.NoError(t, err)
	secrets, err := base64.StdEncoding.DecodeString("YWJjZBdd6z/4lW/JBgEjVxcAnhK16iimfeyi1AAtWPzkfbWYyXHAad8A+Xzc6mE8bMj6dMQ5CgT0xcppEWYN9RFtO5+Wv4Carfq3TEIX9IWEDuU+lQG0noeHzKZ6k1J22iNAiL7fEXNWNy2H7igzJbj6svbH2LTRKxEW2Cj9Qkqzip5UapHmGZf6G6E7VkMvmJsbrW5uoZAVq2vP+ocuKmzBPaBlqko9F0YKglwXyhfaQQQ0Y3x4secMwC12")
	require.NoError(t, err)
	err = db.AddUser(context.Background(), &User{
		Username: "legacyuser",
		Secrets:  secrets,
	})
	require.NoError(t, err)

	secrets, err = base64.StdEncoding.DecodeString("YWJjZHpSayGYcjcKbUNfJJjNOXxgxV+GWTVYinpeKqTSfUjUuT4+Hs2uZY68+KvnXkPkoV1eo4HvpVzxy683DHi8Ih+P4Nuqz4FhhLddFnZlzPn1sHuvSjs8S2qGP/jO5+3075I/TWiT2CxO8B83ezMX7tmlwvTbWdYbmV1saEyCVFssuzTARcfvee0f6YvFe9eX1iHfAwXvPsdrt0eTqbTcUzDzv5pQb/t18MtJsK6cB2vh3XJO0psbBWsshGNJYIkMaiGmhi457zejvIt1xcC+dsZZUJVpvoGrZvHd25gH9PLQ/VSU0atrhXS93nsdW8+Y4M4tDFZ8R9pZsseZKt4Zuj1FbxD/qZcdm2w8KaCQgVjzzJJu6//Z5/qF0Neycmm6uiAs4zQWVkibtR9BLEmwHsLd2u4n1EhPAzp14kyzI72/")
	require.NoError(t, err)
	err = db.AddUser(context.Background(), &User{
		Username: "testusername",
		Secrets:  secrets,
	})
	require.NoError(t, err)

	return db
}

func doChallengeResponse(t *testing.T, sk *ecdsa.PrivateKey, username, pin string) string {
	// retrieve a challenge
	auth := &irma.KeyshareAuthChallenge{}
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/users/verify_start",
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

func loadClientPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	testdata := test.FindTestdataFolder(t)
	bts, err := os.ReadFile(filepath.Join(testdata, "client", "ecdsa_sk.pem"))
	require.NoError(t, err)
	sk, err := signed.UnmarshalPemPrivateKey(bts)
	require.NoError(t, err)
	return sk
}

func registrationJWT(t *testing.T, sk *ecdsa.PrivateKey, data irma.KeyshareKeyRegistrationData) string {
	j, err := jwt.NewWithClaims(jwt.SigningMethodES256, irma.KeyshareKeyRegistrationClaims{
		KeyshareKeyRegistrationData: data,
	}).SignedString(sk)
	require.NoError(t, err)
	return j
}
