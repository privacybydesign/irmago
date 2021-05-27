package keyshareserver

import (
	"context"
	"encoding/base64"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/keysharecore"
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
	StartKeyshareServer(t, NewMemoryDB(), "")
	defer StopKeyshareServer(t)

	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/client/register",
		"gval;kefsajsdkl;", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/verify/pin",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/change/pin",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		400, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/prove/getCommitments",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		403, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/prove/getCommitments",
		"[]", nil,
		403, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/prove/getResponse",
		"asdlkzdsf;lskajl;kasdjfvl;jzxclvyewr", nil,
		403, nil,
	)
}

func TestServerHandleRegister(t *testing.T) {
	StartKeyshareServer(t, NewMemoryDB(), "")
	defer StopKeyshareServer(t)

	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/client/register",
		`{"pin":"testpin","email":"test@test.com","language":"en"}`, nil,
		200, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/client/register",
		`{"pin":"testpin","email":"test@test.com","language":"dne"}`, nil,
		200, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/client/register",
		`{"pin":"testpin","language":"en"}`, nil,
		200, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/client/register",
		`{"pin":"testpin","language":"dne"}`, nil,
		200, nil,
	)
}

func TestServerHandleValidate(t *testing.T) {
	db := createDB(t)
	StartKeyshareServer(t, db, "")
	defer StopKeyshareServer(t)

	var jwtMsg irma.KeysharePinStatus
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/verify/pin",
		`{"id":"testusername","pin":"puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n"}`, nil,
		200, &jwtMsg,
	)
	require.Equal(t, "success", jwtMsg.Status)

	var msg irma.KeyshareAuthorization
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/isAuthorized",
		"", http.Header{
			"X-IRMA-Keyshare-Username": []string{"testusername"},
			"Authorization":            []string{jwtMsg.Message},
		},
		200, &msg,
	)
	assert.Equal(t, "authorized", msg.Status)

	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/isAuthorized",
		"", http.Header{
			"X-IRMA-Keyshare-Username": []string{"testusername"},
			"Authorization":            []string{"Bearer " + jwtMsg.Message},
		},
		200, &msg,
	)
	assert.Equal(t, "authorized", msg.Status)

	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/isAuthorized",
		"", http.Header{
			"X-IRMA-Keyshare-Username": []string{"testusername"},
			"Authorization":            []string{"eyalksjdf.aljsdklfesdfhas.asdfhasdf"},
		},
		200, &msg,
	)
	assert.Equal(t, "expired", msg.Status)
}

func TestPinTries(t *testing.T) {
	db := createDB(t)
	StartKeyshareServer(t, &testDB{db: db, ok: true, tries: 1, wait: 0, err: nil}, "")
	defer StopKeyshareServer(t)

	var jwtMsg irma.KeysharePinStatus
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/verify/pin",
		`{"id":"testusername","pin":"puZGbaLDmFywGhFDi4vW2G87Zh"}`, nil,
		200, &jwtMsg,
	)
	require.Equal(t, "failure", jwtMsg.Status)
	require.Equal(t, "1", jwtMsg.Message)

	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/change/pin",
		`{"id":"testusername","oldpin":"puZGbaLDmFywGhFDi4vW2G87Zh","newpin":"ljaksdfj;alkf"}`, nil,
		200, &jwtMsg,
	)
	require.Equal(t, "failure", jwtMsg.Status)
	require.Equal(t, "1", jwtMsg.Message)
}

func TestPinNoRemainingTries(t *testing.T) {
	db := createDB(t)

	for _, ok := range []bool{true, false} {
		StartKeyshareServer(t, &testDB{db: db, ok: ok, tries: 0, wait: 5, err: nil}, "")

		var jwtMsg irma.KeysharePinStatus
		test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/verify/pin",
			`{"id":"testusername","pin":"puZGbaLDmFywGhFDi4vW2G87Zh"}`, nil,
			200, &jwtMsg,
		)
		require.Equal(t, "error", jwtMsg.Status)
		require.Equal(t, "5", jwtMsg.Message)

		test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/change/pin",
			`{"id":"testusername","oldpin":"puZGbaLDmFywGhFDi4vW2G87Zh","newpin":"ljaksdfj;alkf"}`, nil,
			200, &jwtMsg,
		)
		require.Equal(t, "error", jwtMsg.Status)
		require.Equal(t, "5", jwtMsg.Message)

		StopKeyshareServer(t)
	}
}

func TestMissingUser(t *testing.T) {
	StartKeyshareServer(t, NewMemoryDB(), "")
	defer StopKeyshareServer(t)

	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/isAuthorized",
		"", http.Header{
			"X-IRMA-Keyshare-Username": []string{"doesnotexist"},
			"Authorization":            []string{"ey.ey.ey"},
		},
		403, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/verify/pin",
		`{"id":"doesnotexist","pin":"bla"}`, nil,
		403, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/change/pin",
		`{"id":"doesnotexist","oldpin":"old","newpin":"new"}`, nil,
		403, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/prove/getCommitments",
		`["test.test-3"]`, http.Header{
			"X-IRMA-Keyshare-Username": []string{"doesnotexist"},
			"Authorization":            []string{"ey.ey.ey"},
		},
		403, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/prove/getResponse",
		"123456789", http.Header{
			"X-IRMA-Keyshare-Username": []string{"doesnotexist"},
			"Authorization":            []string{"ey.ey.ey"},
		},
		403, nil,
	)
}

func TestKeyshareSessions(t *testing.T) {
	db := createDB(t)
	StartKeyshareServer(t, db, "")
	defer StopKeyshareServer(t)

	var jwtMsg irma.KeysharePinStatus
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/users/verify/pin",
		`{"id":"testusername","pin":"puZGbaLDmFywGhFDi4vW2G87ZhXpaUsvymZwNJfB/SU=\n"}`, nil,
		200, &jwtMsg,
	)
	require.Equal(t, "success", jwtMsg.Status)

	// no active session, can't retrieve result
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/prove/getResponse",
		"12345678", http.Header{
			"X-IRMA-Keyshare-Username": []string{"testusername"},
			"Authorization":            []string{jwtMsg.Message},
		},
		400, nil,
	)

	// can't retrieve commitments with fake authorization
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/prove/getCommitments",
		`["test.test-3"]`, http.Header{
			"X-IRMA-Keyshare-Username": []string{"testusername"},
			"Authorization":            []string{"fakeauthorization"},
		},
		400, nil,
	)

	// retrieve commitments normally
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/prove/getCommitments",
		`["test.test-3"]`, http.Header{
			"X-IRMA-Keyshare-Username": []string{"testusername"},
			"Authorization":            []string{jwtMsg.Message},
		},
		200, nil,
	)

	// can't retrieve resukt with fake authorization
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/prove/getResponse",
		"12345678", http.Header{
			"X-IRMA-Keyshare-Username": []string{"testusername"},
			"Authorization":            []string{"fakeauthorization"},
		},
		400, nil,
	)

	// can start session while another is already active
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/prove/getCommitments",
		`["test.test-3"]`, http.Header{
			"X-IRMA-Keyshare-Username": []string{"testusername"},
			"Authorization":            []string{jwtMsg.Message},
		},
		200, nil,
	)

	// finish session
	test.HTTPPost(t, nil, "http://localhost:8080/irma_keyshare_server/api/v1/prove/getResponse",
		"12345678", http.Header{
			"X-IRMA-Keyshare-Username": []string{"testusername"},
			"Authorization":            []string{jwtMsg.Message},
		},
		200, nil,
	)
}

var keyshareServ *http.Server

func StartKeyshareServer(t *testing.T, db DB, emailserver string) {
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
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareAttribute:     irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"),
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

	r := chi.NewRouter()
	r.Mount("/irma_keyshare_server/api/v1/", s.Handler())

	keyshareServ = &http.Server{
		Addr:    "localhost:8080",
		Handler: r,
	}

	go func() {
		err := keyshareServ.ListenAndServe()
		if err == http.ErrServerClosed {
			err = nil
		}
		assert.NoError(t, err)
	}()
}

func StopKeyshareServer(t *testing.T) {
	err := keyshareServ.Shutdown(context.Background())
	assert.NoError(t, err)
}

type testDB struct {
	db    DB
	ok    bool
	tries int
	wait  int64
	err   error
}

func (db *testDB) AddUser(user *User) error {
	return db.db.AddUser(user)
}

func (db *testDB) User(username string) (*User, error) {
	return db.db.User(username)
}

func (db *testDB) UpdateUser(user *User) error {
	return db.db.UpdateUser(user)
}

func (db *testDB) ReservePinTry(user *User) (bool, int, int64, error) {
	return db.ok, db.tries, db.wait, db.err
}

func (db *testDB) ResetPinTries(user *User) error {
	return db.db.ResetPinTries(user)
}

func (db *testDB) SetSeen(user *User) error {
	return db.db.SetSeen(user)
}

func (db *testDB) AddLog(user *User, entrytype EventType, params interface{}) error {
	return db.db.AddLog(user, entrytype, params)
}

func (db *testDB) AddEmailVerification(user *User, email, token string) error {
	return db.db.AddEmailVerification(user, email, token)
}

func createDB(t *testing.T) DB {
	db := NewMemoryDB()
	err := db.AddUser(&User{
		Username: "",
		UserData: keysharecore.User{},
	})
	require.NoError(t, err)
	var ep keysharecore.User
	p, err := base64.StdEncoding.DecodeString("YWJjZK4w5SC+7D4lDrhiJGvB1iwxSeF90dGGPoGqqG7g3ivbfHibOdkKoOTZPbFlttBzn2EJgaEsL24Re8OWWWw5pd31/GCd14RXcb9Wy2oWhbr0pvJDLpIxXZt/qiQC0nJiIAYWLGZOdj5o0irDfqP1CSfw3IoKkVEl4lHRj0LCeINJIOpEfGlFtl4DHlWu8SMQFV1AIm3Gv64XzGncdkclVd41ti7cicBrcK8N2u9WvY/jCS4/Lxa2syp/O4IY")
	require.NoError(t, err)
	copy(ep[:], p)
	err = db.AddUser(&User{
		Username: "testusername",
		UserData: ep,
	})
	require.NoError(t, err)
	return db
}
