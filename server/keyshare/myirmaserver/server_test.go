package myirmaserver

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi"
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
	StartMyIrmaServer(t, newMemoryDB(), "localhost:1025")
	defer StopKeyshareServer(t)

	test.HTTPGet(t, nil, "http://localhost:8080/user", nil, 400, nil)

	test.HTTPGet(t, nil, "http://localhost:8080/user/logs/0", nil, 400, nil)

	test.HTTPPost(t, nil, "http://localhost:8080/user/delete", "", nil, 400, nil)

	test.HTTPPost(t, nil, "http://localhost:8080/email/add", "", nil, 400, nil)

	test.HTTPPost(t, nil, "http://localhost:8080/email/remove", "", nil, 400, nil)
}

func textPlainHeader() http.Header {
	return http.Header{"Content-Type": []string{"text/plain"}}
}

func TestServerIrmaSessions(t *testing.T) {
	db := &memoryDB{
		userData: map[string]memoryUserData{
			"testuser": {
				id:         15,
				lastActive: time.Unix(0, 0),
				email:      []string{"test@test.com"},
			},
		},
		loginEmailTokens: map[string]string{
			"testtoken": "test@test.com",
		},
	}
	StartMyIrmaServer(t, db, "")
	defer StopKeyshareServer(t)

	client := test.NewHTTPClient()

	test.HTTPPost(t, client, "http://localhost:8080/login/irma", "", nil, 200, nil)

	test.HTTPPost(t, client, "http://localhost:8080/login/token", `{"username":"testuser","token":"testtoken"}`, nil, 204, nil)

	test.HTTPPost(t, client, "http://localhost:8080/email/add", "", nil, 200, nil)
}

func TestServerSessionMgmnt(t *testing.T) {
	db := &memoryDB{
		userData: map[string]memoryUserData{
			"testuser": {
				id:         15,
				lastActive: time.Unix(0, 0),
				email:      []string{"test@test.com"},
			},
			"noemail": {
				id:         17,
				lastActive: time.Unix(0, 0),
			},
		},
		loginEmailTokens: map[string]string{
			"testtoken": "test@test.com",
		},
		verifyEmailTokens: map[string]int64{
			"testemailtoken": 15,
		},
	}
	StartMyIrmaServer(t, db, "")
	defer StopKeyshareServer(t)

	client := test.NewHTTPClient()

	var body []byte
	test.HTTPPost(t, client, "http://localhost:8080/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8080/login/irma", "", nil, 200, nil)

	test.HTTPPost(t, client, "http://localhost:8080/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8080/login/token/candidates", "doesnotexist", textPlainHeader(), 400, nil)

	var cands []LoginCandidate
	test.HTTPPost(t, client, "http://localhost:8080/login/token/candidates", "testtoken", textPlainHeader(), 200, &cands)
	assert.Equal(t, 1, len(cands))
	assert.Equal(t, "testuser", cands[0].Username)

	test.HTTPPost(t, client, "http://localhost:8080/login/token", `{"token": "doesnotexist", "username": "testuser"}`, nil, 400, nil)

	test.HTTPPost(t, client, "http://localhost:8080/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8080/login/token", `{"token": "testtoken", "username":"doesnotexist"}`, nil, 400, nil)

	test.HTTPPost(t, client, "http://localhost:8080/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8080/login/token", `{"token": "testtoken", "username":"noemail"}`, nil, 400, nil)

	test.HTTPPost(t, client, "http://localhost:8080/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8080/login/token", `{"token": "testtoken", "username":"testuser"}`, nil, 204, nil)

	test.HTTPPost(t, client, "http://localhost:8080/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("ok"), body)

	test.HTTPPost(t, client, "http://localhost:8080/logout", "", nil, 204, nil)

	test.HTTPPost(t, client, "http://localhost:8080/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8080/verify", "doesnotexist", textPlainHeader(), 400, nil)

	test.HTTPPost(t, client, "http://localhost:8080/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8080/verify", "testemailtoken", textPlainHeader(), 204, nil)

	test.HTTPPost(t, client, "http://localhost:8080/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("ok"), body)

	test.HTTPPost(t, client, "http://localhost:8080/user/delete", "", nil, 204, nil)

	test.HTTPPost(t, client, "http://localhost:8080/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)
}

func TestServerUserData(t *testing.T) {
	db := &memoryDB{
		userData: map[string]memoryUserData{
			"testuser": {
				id:         15,
				lastActive: time.Unix(0, 0),
				email:      []string{"test@test.com"},
				logEntries: []LogEntry{
					{
						Timestamp: 110,
						Event:     "test",
						Param:     &strEmpty,
					},
					{
						Timestamp: 120,
						Event:     "test2",
						Param:     &str15,
					},
				},
			},
		},
		loginEmailTokens: map[string]string{
			"testtoken": "test@test.com",
		},
	}
	StartMyIrmaServer(t, db, "")
	defer StopKeyshareServer(t)

	client := test.NewHTTPClient()

	test.HTTPPost(t, client, "http://localhost:8080/login/token", `{"username":"testuser", "token":"testtoken"}`, nil, 204, nil)

	var userdata User
	test.HTTPGet(t, client, "http://localhost:8080/user", nil, 200, &userdata)
	assert.Equal(t, []UserEmail{{Email: "test@test.com", DeleteInProgress: false}}, userdata.Emails)

	test.HTTPPost(t, client, "http://localhost:8080/email/remove", "test@test.com", textPlainHeader(), 204, nil)

	userdata = User{}
	test.HTTPGet(t, client, "http://localhost:8080/user", nil, 200, &userdata)
	assert.Empty(t, userdata.Emails)

	test.HTTPGet(t, client, "http://localhost:8080/user/logs/abcd", nil, 400, nil)

	var logs []LogEntry
	test.HTTPGet(t, client, "http://localhost:8080/user/logs/0", nil, 200, &logs)
	assert.Equal(t, []LogEntry{
		{Timestamp: 110, Event: "test", Param: &strEmpty},
		{Timestamp: 120, Event: "test2", Param: &str15},
	}, logs)

	test.HTTPGet(t, client, "http://localhost:8080/user/logs/1", nil, 200, &logs)
	assert.Equal(t, []LogEntry{
		{Timestamp: 120, Event: "test2", Param: &str15},
	}, logs)
}

var keyshareServ *http.Server

func StartMyIrmaServer(t *testing.T, db DB, emailserver string) {
	testdataPath := test.FindTestdataFolder(t)
	s, err := New(&Configuration{
		Configuration: &server.Configuration{
			SchemesPath: filepath.Join(testdataPath, "irma_configuration"),
			Logger:      irma.Logger,
		},
		EmailConfiguration: keyshare.EmailConfiguration{
			EmailServer:     emailserver,
			EmailFrom:       "test@example.com",
			DefaultLanguage: "en",
		},
		DB:                 db,
		SessionLifetime:    15 * 60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		LoginEmailFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		LoginEmailSubjects: map[string]string{
			"en": "testsubject",
		},
		LoginEmailBaseURL: map[string]string{
			"en": "http://example.com/verify/",
		},
		DeleteEmailFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		DeleteEmailSubjects: map[string]string{
			"en": "testsubject",
		},
		DeleteAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		DeleteAccountSubjects: map[string]string{
			"en": "testsubject",
		},
	})
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Mount("/", s.Handler())

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
