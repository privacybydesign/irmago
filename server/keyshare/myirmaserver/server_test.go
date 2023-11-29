package myirmaserver

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
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

var (
	str15    = "15"
	strEmpty = ""
)

func TestServerInvalidMessage(t *testing.T) {
	myirmaServer, httpServer := StartMyIrmaServer(t, newMemoryDB(), "")
	defer StopMyIrmaServer(t, myirmaServer, httpServer)

	test.HTTPGet(t, nil, "http://localhost:8081/user", nil, 400, nil)

	test.HTTPGet(t, nil, "http://localhost:8081/user/logs/0", nil, 400, nil)

	test.HTTPPost(t, nil, "http://localhost:8081/user/delete", "", nil, 400, nil)

	test.HTTPPost(t, nil, "http://localhost:8081/email/add", "", nil, 400, nil)

	test.HTTPPost(t, nil, "http://localhost:8081/email/remove", "", nil, 400, nil)
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
				email:      []string{"test@example.com"},
			},
		},
		loginEmailTokens: map[string]string{
			"testtoken": "test@example.com",
		},
	}
	myirmaServer, httpServer := StartMyIrmaServer(t, db, "")
	defer StopMyIrmaServer(t, myirmaServer, httpServer)

	client := test.NewHTTPClient()

	test.HTTPPost(t, client, "http://localhost:8081/login/irma", "", nil, 200, nil)

	test.HTTPPost(t, client, "http://localhost:8081/login/token", `{"username":"testuser","token":"testtoken"}`, nil, 204, nil)

	test.HTTPPost(t, client, "http://localhost:8081/email/add", "", nil, 200, nil)
}

func TestServerSessionMgmnt(t *testing.T) {
	db := &memoryDB{
		userData: map[string]memoryUserData{
			"testuser": {
				id:         15,
				lastActive: time.Unix(0, 0),
				email:      []string{"test@example.com"},
			},
			"noemail": {
				id:         17,
				lastActive: time.Unix(0, 0),
			},
		},
		loginEmailTokens: map[string]string{
			"testtoken": "test@example.com",
		},
		verifyEmailTokens: map[string]int64{
			"testemailtoken": 15,
		},
	}
	myirmaServer, httpServer := StartMyIrmaServer(t, db, "")
	defer StopMyIrmaServer(t, myirmaServer, httpServer)

	client := test.NewHTTPClient()

	var body []byte
	test.HTTPPost(t, client, "http://localhost:8081/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8081/login/irma", "", nil, 200, nil)

	test.HTTPPost(t, client, "http://localhost:8081/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8081/login/token/candidates", "doesnotexist", textPlainHeader(), 403, nil)

	var cands []loginCandidate
	test.HTTPPost(t, client, "http://localhost:8081/login/token/candidates", "testtoken", textPlainHeader(), 200, &cands)
	assert.Equal(t, 1, len(cands))
	assert.Equal(t, "testuser", cands[0].Username)

	test.HTTPPost(t, client, "http://localhost:8081/login/token", `{"token": "doesnotexist", "username": "testuser"}`, nil, 403, nil)

	test.HTTPPost(t, client, "http://localhost:8081/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8081/login/token", `{"token": "testtoken", "username":"doesnotexist"}`, nil, 403, nil)

	test.HTTPPost(t, client, "http://localhost:8081/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8081/login/token", `{"token": "testtoken", "username":"noemail"}`, nil, 403, nil)

	test.HTTPPost(t, client, "http://localhost:8081/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8081/login/token", `{"token": "testtoken", "username":"testuser"}`, nil, 204, nil)

	test.HTTPPost(t, client, "http://localhost:8081/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("ok"), body)

	test.HTTPPost(t, client, "http://localhost:8081/logout", "", nil, 204, nil)

	test.HTTPPost(t, client, "http://localhost:8081/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8081/verify", "doesnotexist", textPlainHeader(), 403, nil)

	test.HTTPPost(t, client, "http://localhost:8081/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)

	test.HTTPPost(t, client, "http://localhost:8081/verify", "testemailtoken", textPlainHeader(), 204, nil)

	test.HTTPPost(t, client, "http://localhost:8081/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("ok"), body)

	test.HTTPPost(t, client, "http://localhost:8081/user/delete", "", nil, 204, nil)

	test.HTTPPost(t, client, "http://localhost:8081/checksession", "", nil, 200, &body)
	assert.Equal(t, []byte("expired"), body)
}

func TestServerUserData(t *testing.T) {
	db := &memoryDB{
		userData: map[string]memoryUserData{
			"testuser": {
				id:         15,
				lastActive: time.Unix(0, 0),
				email:      []string{"test@github.com"},
				logEntries: []logEntry{
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
			"testtoken": "test@github.com",
		},
	}
	myirmaServer, httpServer := StartMyIrmaServer(t, db, "")
	defer StopMyIrmaServer(t, myirmaServer, httpServer)

	client := test.NewHTTPClient()

	test.HTTPPost(t, client, "http://localhost:8081/login/token", `{"username":"testuser", "token":"testtoken"}`, nil, 204, nil)

	var userdata user
	test.HTTPGet(t, client, "http://localhost:8081/user", nil, 200, &userdata)
	assert.Equal(t, []userEmail{{Email: "test@github.com", DeleteInProgress: false}}, userdata.Emails)

	test.HTTPPost(t, client, "http://localhost:8081/email/remove", "test@github.com", textPlainHeader(), 204, nil)

	userdata = user{}
	test.HTTPGet(t, client, "http://localhost:8081/user", nil, 200, &userdata)
	assert.Empty(t, userdata.Emails)

	test.HTTPGet(t, client, "http://localhost:8081/user/logs/abcd", nil, 400, nil)

	var logs []logEntry
	test.HTTPGet(t, client, "http://localhost:8081/user/logs/0", nil, 200, &logs)
	assert.Equal(t, []logEntry{
		{Timestamp: 110, Event: "test", Param: &strEmpty},
		{Timestamp: 120, Event: "test2", Param: &str15},
	}, logs)

	test.HTTPGet(t, client, "http://localhost:8081/user/logs/1", nil, 200, &logs)
	assert.Equal(t, []logEntry{
		{Timestamp: 120, Event: "test2", Param: &str15},
	}, logs)
}

func StartMyIrmaServer(t *testing.T, db db, emailserver string) (*Server, *http.Server) {
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
		LoginURL: map[string]string{
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

	s.Stop()

	serv := &http.Server{
		Addr:    "localhost:8081",
		Handler: r,
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

func StopMyIrmaServer(t *testing.T, myirmaServer *Server, httpServer *http.Server) {
	myirmaServer.Stop()
	err := httpServer.Shutdown(context.Background())
	assert.NoError(t, err)
}
