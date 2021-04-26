package myirmaserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
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
	StartKeyshareServer(t, NewMyirmaMemoryDB(), "localhost:1025")
	defer StopKeyshareServer(t)

	reqData := bytes.NewBufferString("gval;kefsajsdkl;")
	res, err := http.Post("http://localhost:8080/login/email", "application/json", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 400, res.StatusCode)
	_ = res.Body.Close()

	reqData = bytes.NewBufferString("aljksd;falsdfjgkj223hl4jk")
	res, err = http.Post("http://localhost:8080/login/token", "application/json", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 400, res.StatusCode)
	_ = res.Body.Close()

	res, err = http.Get("http://localhost:8080/user/logs/abcd")
	assert.NoError(t, err)
	assert.Equal(t, 404, res.StatusCode)
	_ = res.Body.Close()

	res, err = http.Get("http://localhost:8080/user")
	assert.NoError(t, err)
	assert.Equal(t, 400, res.StatusCode)
	_ = res.Body.Close()

	res, err = http.Get("http://localhost:8080/user/logs/0")
	assert.NoError(t, err)
	assert.Equal(t, 400, res.StatusCode)
	_ = res.Body.Close()

	res, err = http.Post("http://localhost:8080/user/delete", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 400, res.StatusCode)
	_ = res.Body.Close()

	res, err = http.Post("http://localhost:8080/email/add", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 400, res.StatusCode)
	_ = res.Body.Close()

	res, err = http.Post("http://localhost:8080/email/remove", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 400, res.StatusCode)
	_ = res.Body.Close()
}

func TestServerIrmaSessions(t *testing.T) {
	db := &MyirmaMemoryDB{
		UserData: map[string]MemoryUserData{
			"testuser": MemoryUserData{
				ID:         15,
				LastActive: time.Unix(0, 0),
				Email:      []string{"test@test.com"},
			},
		},
		LoginEmailTokens: map[string]string{
			"testtoken": "test@test.com",
		},
	}
	StartKeyshareServer(t, db, "")
	defer StopKeyshareServer(t)

	res, err := http.Post("http://localhost:8080/login/irma", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	_ = res.Body.Close()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar: jar,
	}
	reqData := bytes.NewBufferString(`{"username":"testuser","token":"testtoken"}`)
	res, err = client.Post("http://localhost:8080/login/token", "application/json", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 204, res.StatusCode)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/email/add", "application/json", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
}

func TestServerSessionMgmnt(t *testing.T) {
	db := &MyirmaMemoryDB{
		UserData: map[string]MemoryUserData{
			"testuser": MemoryUserData{
				ID:         15,
				LastActive: time.Unix(0, 0),
				Email:      []string{"test@test.com"},
			},
			"noemail": MemoryUserData{
				ID:         17,
				LastActive: time.Unix(0, 0),
			},
		},
		LoginEmailTokens: map[string]string{
			"testtoken": "test@test.com",
		},
		VerifyEmailTokens: map[string]int64{
			"testemailtoken": 15,
		},
	}
	StartKeyshareServer(t, db, "")
	defer StopKeyshareServer(t)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar: jar,
	}

	res, err := client.Post("http://localhost:8080/checksession", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("expired"), body)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/login/irma", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/checksession", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err = ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("expired"), body)
	_ = res.Body.Close()

	reqData := bytes.NewBufferString("doesnotexist")
	res, err = client.Post("http://localhost:8080/login/token/candidates", "text/plain", reqData)
	assert.NoError(t, err)
	assert.NotEqual(t, 200, res.StatusCode)
	_ = res.Body.Close()

	reqData = bytes.NewBufferString("testtoken")
	res, err = client.Post("http://localhost:8080/login/token/candidates", "text/plain", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err = ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	var cands []LoginCandidate
	err = json.Unmarshal(body, &cands)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(cands))
	assert.Equal(t, "testuser", cands[0].Username)
	_ = res.Body.Close()

	reqData = bytes.NewBufferString(`{"token": "doesnotexist", "username":"testuser"}`)
	res, err = client.Post("http://localhost:8080/login/token", "application/json", reqData)
	assert.NoError(t, err)
	assert.NotEqual(t, 204, res.StatusCode)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/checksession", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err = ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("expired"), body)
	_ = res.Body.Close()

	reqData = bytes.NewBufferString(`{"token": "testtoken", "username":"doesnotexist"}`)
	res, err = client.Post("http://localhost:8080/login/token", "application/json", reqData)
	assert.NoError(t, err)
	assert.NotEqual(t, 204, res.StatusCode)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/checksession", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err = ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("expired"), body)
	_ = res.Body.Close()

	reqData = bytes.NewBufferString(`{"token": "testtoken", "username":"noemail"}`)
	res, err = client.Post("http://localhost:8080/login/token", "application/json", reqData)
	assert.NoError(t, err)
	assert.NotEqual(t, 204, res.StatusCode)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/checksession", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err = ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("expired"), body)
	_ = res.Body.Close()

	reqData = bytes.NewBufferString(`{"token": "testtoken", "username":"testuser"}`)
	res, err = client.Post("http://localhost:8080/login/token", "application/json", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 204, res.StatusCode)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/checksession", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err = ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("ok"), body)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/logout", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 204, res.StatusCode)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/checksession", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err = ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("expired"), body)
	_ = res.Body.Close()

	reqData = bytes.NewBufferString("doesnotexist")
	res, err = client.Post("http://localhost:8080/verify", "text/plain", reqData)
	assert.NoError(t, err)
	assert.NotEqual(t, 204, res.StatusCode)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/checksession", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err = ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("expired"), body)
	_ = res.Body.Close()

	reqData = bytes.NewBufferString("testemailtoken")
	res, err = client.Post("http://localhost:8080/verify", "text/plain", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 204, res.StatusCode)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/checksession", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err = ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("ok"), body)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/user/delete", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 204, res.StatusCode)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/checksession", "", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err = ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("expired"), body)
	_ = res.Body.Close()
}

func TestServerUserData(t *testing.T) {
	db := &MyirmaMemoryDB{
		UserData: map[string]MemoryUserData{
			"testuser": MemoryUserData{
				ID:         15,
				LastActive: time.Unix(0, 0),
				Email:      []string{"test@test.com"},
				LogEntries: []LogEntry{
					LogEntry{
						Timestamp: 110,
						Event:     "test",
						Param:     "",
					},
					LogEntry{
						Timestamp: 120,
						Event:     "test2",
						Param:     "15",
					},
				},
			},
		},
		LoginEmailTokens: map[string]string{
			"testtoken": "test@test.com",
		},
	}
	StartKeyshareServer(t, db, "")
	defer StopKeyshareServer(t)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar: jar,
	}

	reqData := bytes.NewBufferString(`{"username":"testuser", "token":"testtoken"}`)
	res, err := client.Post("http://localhost:8080/login/token", "application/json", reqData)
	require.NoError(t, err)
	require.Equal(t, 204, res.StatusCode)
	_ = res.Body.Close()

	res, err = client.Get("http://localhost:8080/user")
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	var userdata UserInformation
	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	err = json.Unmarshal(body, &userdata)
	assert.NoError(t, err)
	assert.Equal(t, []UserEmail{{Email: "test@test.com", DeleteInProgress: false}}, userdata.Emails)
	_ = res.Body.Close()

	reqData = bytes.NewBufferString("test@test.com")
	res, err = client.Post("http://localhost:8080/email/remove", "text/plain", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 204, res.StatusCode)
	_ = res.Body.Close()

	res, err = client.Get("http://localhost:8080/user")
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err = ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	err = json.Unmarshal(body, &userdata)
	assert.NoError(t, err)
	assert.NotEqual(t, []string{"test@test.com"}, userdata.Emails)
	_ = res.Body.Close()

	res, err = client.Get("http://localhost:8080/user/logs/0")
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err = ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	var logs []LogEntry
	err = json.Unmarshal(body, &logs)
	assert.NoError(t, err)
	assert.Equal(t, []LogEntry{
		LogEntry{
			Timestamp: 110,
			Event:     "test",
			Param:     "",
		},
		LogEntry{
			Timestamp: 120,
			Event:     "test2",
			Param:     "15",
		},
	}, logs)

	res, err = client.Get("http://localhost:8080/user/logs/1")
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	body, err = ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	err = json.Unmarshal(body, &logs)
	assert.NoError(t, err)
	assert.Equal(t, []LogEntry{
		LogEntry{
			Timestamp: 120,
			Event:     "test2",
			Param:     "15",
		},
	}, logs)
}

var keyshareServ *http.Server

func StartKeyshareServer(t *testing.T, db MyirmaDB, emailserver string) {
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
		MyIRMAURL:          "http://localhost:8080/irma_keyshare_server/api/v1/",
		DB:                 db,
		SessionLifetime:    15 * 60,
		KeyshareAttributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")},
		EmailAttributes:    []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("test.test.email.email")},
		LoginEmailFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		LoginEmailSubject: map[string]string{
			"en": "testsubject",
		},
		LoginEmailBaseURL: map[string]string{
			"en": "http://example.com/verify/",
		},
		DeleteEmailFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		DeleteEmailSubject: map[string]string{
			"en": "testsubject",
		},
		DeleteAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		DeleteAccountSubject: map[string]string{
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
