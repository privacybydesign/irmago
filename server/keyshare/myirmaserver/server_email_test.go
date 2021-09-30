//+build !local_tests

package myirmaserver

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/test"
)

func TestServerLoginEmail(t *testing.T) {
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
	myirmaServer, httpServer := StartMyIrmaServer(t, db, "localhost:1025")
	defer StopMyIrmaServer(t, myirmaServer, httpServer)

	test.HTTPPost(t, nil, "http://localhost:8081/login/email", `{"email": "nonexistinglanguage", "language": "en"}`, nil, 403, nil)

	test.HTTPPost(t, nil, "http://localhost:8081/login/email", `{"email": "test@test.com", "language":"en"}`, nil, 204, nil)

	test.HTTPPost(t, nil, "http://localhost:8081/login/email", `{"email": "test@test.com", "language":"nonexistinglanguage"}`, nil, 204, nil)

	client := test.NewHTTPClient()

	test.HTTPPost(t, client, "http://localhost:8081/login/token", `{"username":"testuser", "token":"testtoken"}`, nil, 204, nil)

	test.HTTPPost(t, client, "http://localhost:8081/email/remove", "test@test.com", nil, 204, nil)

	test.HTTPPost(t, client, "http://localhost:8081/user/delete", "", nil, 204, nil)
}

func TestServerInvalidEmailMessage(t *testing.T) {
	myirmaServer, httpServer := StartMyIrmaServer(t, newMemoryDB(), "localhost:1025")
	defer StopMyIrmaServer(t, myirmaServer, httpServer)

	test.HTTPPost(t, nil, "http://localhost:8081/login/email", "gval;kefsajsdkl;", nil, 400, nil)

	test.HTTPPost(t, nil, "http://localhost:8081/login/token", "gval;kefsajsdkl;", nil, 400, nil)
}
