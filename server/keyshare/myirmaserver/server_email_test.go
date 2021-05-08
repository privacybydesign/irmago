//+build !local_tests

package myirmaserver

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/test"
)

func TestServerLoginEmail(t *testing.T) {
	db := &myirmaMemoryDB{
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
	StartKeyshareServer(t, db, "localhost:1025")
	defer StopKeyshareServer(t)

	test.HTTPPost(t, nil, "http://localhost:8080/login/email", `{"email": "dne", "language": "en"}`, nil, 403, nil)

	test.HTTPPost(t, nil, "http://localhost:8080/login/email", `{"email": "test@test.com", "language":"en"}`, nil, 204, nil)

	test.HTTPPost(t, nil, "http://localhost:8080/login/email", `{"email": "test@test.com", "language":"dne"}`, nil, 204, nil)

	client := test.NewHTTPClient()

	test.HTTPPost(t, client, "http://localhost:8080/login/token", `{"username":"testuser", "token":"testtoken"}`, nil, 204, nil)

	test.HTTPPost(t, client, "http://localhost:8080/email/remove", "test@test.com", nil, 204, nil)

	test.HTTPPost(t, client, "http://localhost:8080/user/delete", "", nil, 204, nil)
}
