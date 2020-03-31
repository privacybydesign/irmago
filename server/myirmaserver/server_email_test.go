//+build !local_tests

package myirmaserver

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestServerLoginEmail(t *testing.T) {
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
	StartKeyshareServer(t, db, "localhost:1025")
	defer StopKeyshareServer(t)

	reqData := bytes.NewBufferString(`{"email": "dne", "language": "en"}`)
	res, err := http.Post("http://localhost:8080/login/email", "application/json", reqData)
	assert.NoError(t, err)
	assert.NotEqual(t, 204, res.StatusCode)
	res.Body.Close()

	reqData = bytes.NewBufferString(`{"email": "test@test.com", "language":"en"}`)
	res, err = http.Post("http://localhost:8080/login/email", "application/json", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 204, res.StatusCode)
	res.Body.Close()

	reqData = bytes.NewBufferString(`{"email": "test@test.com", "language":"dne"}`)
	res, err = http.Post("http://localhost:8080/login/email", "application/json", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 204, res.StatusCode)
	res.Body.Close()
}
