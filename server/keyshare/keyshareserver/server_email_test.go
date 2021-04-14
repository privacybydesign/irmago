//+build !local_tests

package keyshareserver

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServerRegistrationWithEmail(t *testing.T) {
	StartKeyshareServer(t, NewMemoryDatabase(), "localhost:1025")
	defer StopKeyshareServer(t)

	reqData := bytes.NewBufferString(`{"pin":"testpin","email":"test@test.com","language":"en"}`)
	res, err := http.Post("http://localhost:8080/irma_keyshare_server/api/v1/client/register", "application/json", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)

	reqData = bytes.NewBufferString(`{"pin":"testpin","email":"test@test.com","language":"dne"}`)
	res, err = http.Post("http://localhost:8080/irma_keyshare_server/api/v1/client/register", "application/json", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)

	reqData = bytes.NewBufferString(`{"pin":"testpin","language":"en"}`)
	res, err = http.Post("http://localhost:8080/irma_keyshare_server/api/v1/client/register", "application/json", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)

	reqData = bytes.NewBufferString(`{"pin":"testpin","language":"dne"}`)
	res, err = http.Post("http://localhost:8080/irma_keyshare_server/api/v1/client/register", "application/json", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
}
