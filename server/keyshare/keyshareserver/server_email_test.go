//+build !local_tests

package keyshareserver

import (
	"testing"
)

func TestServerRegistrationWithEmail(t *testing.T) {
	StartKeyshareServer(t, NewMemoryDatabase(), "localhost:1025")
	defer StopKeyshareServer(t)

	post(t, "http://localhost:8080/irma_keyshare_server/api/v1/client/register",
		`{"pin":"testpin","email":"test@test.com","language":"en"}`,
		nil,
		200,
		nil,
	)

	post(t, "http://localhost:8080/irma_keyshare_server/api/v1/client/register",
		`{"pin":"testpin","email":"test@test.com","language":"dne"}`,
		nil,
		200,
		nil,
	)

	post(t, "http://localhost:8080/irma_keyshare_server/api/v1/client/register",
		`{"pin":"testpin","language":"en"}`,
		nil,
		200,
		nil,
	)

	post(t, "http://localhost:8080/irma_keyshare_server/api/v1/client/register",
		`{"pin":"testpin","language":"dne"}`,
		nil,
		200,
		nil,
	)
}