//go:build !local_tests
// +build !local_tests

package keyshareserver

import (
	"testing"

	"github.com/privacybydesign/irmago/internal/test"
)

func TestServerRegistrationWithEmail(t *testing.T) {
	keyshareServer, httpServer := StartKeyshareServer(t, NewMemoryDB(), "localhost:1025")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	test.HTTPPost(t, nil, "http://localhost:8080/client/register",
		`{"pin":"testpin","email":"test@example.com","language":"en"}`, nil,
		200, nil,
	)
	test.HTTPPost(t, nil, "http://localhost:8080/client/register",
		`{"pin":"testpin","email":"test@idonotexist-d8ejd84md7aja8.com","language":"en"}`, nil,
		400, nil, // no MX/A/AAAA record for idonotexist-d8ejd84md7aja8.com
	)

	// If somehow the IRMA app gains support for a language earlier than the keyshare server,
	// rejecting the registration would be too severe. So the registration is accepted and the
	// server falls back to its default language.
	test.HTTPPost(t, nil, "http://localhost:8080/client/register",
		`{"pin":"testpin","email":"test@example.com","language":"nonexistinglanguage"}`, nil,
		200, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/client/register",
		`{"pin":"testpin","language":"en"}`, nil,
		200, nil,
	)

	test.HTTPPost(t, nil, "http://localhost:8080/client/register",
		`{"pin":"testpin","language":"nonexistinglanguage"}`, nil,
		200, nil,
	)
}
