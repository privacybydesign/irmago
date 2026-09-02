package irmaserver

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/irma/server"
	"github.com/stretchr/testify/require"
)

func TestAnonimizeRequest(t *testing.T) {
	req, err := server.ParseSessionRequest(`{"request":{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"MtILupG0g0J23GNR1YtupQ==","devMode":true,"disclose":[[[{"type":"test.test.email.email","value":"example@example.com"}]]]}}`)
	require.NoError(t, err)
	out, err := json.Marshal(purgeRequest(req))
	require.NoError(t, err)
	require.Equal(t, `{"validity":120,"request":{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"MtILupG0g0J23GNR1YtupQ==","devMode":true,"disclose":[[["test.test.email.email"]]]}}`, string(out))

	req, err = server.ParseSessionRequest(`{"request":{"@context":"https://irma.app/ld/request/issuance/v2","context":"AQ==","nonce":"wrmq+QY8r86nbGTI+mMAzg==","devMode":true,"credentials":[{"validity":2000000000,"keyCounter":2,"credential":"irma-demo.RU.studentCard","attributes":{"level":"42","studentCardNumber":"31415927","studentID":"s1234567","university":"Radboud"}}],"disclose":[[[{"type":"test.test.email.email","value":"example@example.com"}]]]}}`)
	require.NoError(t, err)
	out, err = json.Marshal(purgeRequest(req))
	require.NoError(t, err)
	require.Equal(t, `{"validity":120,"request":{"@context":"https://irma.app/ld/request/issuance/v2","context":"AQ==","nonce":"wrmq+QY8r86nbGTI+mMAzg==","devMode":true,"disclose":[[["test.test.email.email"]]],"credentials":[{"validity":2000000000,"keyCounter":2,"credential":"irma-demo.RU.studentCard","attributes":null}]}}`, string(out))
}

func TestNextSessionTimeout(t *testing.T) {
	const disclosure = `{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"MtILupG0g0J23GNR1YtupQ==","devMode":true,"disclose":[[["test.test.email.email"]]]}`

	for _, tc := range []struct {
		name     string
		request  string
		expected time.Duration
	}{
		{
			name:     "no next session falls back to the default",
			request:  `{"request":` + disclosure + `}`,
			expected: server.WriteTimeout,
		},
		{
			name:     "next session without a timeout falls back to the default",
			request:  `{"nextSession":{"url":"https://example.com"},"request":` + disclosure + `}`,
			expected: server.WriteTimeout,
		},
		{
			name:     "next session timeout is honoured",
			request:  `{"nextSession":{"url":"https://example.com","timeout":12},"request":` + disclosure + `}`,
			expected: 12 * time.Second,
		},
		{
			name:     "a timeout below the default does not shorten the handler",
			request:  `{"nextSession":{"url":"https://example.com","timeout":1},"request":` + disclosure + `}`,
			expected: server.WriteTimeout,
		},
		{
			// Without a URL nothing is fetched, so there is nothing to wait for.
			name:     "a timeout without a next session URL is ignored",
			request:  `{"nextSession":{"timeout":12},"request":` + disclosure + `}`,
			expected: server.WriteTimeout,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := server.ParseSessionRequest(tc.request)
			require.NoError(t, err)
			require.Equal(t, tc.expected, nextSessionTimeout(&sessionData{Rrequest: req}))
		})
	}
}

// A timeout above the configured maximum is refused when the session is started, which is what
// lets nextSessionTimeout use the stored value as is.
func TestNextSessionTimeoutAboveMaximumIsRefused(t *testing.T) {
	conf := sessionsConf(t)
	conf.MaxNextSessionTimeout = 15
	s, err := New(conf)
	require.NoError(t, err)
	defer s.Stop()

	_, _, _, err = s.StartSession(
		`{"nextSession":{"url":"https://example.com","timeout":600},"request":{"@context":"https://irma.app/ld/request/disclosure/v2","disclose":[[["test.test.email.email"]]]}}`,
		nil,
		"",
	)
	require.ErrorContains(t, err, "nextSession.timeout of 600 seconds exceeds the server maximum of 15")
}
