package irmaserver

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/server"
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
