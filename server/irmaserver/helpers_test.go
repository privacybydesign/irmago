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
	require.Equal(t, `{"request":{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"MtILupG0g0J23GNR1YtupQ==","devMode":true,"disclose":[[["test.test.email.email"]]]}}`, string(out))
}
