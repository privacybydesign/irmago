package server

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/privacybydesign/irmago"
	"github.com/stretchr/testify/require"
)

func TestParseSessionRequest(t *testing.T) {
	requestJson := `{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"M3LYmTr3CZDYZkMNK2uCCg==","protocolVersion":"2.5","disclose":[[["irma-demo.RU.studentCard.studentID"]]],"labels":{"0":null}}`
	requestorRequestJson := fmt.Sprintf(`{"request": %s}`, requestJson)
	t.Run("valid json string", func(t *testing.T) {
		res, err := ParseSessionRequest(requestJson)
		require.NoError(t, err)
		require.Equal(t,
			"irma-demo.RU.studentCard.studentID",
			res.SessionRequest().Disclosure().Disclose[0][0][0].Type.String())
	})

	t.Run("valid byte array", func(t *testing.T) {
		res, err := ParseSessionRequest([]byte(requestJson))
		require.NoError(t, err)
		require.Equal(t,
			"irma-demo.RU.studentCard.studentID",
			res.SessionRequest().Disclosure().Disclose[0][0][0].Type.String())
	})

	t.Run("valid struct", func(t *testing.T) {
		request := &irma.DisclosureRequest{}
		require.NoError(t, json.Unmarshal([]byte(requestJson), request))
		res, err := ParseSessionRequest(request)
		require.NoError(t, err)
		require.Equal(t,
			"irma-demo.RU.studentCard.studentID",
			res.SessionRequest().Disclosure().Disclose[0][0][0].Type.String())
	})

	t.Run("requestor request string", func(t *testing.T) {
		res, err := ParseSessionRequest(requestorRequestJson)
		require.NoError(t, err)
		require.Equal(t,
			"irma-demo.RU.studentCard.studentID",
			res.SessionRequest().Disclosure().Disclose[0][0][0].Type.String())
	})

	t.Run("requestor request struct", func(t *testing.T) {
		request := &irma.DisclosureRequest{}
		require.NoError(t, json.Unmarshal([]byte(requestJson), request))
		sessionRequest := &irma.ServiceProviderRequest{
			Request: request,
		}

		res, err := ParseSessionRequest(sessionRequest)
		require.NoError(t, err)
		require.Equal(t,
			"irma-demo.RU.studentCard.studentID",
			res.SessionRequest().Disclosure().Disclose[0][0][0].Type.String())
		req, ok := res.(*irma.ServiceProviderRequest)
		require.True(t, ok)
		require.Equal(t, request, req.Request)
	})

	t.Run("invalid type", func(t *testing.T) {
		_, err := ParseSessionRequest(42)
		require.Error(t, err)
	})

	t.Run("invalid string", func(t *testing.T) {
		_, err := ParseSessionRequest(`{"foo": "bar"}`)
		require.Error(t, err)
	})
}
