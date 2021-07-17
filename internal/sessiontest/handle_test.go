package sessiontest

import (
	"net/http"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/stretchr/testify/require"
)

func init() {
	common.ForceHTTPS = false
	irma.SetLogger(logger)
}

func TestHandleSessionDelete(t *testing.T) {
	StartIrmaServer(t, false, "")
	defer StopIrmaServer()

	// Setup a new disclosure session
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	session := startSession(t, getDisclosureRequest(id), "verification")

	// Attempt to delete the disclosed session
	req, reqErr := http.NewRequest(http.MethodDelete, "http://localhost:48682/session/"+session.Token, nil)
	require.NoError(t, reqErr)

	// Verify the API response
	// TODO: Also test the actual deletion of the session
	res, resErr := (&http.Client{}).Do(req)
	require.NoError(t, resErr)
	require.Equal(t, res.StatusCode, http.StatusNoContent)
}
