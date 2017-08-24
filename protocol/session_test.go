package protocol

import (
	"encoding/json"
	"testing"

	"encoding/base64"

	"github.com/credentials/irmago"
	"github.com/stretchr/testify/require"
)

type TestHandler struct {
	t *testing.T
}

func (th TestHandler) StatusUpdate(action Action, status Status) {}
func (th TestHandler) Success(action Action)                     {}
func (th TestHandler) Cancelled(action Action) {
	th.t.FailNow()
}
func (th TestHandler) Failure(action Action, err SessionError, info string) {
	th.t.Fatal(string(err), info)
}
func (th TestHandler) UnsatisfiableRequest(action Action, missing irmago.AttributeDisjunctionList) {
	th.t.FailNow()
}
func (th TestHandler) AskIssuancePermission(request IssuanceRequest, ServerName string, choice PermissionHandler) {
}
func (th TestHandler) AskVerificationPermission(request DisclosureRequest, ServerName string, callback PermissionHandler) {
	choice := &irmago.DisclosureChoice{
		Attributes: []*irmago.AttributeIdentifier{},
	}
	var candidates []*irmago.AttributeIdentifier
	for _, disjunction := range request.Content {
		candidates = irmago.Manager.Candidates(disjunction)
		require.NotNil(th.t, candidates)
		require.NotEmpty(th.t, candidates, 1)
		choice.Attributes = append(choice.Attributes, candidates[0])
	}
	callback(true, choice)
}
func (th TestHandler) AskSignaturePermission(request SignatureRequest, ServerName string, choice PermissionHandler) {
}

func TestSession(t *testing.T) {
	id := irmago.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentNumber")
	url := "https://demo.irmacard.org/tomcat/irma_api_server/api/v2"
	name := "testsp"

	spRequest := NewServiceProviderJwt(name, DisclosureRequest{
		Content: irmago.AttributeDisjunctionList([]*irmago.AttributeDisjunction{
			&irmago.AttributeDisjunction{
				Label:      "foo",
				Attributes: []irmago.AttributeTypeIdentifier{id},
			},
		}),
	})

	headerbytes, err := json.Marshal(&map[string]string{"alg": "none", "typ": "JWT"})
	require.NoError(t, err)
	bodybytes, err := json.Marshal(spRequest)
	require.NoError(t, err)

	jwt := base64.StdEncoding.EncodeToString(headerbytes) + "." + base64.StdEncoding.EncodeToString(bodybytes) + "."
	qr, err := StartSession(jwt, url)
	require.NoError(t, err)

	NewSession(qr, TestHandler{t})
}
