package protocol

import (
	"encoding/json"
	"testing"

	"encoding/base64"

	"fmt"

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
	id := irmago.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	url := "https://demo.irmacard.org/tomcat/irma_api_server/api/v2/verification"
	name := "testsp"

	spRequest := NewServiceProviderJwt(name, DisclosureRequest{
		Content: irmago.AttributeDisjunctionList([]*irmago.AttributeDisjunction{
			&irmago.AttributeDisjunction{
				Label:      "foo",
				Attributes: []irmago.AttributeTypeIdentifier{id},
			},
		}),
	})
	fmt.Printf("%+v\n", spRequest.Request.Request.Content[0])

	headerbytes, err := json.Marshal(&map[string]string{"alg": "none", "typ": "JWT"})
	require.NoError(t, err)
	bodybytes, err := json.Marshal(spRequest)
	require.NoError(t, err)

	jwt := base64.StdEncoding.EncodeToString(headerbytes) + "." + base64.StdEncoding.EncodeToString(bodybytes) + "."
	fmt.Println(jwt)
	qr, transportErr := StartSession(jwt, url)
	if transportErr != nil {
		fmt.Println(transportErr.(*TransportError).ApiErr)
	}
	require.NoError(t, transportErr)

	NewSession(qr, TestHandler{t})
}
