package protocol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/credentials/irmago"
	"github.com/stretchr/testify/require"
)

// Helper functions copypasted from irmago. AFAIK there is no way in go
// to reuse irmago test methods here without copypasting.

func TestMain(m *testing.M) {
	retCode := m.Run()

	err := os.RemoveAll("../testdata/storage/test")
	if err != nil {
		fmt.Println("Could not delete test storage")
		os.Exit(1)
	}

	os.Exit(retCode)
}

func parseMetaStore(t *testing.T) {
	require.NoError(t, irmago.MetaStore.ParseFolder("../testdata/irma_configuration"), "MetaStore.ParseFolder() failed")
}

func parseStorage(t *testing.T) {
	exists, err := irmago.PathExists("../testdata/storage/path")
	require.NoError(t, err, "pathexists() failed")
	if !exists {
		require.NoError(t, os.Mkdir("../testdata/storage/test", 0755), "Could not create test storage")
	}
	require.NoError(t, irmago.Manager.Init("../testdata/storage/test"), "Manager.Init() failed")
}

func parseAndroidStorage(t *testing.T) {
	require.NoError(t, irmago.Manager.ParseAndroidStorage(), "ParseAndroidStorage() failed")
}

func teardown(t *testing.T) {
	require.NoError(t, os.RemoveAll("../testdata/storage/test"))
}

type TestHandler struct {
	t *testing.T
	c chan *Error
}

func (th TestHandler) StatusUpdate(action Action, status Status) {}
func (th TestHandler) Success(action Action) {
	th.c <- nil
}
func (th TestHandler) Cancelled(action Action) {
	th.c <- &Error{}
}
func (th TestHandler) Failure(action Action, err *Error) {
	th.c <- err
}
func (th TestHandler) UnsatisfiableRequest(action Action, missing irmago.AttributeDisjunctionList) {
	th.c <- &Error{}
}
func (th TestHandler) AskIssuancePermission(request irmago.IssuanceRequest, ServerName string, choice PermissionHandler) {
}
func (th TestHandler) AskVerificationPermission(request irmago.DisclosureRequest, ServerName string, callback PermissionHandler) {
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
func (th TestHandler) AskSignaturePermission(request irmago.SignatureRequest, ServerName string, choice PermissionHandler) {
	th.AskVerificationPermission(request.DisclosureRequest, ServerName, choice)
}

func getDisclosureJwt(name string, id irmago.AttributeTypeIdentifier) interface{} {
	return NewServiceProviderJwt(name, irmago.DisclosureRequest{
		Content: irmago.AttributeDisjunctionList([]*irmago.AttributeDisjunction{
			&irmago.AttributeDisjunction{
				Label:      "foo",
				Attributes: []irmago.AttributeTypeIdentifier{id},
			},
		}),
	})
}

func getSigningJwt(name string, id irmago.AttributeTypeIdentifier) interface{} {
	return NewSignatureServerJwt(name, irmago.SignatureRequest{
		Message:     "test",
		MessageType: "STRING",
		DisclosureRequest: irmago.DisclosureRequest{
			Content: irmago.AttributeDisjunctionList([]*irmago.AttributeDisjunction{
				&irmago.AttributeDisjunction{
					Label:      "foo",
					Attributes: []irmago.AttributeTypeIdentifier{id},
				},
			}),
		},
	})
}

func TestSigningSession(t *testing.T) {
	id := irmago.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testsigclient"

	jwtcontents := getSigningJwt(name, id)
	sessionHelper(t, jwtcontents, "signature")
}

func TestDisclosureSession(t *testing.T) {
	id := irmago.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	name := "testsp"

	jwtcontents := getDisclosureJwt(name, id)
	sessionHelper(t, jwtcontents, "verification")
}

func sessionHelper(t *testing.T, jwtcontents interface{}, url string) {
	parseMetaStore(t)
	parseStorage(t)
	parseAndroidStorage(t)

	//url = "http://localhost:8081/irma_api_server/api/v2/" + url
	url = "https://demo.irmacard.org/tomcat/irma_api_server/api/v2/" + url

	headerbytes, err := json.Marshal(&map[string]string{"alg": "none", "typ": "JWT"})
	require.NoError(t, err)
	bodybytes, err := json.Marshal(jwtcontents)
	require.NoError(t, err)

	jwt := base64.RawStdEncoding.EncodeToString(headerbytes) + "." + base64.RawStdEncoding.EncodeToString(bodybytes) + "."
	qr, transportErr := StartSession(jwt, url)
	if transportErr != nil {
		fmt.Println(transportErr.(*TransportError).ApiErr)
	}
	require.NoError(t, transportErr)
	qr.URL = url + "/" + qr.URL

	c := make(chan *Error)
	NewSession(qr, TestHandler{t, c})

	if err := <-c; err != nil {
		t.Fatal(*err)
	}

	teardown(t)
}
