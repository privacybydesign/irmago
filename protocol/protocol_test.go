package protocol

import (
	"encoding/json"
	"testing"

	"github.com/credentials/irmago"
	"github.com/stretchr/testify/require"
)

func TestServiceProvider(t *testing.T) {
	var spjwt ServiceProviderJwt

	var spjson = `{
		"sprequest": {
			"validity": 60,
			"timeout": 60,
			"request": {
				"content": [
					{
						"label": "ID",
						"attributes": ["irma-demo.RU.studentCard.studentID"]
					}
				]
			}
		}
	}`

	require.NoError(t, json.Unmarshal([]byte(spjson), &spjwt))
	require.NotNil(t, spjwt.Request.Request.Content)
	require.NotEmpty(t, spjwt.Request.Request.Content)
	require.NotNil(t, spjwt.Request.Request.Content[0])
	require.NotEmpty(t, spjwt.Request.Request.Content[0])
	require.NotNil(t, spjwt.Request.Request.Content[0].Attributes)
	require.NotEmpty(t, spjwt.Request.Request.Content[0].Attributes)
	require.Equal(t, spjwt.Request.Request.Content[0].Attributes[0].Name(), "studentID")

	require.NotNil(t, spjwt.Request.Request.Content.Find(irmago.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")))
}

func TestTransport(t *testing.T) {
	transport := NewHTTPTransport("https://xkcd.com")
	obj := &struct {
		Num   int    `json:"num"`
		Img   string `json:"img"`
		Title string `json:"title"`
	}{}

	err := transport.Get("614/info.0.json", obj)
	if err != nil { // require.NoError() does not work because of the type of err
		t.Fatalf("%+v\n", err)
	}
}
