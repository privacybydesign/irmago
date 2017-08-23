package protocol

import (
	"encoding/json"
	"testing"

	"time"

	"github.com/credentials/irmago"
	"github.com/stretchr/testify/require"
)

func TestTimestamp(t *testing.T) {
	mytime := Timestamp(time.Unix(1500000000, 0))
	timestruct := struct{ Time *Timestamp }{Time: &mytime}
	bytes, err := json.Marshal(timestruct)
	require.NoError(t, err)

	timestruct = struct{ Time *Timestamp }{}
	require.NoError(t, json.Unmarshal(bytes, &timestruct))
	require.Equal(t, time.Time(*timestruct.Time).Unix(), int64(1500000000))
}

func TestServiceProviderRequest(t *testing.T) {
	var sprequest ServiceProviderRequest

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

	require.NoError(t, json.Unmarshal([]byte(spjson), &sprequest))
	require.NotNil(t, sprequest.Request.Request.Content)
	require.NotEmpty(t, sprequest.Request.Request.Content)
	require.NotNil(t, sprequest.Request.Request.Content[0])
	require.NotEmpty(t, sprequest.Request.Request.Content[0])
	require.NotNil(t, sprequest.Request.Request.Content[0].Attributes)
	require.NotEmpty(t, sprequest.Request.Request.Content[0].Attributes)
	require.Equal(t, sprequest.Request.Request.Content[0].Attributes[0].Name(), "studentID")

	require.NotNil(t, sprequest.Request.Request.Content.Find(irmago.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")))
}

func TestTransport(t *testing.T) {
	transport := NewHTTPTransport("https://xkcd.com")
	obj := &struct {
		Num   int    `json:"num"`
		Img   string `json:"img"`
		Title string `json:"title"`
	}{}

	err := transport.Get("614/info.0.json", obj)
	require.NoError(t, err)
}
