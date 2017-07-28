package protocol

import (
	"encoding/json"
	"testing"

	"time"

	"github.com/credentials/irmago"
	"github.com/stretchr/testify/require"
)

func TestAttributeDisjunctionMarshaling(t *testing.T) {
	disjunction := AttributeDisjunction{}

	var _ json.Unmarshaler = &disjunction
	var _ json.Marshaler = &disjunction

	id := irmago.NewAttributeIdentifier("MijnOverheid.ageLower.over18")

	attrsjson := `
	{
		"label": "Over 18",
		"attributes": {
			"MijnOverheid.ageLower.over18": "yes",
			"Thalia.age.over18": "Yes"
		}
	}`
	require.NoError(t, json.Unmarshal([]byte(attrsjson), &disjunction))
	require.True(t, disjunction.HasValues())
	require.Contains(t, disjunction.Attributes, id)
	require.Contains(t, disjunction.Values, id)
	require.Equal(t, disjunction.Values[id], "yes")

	disjunction = AttributeDisjunction{}
	attrsjson = `
	{
		"label": "Over 18",
		"attributes": [
			"MijnOverheid.ageLower.over18",
			"Thalia.age.over18"
		]
	}`
	require.NoError(t, json.Unmarshal([]byte(attrsjson), &disjunction))
	require.False(t, disjunction.HasValues())
	require.Contains(t, disjunction.Attributes, id)

	require.True(t, disjunction.MatchesStore())

	require.False(t, disjunction.Satisfied())
	disjunction.selected = &disjunction.Attributes[0]
	require.True(t, disjunction.Satisfied())
}

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

	require.NotNil(t, sprequest.Request.Request.Content.Find(irmago.NewAttributeIdentifier("irma-demo.RU.studentCard.studentID")))
}
