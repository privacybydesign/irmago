package vcdm

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsOpenBadgesCredential(t *testing.T) {
	require.True(t, IsOpenBadgesCredential([]string{
		"https://www.w3.org/2018/credentials#VerifiableCredential",
		OpenBadgeCredentialType,
	}))
	require.False(t, IsOpenBadgesCredential([]string{"OpenBadgeCredential"}),
		"a compact term no context defines is not the Open Badges type")
	require.False(t, IsOpenBadgesCredential([]string{"https://example.com/vocab#OpenBadgeCredential"}))
	require.False(t, IsOpenBadgesCredential(nil))
}

// Both names the Open Badges context gives the credential type expand to the
// type IsOpenBadgesCredential looks for. The term definitions are copied from
// https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json, where
// AchievementCredential's @id is the term OpenBadgeCredential.
func TestIsOpenBadgesCredential_ExpandedWithTheOpenBadgesContext(t *testing.T) {
	server, _ := contextServer(t, `{"@context": {
		"@protected": true,
		"id": "@id",
		"type": "@type",
		"OpenBadgeCredential": {"@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#OpenBadgeCredential"},
		"AchievementCredential": {"@id": "OpenBadgeCredential"}
	}}`, http.StatusOK)

	for _, name := range []string{"OpenBadgeCredential", "AchievementCredential"} {
		t.Run(name, func(t *testing.T) {
			types, err := ExpandTypes(Document{
				ContextKey: []any{ContextV2, server.URL + "/context"},
				TypeKey:    []any{TypeVerifiableCredential, name},
			}, NewContextLoader(server.Client()))
			require.NoError(t, err)
			require.True(t, IsOpenBadgesCredential(types), "expanded types: %v", types)
		})
	}
}

func TestAchievementImage(t *testing.T) {
	cases := map[string]struct {
		subject string
		want    string
		wantOK  bool
	}{
		"Image object": {
			`{"achievement": {"image": {"id": "https://example.com/badge.png", "type": "Image"}}}`,
			"https://example.com/badge.png", true,
		},
		"string": {`{"achievement": {"image": "data:image/png;base64,iVBORw0KGgo="}}`, "data:image/png;base64,iVBORw0KGgo=", true},
		"first subject with an achievement image": {
			`[{"id": "did:example:1"}, {"achievement": {"image": "https://example.com/badge.png"}}]`,
			"https://example.com/badge.png", true,
		},
		"achievement without image": {`{"achievement": {"name": "Badge"}}`, "", false},
		"achievement not an object": {`{"achievement": "https://example.com/achievements/1"}`, "", false},
		"wrong image shape":         {`{"achievement": {"image": 42}}`, "", false},
		"no achievement":            {`{"id": "did:example:1"}`, "", false},
		"subject not an object":     {`"did:example:1"`, "", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := docFromJSON(t, `{"credentialSubject": `+tc.subject+`}`).AchievementImage()
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.want, got)
		})
	}
}
