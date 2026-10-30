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
