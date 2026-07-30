package oauth2

import (
	"encoding/json"
	"testing"
)

func TestAuthorizationServerMetadata_SupportsGrantType(t *testing.T) {
	tests := []struct {
		name      string
		metadata  string
		grantType string
		want      bool
	}{
		{
			name:      "listed grant type is supported",
			metadata:  `{"grant_types_supported":["authorization_code","refresh_token"]}`,
			grantType: GrantTypeAuthorizationCode,
			want:      true,
		},
		{
			name:      "unlisted grant type is not supported",
			metadata:  `{"grant_types_supported":["refresh_token"]}`,
			grantType: GrantTypeAuthorizationCode,
			want:      false,
		},
		{
			// RFC 8414 § 2: grant_types_supported is OPTIONAL and defaults to
			// ["authorization_code", "implicit"].
			name:      "omitted grant_types_supported defaults to authorization_code",
			metadata:  `{}`,
			grantType: GrantTypeAuthorizationCode,
			want:      true,
		},
		{
			name:      "omitted grant_types_supported does not default to pre-authorized code",
			metadata:  `{}`,
			grantType: GrantTypePreAuthorizedCode,
			want:      false,
		},
		{
			// An explicitly empty list is not the same as an omitted one.
			name:      "empty grant_types_supported supports nothing",
			metadata:  `{"grant_types_supported":[]}`,
			grantType: GrantTypeAuthorizationCode,
			want:      false,
		},
		{
			name:      "pre-authorized code grant type is matched on its URN",
			metadata:  `{"grant_types_supported":["urn:ietf:params:oauth:grant-type:pre-authorized_code"]}`,
			grantType: GrantTypePreAuthorizedCode,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var asMetadata AuthorizationServerMetadata
			if err := json.Unmarshal([]byte(tt.metadata), &asMetadata); err != nil {
				t.Fatalf("failed to unmarshal test metadata: %v", err)
			}

			if got := asMetadata.SupportsGrantType(tt.grantType); got != tt.want {
				t.Errorf("SupportsGrantType(%q) = %v, want %v", tt.grantType, got, tt.want)
			}
		})
	}
}
