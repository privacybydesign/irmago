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

func TestAuthorizationServerMetadata_UnmarshalJSON(t *testing.T) {
	const jwks = `{"keys":[{"kty":"EC","crv":"P-256","kid":"k1",` +
		`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
		`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`

	t.Run("jwks is parsed alongside the other members", func(t *testing.T) {
		metadata := `{"issuer":"https://as.example.com","token_endpoint":"https://as.example.com/token","jwks":` + jwks + `}`

		var asMetadata AuthorizationServerMetadata
		if err := json.Unmarshal([]byte(metadata), &asMetadata); err != nil {
			t.Fatalf("failed to unmarshal test metadata: %v", err)
		}

		if asMetadata.Issuer != "https://as.example.com" {
			t.Errorf("Issuer = %q, want %q", asMetadata.Issuer, "https://as.example.com")
		}
		if asMetadata.TokenEndpoint != "https://as.example.com/token" {
			t.Errorf("TokenEndpoint = %q, want %q", asMetadata.TokenEndpoint, "https://as.example.com/token")
		}
		if asMetadata.Jwks == nil {
			t.Fatal("Jwks = nil, want a key set")
		}
		if _, ok := asMetadata.Jwks.LookupKeyID("k1"); !ok {
			t.Errorf("key %q missing from Jwks", "k1")
		}
	})

	t.Run("marshalled metadata round trips", func(t *testing.T) {
		metadata := `{"issuer":"https://as.example.com","jwks":` + jwks + `}`

		var asMetadata AuthorizationServerMetadata
		if err := json.Unmarshal([]byte(metadata), &asMetadata); err != nil {
			t.Fatalf("failed to unmarshal test metadata: %v", err)
		}

		marshalled, err := json.Marshal(&asMetadata)
		if err != nil {
			t.Fatalf("failed to marshal metadata: %v", err)
		}

		var roundTripped AuthorizationServerMetadata
		if err := json.Unmarshal(marshalled, &roundTripped); err != nil {
			t.Fatalf("failed to unmarshal marshalled metadata %s: %v", marshalled, err)
		}
		if roundTripped.Jwks == nil {
			t.Fatalf("Jwks lost in round trip through %s", marshalled)
		}
	})

	t.Run("absent and null jwks leave the key set nil", func(t *testing.T) {
		for _, metadata := range []string{`{"issuer":"x"}`, `{"issuer":"x","jwks":null}`} {
			var asMetadata AuthorizationServerMetadata
			if err := json.Unmarshal([]byte(metadata), &asMetadata); err != nil {
				t.Fatalf("failed to unmarshal %s: %v", metadata, err)
			}
			if asMetadata.Jwks != nil {
				t.Errorf("Jwks = %v for %s, want nil", asMetadata.Jwks, metadata)
			}
		}
	})

	t.Run("malformed jwks is an error", func(t *testing.T) {
		var asMetadata AuthorizationServerMetadata
		if err := json.Unmarshal([]byte(`{"issuer":"x","jwks":"not-a-key-set"}`), &asMetadata); err == nil {
			t.Error("expected an error for a malformed jwks member")
		}
	})
}
