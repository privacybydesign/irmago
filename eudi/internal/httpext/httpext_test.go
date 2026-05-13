package httpext

import (
	"reflect"
	"testing"
)

func TestParseWWWAuthenticate(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    []Challenge
		wantErr bool
	}{
		{
			name:   "empty header",
			header: "",
			want:   nil,
		},
		{
			name:   "only whitespace",
			header: "   \t  ",
			want:   nil,
		},
		{
			name:   "scheme only",
			header: "Bearer",
			want:   []Challenge{{Scheme: "Bearer"}},
		},
		{
			name:   "scheme with trailing whitespace",
			header: "Bearer ",
			want:   []Challenge{{Scheme: "Bearer"}},
		},
		{
			name:   "single auth-param",
			header: `Bearer realm="example"`,
			want: []Challenge{
				{Scheme: "Bearer", Params: map[string]string{"realm": "example"}},
			},
		},
		{
			name:   "multiple auth-params",
			header: `Bearer realm="example", error="invalid_token", error_description="The access token expired"`,
			want: []Challenge{
				{
					Scheme: "Bearer",
					Params: map[string]string{
						"realm":             "example",
						"error":             "invalid_token",
						"error_description": "The access token expired",
					},
				},
			},
		},
		{
			name:   "comma inside quoted error_description is not a separator",
			header: `Bearer realm="example", error_description="Token expired, please re-authenticate", error="invalid_token"`,
			want: []Challenge{
				{
					Scheme: "Bearer",
					Params: map[string]string{
						"realm":             "example",
						"error_description": "Token expired, please re-authenticate",
						"error":             "invalid_token",
					},
				},
			},
		},
		{
			name:   "auth-param key is case-insensitive",
			header: `Bearer REALM="example", Error="invalid_token"`,
			want: []Challenge{
				{
					Scheme: "Bearer",
					Params: map[string]string{
						"realm": "example",
						"error": "invalid_token",
					},
				},
			},
		},
		{
			name:   "auth-param with token value (no quotes)",
			header: `Bearer realm=example`,
			want: []Challenge{
				{Scheme: "Bearer", Params: map[string]string{"realm": "example"}},
			},
		},
		{
			name:   "auth-param with BWS around equals",
			header: "Bearer realm\t= \t\"example\"",
			want: []Challenge{
				{Scheme: "Bearer", Params: map[string]string{"realm": "example"}},
			},
		},
		{
			name:   "token68 base64",
			header: "Bearer dXNlcjpwYXNzd29yZA==",
			want: []Challenge{
				{Scheme: "Bearer", Token68: "dXNlcjpwYXNzd29yZA=="},
			},
		},
		{
			name:   "token68 without padding",
			header: "Bearer dGVzdA",
			want: []Challenge{
				{Scheme: "Bearer", Token68: "dGVzdA"},
			},
		},
		{
			name:   "token68 base64url with plus and slash",
			header: "Bearer abc+def/ghi==",
			want: []Challenge{
				{Scheme: "Bearer", Token68: "abc+def/ghi=="},
			},
		},
		{
			name:   "two challenges comma-separated",
			header: `Bearer realm="example", Basic realm="test"`,
			want: []Challenge{
				{Scheme: "Bearer", Params: map[string]string{"realm": "example"}},
				{Scheme: "Basic", Params: map[string]string{"realm": "test"}},
			},
		},
		{
			name:   "two bare schemes",
			header: "Scheme1, Scheme2",
			want: []Challenge{
				{Scheme: "Scheme1"},
				{Scheme: "Scheme2"},
			},
		},
		{
			name:   "three challenges mixed",
			header: `Bearer realm="a", Basic realm="b", Digest realm="c"`,
			want: []Challenge{
				{Scheme: "Bearer", Params: map[string]string{"realm": "a"}},
				{Scheme: "Basic", Params: map[string]string{"realm": "b"}},
				{Scheme: "Digest", Params: map[string]string{"realm": "c"}},
			},
		},
		{
			name:   "leading comma per hash-rule",
			header: `,Bearer realm="x"`,
			want: []Challenge{
				{Scheme: "Bearer", Params: map[string]string{"realm": "x"}},
			},
		},
		{
			name:   "trailing comma per hash-rule",
			header: `Bearer realm="x",`,
			want: []Challenge{
				{Scheme: "Bearer", Params: map[string]string{"realm": "x"}},
			},
		},
		{
			name:   "consecutive commas per hash-rule",
			header: `Bearer realm="x",,, Basic realm="y"`,
			want: []Challenge{
				{Scheme: "Bearer", Params: map[string]string{"realm": "x"}},
				{Scheme: "Basic", Params: map[string]string{"realm": "y"}},
			},
		},
		{
			name:   "quoted string with escaped double-quote",
			header: `Bearer realm="test \"value\""`,
			want: []Challenge{
				{Scheme: "Bearer", Params: map[string]string{"realm": `test "value"`}},
			},
		},
		{
			name:   "quoted string with escaped backslash",
			header: `Bearer realm="back\\slash"`,
			want: []Challenge{
				{Scheme: "Bearer", Params: map[string]string{"realm": `back\slash`}},
			},
		},
		{
			name:   "quoted string with tab and space",
			header: "Bearer realm=\"hello\tworld\"",
			want: []Challenge{
				{Scheme: "Bearer", Params: map[string]string{"realm": "hello\tworld"}},
			},
		},
		{
			name:   "DPoP challenge with multiple params",
			header: `DPoP realm="example", error="use_dpop_nonce", algs="ES256"`,
			want: []Challenge{
				{
					Scheme: "DPoP",
					Params: map[string]string{
						"realm": "example",
						"error": "use_dpop_nonce",
						"algs":  "ES256",
					},
				},
			},
		},
		{
			name:   "Bearer followed by DPoP challenge",
			header: `Bearer error="insufficient_scope", DPoP realm="example"`,
			want: []Challenge{
				{Scheme: "Bearer", Params: map[string]string{"error": "insufficient_scope"}},
				{Scheme: "DPoP", Params: map[string]string{"realm": "example"}},
			},
		},
		{
			name:   "scheme with non-token68 tchar in param name",
			header: `Bearer x!y="val"`,
			want: []Challenge{
				{Scheme: "Bearer", Params: map[string]string{"x!y": "val"}},
			},
		},
		{
			name:   "bare token after scheme is token68",
			header: `Bearer realm`,
			want:   []Challenge{{Scheme: "Bearer", Token68: "realm"}},
		},
		{
			name:    "invalid character at start of param list",
			header:  `Bearer =value`,
			wantErr: true,
		},
		{
			name:    "unterminated quoted string",
			header:  `Bearer realm="unterminated`,
			wantErr: true,
		},
		{
			name:    "invalid character in quoted string",
			header:  "Bearer realm=\"bad\x00char\"",
			wantErr: true,
		},
		{
			name:    "invalid character directly after scheme",
			header:  "Bearer\x00",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseWWWAuthenticate(tt.header)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseWWWAuthenticate(%q) error = %v, wantErr %v", tt.header, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseWWWAuthenticate(%q)\n got  %+v\n want %+v", tt.header, got, tt.want)
			}
		})
	}
}
