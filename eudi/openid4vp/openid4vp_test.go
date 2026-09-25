package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// jwx v4 by default keeps unparseable JWK Set entries as placeholder keys,
// where v3 rejected the whole set. Client metadata comes from the verifier,
// so we keep the strict v3 behavior; this pins it.
func Test_Jwks_UnmarshalJSON_UnparseableKeyInSet_ReturnsError(t *testing.T) {
	valid := `{"keys":[{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}`
	var jwks Jwks
	require.NoError(t, json.Unmarshal([]byte(valid), &jwks))

	withUnparseable := `{"keys":[{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},{"kty":"EC","crv":"P-256"}]}`
	require.Error(t, json.Unmarshal([]byte(withUnparseable), &jwks))
}
