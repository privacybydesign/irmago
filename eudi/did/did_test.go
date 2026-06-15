package did

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Unmarshal_VerificationMethod_Success(t *testing.T) {
	jsonData := `{
		"id": "did:example:123#key-1",
		"type": "JsonWebKey2020",
		"controller": "did:example:123",
		"publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256",
			"kid": "0256fe6c7e79fbe457cff176e8df7acbd4183086604d54f84592536076d67d5bd5",
			"use": "sig",
			"key_ops": [
			"verify"
			],
			"alg": "ES256",
			"x": "Vv5sfnn75FfP8Xbo33rL1BgwhmBNVPhFklNgdtZ9W9U",
			"y": "cMvoWnMV3LgfvDan1eimpZHRJ1mGXygY5I-HTSpgjzw"
		}
	}`

	var vm VerificationMethod
	err := json.Unmarshal([]byte(jsonData), &vm)
	require.NoError(t, err)
	require.Equal(t, "did:example:123#key-1", vm.ID)
	require.Equal(t, VerificationMethodType_JsonWebKey2020, vm.Type)
	require.Equal(t, "did:example:123", vm.Controller)
	require.NotNil(t, vm.PublicKeyJwk)
}
