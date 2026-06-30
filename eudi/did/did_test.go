package did

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Unmarshal_Document_VerificationRefs_AsStrings(t *testing.T) {
	jsonData := `{
		"@context": "https://www.w3.org/ns/did/v1",
		"id": "did:example:123",
		"authentication":       ["did:example:123#key-1", "did:example:123#key-2"],
		"assertionMethod":      ["did:example:123#key-3"],
		"keyAgreement":         ["did:example:123#key-4"],
		"capabilityInvocation": ["did:example:123#key-5"],
		"capabilityDelegation": ["did:example:123#key-6"]
	}`

	var doc Document
	err := json.Unmarshal([]byte(jsonData), &doc)
	require.NoError(t, err)

	require.Equal(t, []VerificationRef{"did:example:123#key-1", "did:example:123#key-2"}, doc.Authentication)
	require.Equal(t, []VerificationRef{"did:example:123#key-3"}, doc.AssertionMethod)
	require.Equal(t, []VerificationRef{"did:example:123#key-4"}, doc.KeyAgreement)
	require.Equal(t, []VerificationRef{"did:example:123#key-5"}, doc.CapabilityInvocation)
	require.Equal(t, []VerificationRef{"did:example:123#key-6"}, doc.CapabilityDelegation)
}

func Test_Unmarshal_Document_VerificationRefs_AsEmbeddedMethods(t *testing.T) {
	jsonData := `{
		"@context": "https://www.w3.org/ns/did/v1",
		"id": "did:example:123",
		"authentication": [{
			"id": "did:example:123#key-1",
			"type": "Multikey",
			"controller": "did:example:123"
		}],
		"assertionMethod": [{
			"id": "did:example:123#key-2",
			"type": "Multikey",
			"controller": "did:example:123"
		}],
		"keyAgreement": [{
			"id": "did:example:123#key-3",
			"type": "JsonWebKey2020",
			"controller": "did:example:123"
		}],
		"capabilityInvocation": [{
			"id": "did:example:123#key-4",
			"type": "Multikey",
			"controller": "did:example:123"
		}],
		"capabilityDelegation": [{
			"id": "did:example:123#key-5",
			"type": "Multikey",
			"controller": "did:example:123"
		}]
	}`

	var doc Document
	err := json.Unmarshal([]byte(jsonData), &doc)
	require.NoError(t, err)

	assertEmbeddedVM := func(refs []VerificationRef, id string, typ VerificationMethodType) {
		t.Helper()
		require.Len(t, refs, 1)
		vm, ok := refs[0].(VerificationMethod)
		require.True(t, ok, "expected VerificationMethod, got %T", refs[0])
		require.Equal(t, id, vm.ID)
		require.Equal(t, typ, vm.Type)
		require.Equal(t, "did:example:123", vm.Controller)
	}

	assertEmbeddedVM(doc.Authentication, "did:example:123#key-1", VerificationMethodType_Multikey)
	assertEmbeddedVM(doc.AssertionMethod, "did:example:123#key-2", VerificationMethodType_Multikey)
	assertEmbeddedVM(doc.KeyAgreement, "did:example:123#key-3", VerificationMethodType_JsonWebKey2020)
	assertEmbeddedVM(doc.CapabilityInvocation, "did:example:123#key-4", VerificationMethodType_Multikey)
	assertEmbeddedVM(doc.CapabilityDelegation, "did:example:123#key-5", VerificationMethodType_Multikey)
}

func Test_Unmarshal_Document_VerificationRefs_Mixed(t *testing.T) {
	jsonData := `{
		"@context": "https://www.w3.org/ns/did/v1",
		"id": "did:example:123",
		"authentication": [
			"did:example:123#key-1",
			{
				"id": "did:example:123#key-2",
				"type": "Multikey",
				"controller": "did:example:123"
			}
		]
	}`

	var doc Document
	err := json.Unmarshal([]byte(jsonData), &doc)
	require.NoError(t, err)

	require.Len(t, doc.Authentication, 2)
	ref, ok := doc.Authentication[0].(string)
	require.True(t, ok)
	require.Equal(t, "did:example:123#key-1", ref)

	vm, ok := doc.Authentication[1].(VerificationMethod)
	require.True(t, ok)
	require.Equal(t, "did:example:123#key-2", vm.ID)
}

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
