package did

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
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

func Test_Unmarshal_Document_Controller_AsString(t *testing.T) {
	jsonData := `{
		"@context": "https://www.w3.org/ns/did/v1",
		"id": "did:example:123",
		"controller": "did:example:123"
	}`

	var doc Document
	err := json.Unmarshal([]byte(jsonData), &doc)
	require.NoError(t, err)
	require.Equal(t, "did:example:123", doc.Controller)
}

func Test_Unmarshal_Document_Controller_AsArray(t *testing.T) {
	jsonData := `{
		"@context": "https://www.w3.org/ns/did/v1",
		"id": "did:example:123",
		"controller": ["did:example:123", "did:example:456"]
	}`

	var doc Document
	err := json.Unmarshal([]byte(jsonData), &doc)
	require.NoError(t, err)

	controllers, ok := doc.Controller.([]any)
	require.True(t, ok, "expected []any, got %T", doc.Controller)
	require.Equal(t, []any{"did:example:123", "did:example:456"}, controllers)
}

func Test_Unmarshal_VerificationMethod_WithPublicKeyMultibase_DecodesPublicKey(t *testing.T) {
	jsonData := `{
		"id": "did:example:123#key-1",
		"type": "Multikey",
		"controller": "did:example:123",
		"publicKeyMultibase": "z6MkeXCES4onVW4up9Qgz1KRnZsKmGufcaZxF6Zpv2w5QwUK"
	}`

	var vm VerificationMethod
	err := json.Unmarshal([]byte(jsonData), &vm)
	require.NoError(t, err)
	require.NotNil(t, vm.PublicKeyMultibase)

	require.NotNil(t, vm.PublicKey())
	var rawKey ed25519.PublicKey
	require.NoError(t, jwk.Export(*vm.PublicKey(), &rawKey))
	require.Equal(t, testEd25519PubKey, rawKey)
}

func Test_Unmarshal_VerificationMethod_WithoutPublicKeyMultibase_PublicKeyIsNil(t *testing.T) {
	jsonData := `{
		"id": "did:example:123#key-1",
		"type": "Multikey",
		"controller": "did:example:123"
	}`

	var vm VerificationMethod
	err := json.Unmarshal([]byte(jsonData), &vm)
	require.NoError(t, err)
	require.Nil(t, vm.PublicKey())
}

func Test_Unmarshal_VerificationMethod_WithPublicKeyJwk_PublicKeyReturnsJwk(t *testing.T) {
	jsonData := `{
		"id": "did:example:123#key-1",
		"type": "JsonWebKey2020",
		"controller": "did:example:123",
		"publicKeyJwk": {
			"kty": "OKP",
			"crv": "Ed25519",
			"x": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
		}
	}`

	var vm VerificationMethod
	err := json.Unmarshal([]byte(jsonData), &vm)
	require.NoError(t, err)
	require.NotNil(t, vm.PublicKey())
	require.Equal(t, vm.PublicKeyJwk, vm.PublicKey())
}

func Test_Unmarshal_VerificationMethod_BothPublicKeys_ReturnsError(t *testing.T) {
	jsonData := `{
		"id": "did:example:123#key-1",
		"type": "Multikey",
		"controller": "did:example:123",
		"publicKeyMultibase": "z6MkeXCES4onVW4up9Qgz1KRnZsKmGufcaZxF6Zpv2w5QwUK",
		"publicKeyJwk": {
			"kty": "OKP",
			"crv": "Ed25519",
			"x": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
		}
	}`

	var vm VerificationMethod
	err := json.Unmarshal([]byte(jsonData), &vm)
	require.EqualError(t, err, "publicKeyJwk, publicKeyMultibase and publicKeyBase58 are mutually exclusive")
}

func Test_Unmarshal_VerificationMethod_WithPublicKeyBase58_DecodesPublicKey(t *testing.T) {
	// publicKeyBase58 is the same as publicKeyMultibase without the leading 'z' header
	jsonData := `{
		"id": "did:example:123#key-1",
		"type": "Ed25519VerificationKey2018",
		"controller": "did:example:123",
		"publicKeyBase58": "4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw"
	}`

	var vm VerificationMethod
	err := json.Unmarshal([]byte(jsonData), &vm)
	require.NoError(t, err)
	require.NotNil(t, vm.PublicKeyBase58)

	require.NotNil(t, vm.PublicKey())
	var rawKey ed25519.PublicKey
	require.NoError(t, jwk.Export(*vm.PublicKey(), &rawKey))
	require.Equal(t, testEd25519PubKey, rawKey)
}

func Test_Unmarshal_VerificationMethod_WithPublicKeyBase58_JsonWebKey2020_DecodesPublicKey(t *testing.T) {
	// base58 of {"crv":"Ed25519","kty":"OKP","x":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"}
	jsonData := `{
		"id": "did:example:123#key-1",
		"type": "JsonWebKey2020",
		"controller": "did:example:123",
		"publicKeyBase58": "JdezH6zKGTBMUMsyfkZCVMN66PNviAhqcG4qm4QECqZZ6ct5jbp6GWTLRBgs6XU1D37BhSHkFHvrqbKPFYDRihmpQkpP8qZQgEvfLdHXqMSc"
	}`

	var vm VerificationMethod
	err := json.Unmarshal([]byte(jsonData), &vm)
	require.NoError(t, err)
	require.NotNil(t, vm.PublicKey())

	var rawKey ed25519.PublicKey
	require.NoError(t, jwk.Export(*vm.PublicKey(), &rawKey))
	require.Equal(t, testEd25519PubKey, rawKey)
}

func Test_Unmarshal_VerificationMethod_WithPublicKeyBase58AndJwk_ReturnsError(t *testing.T) {
	jsonData := `{
		"id": "did:example:123#key-1",
		"type": "Ed25519VerificationKey2018",
		"controller": "did:example:123",
		"publicKeyBase58": "4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw",
		"publicKeyJwk": {
			"kty": "OKP",
			"crv": "Ed25519",
			"x": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
		}
	}`

	var vm VerificationMethod
	err := json.Unmarshal([]byte(jsonData), &vm)
	require.EqualError(t, err, "publicKeyJwk, publicKeyMultibase and publicKeyBase58 are mutually exclusive")
}

func Test_Unmarshal_VerificationMethod_WithInvalidPublicKeyMultibase_ReturnsError(t *testing.T) {
	jsonData := `{
		"id": "did:example:123#key-1",
		"type": "Multikey",
		"controller": "did:example:123",
		"publicKeyMultibase": "zinvalid"
	}`

	var vm VerificationMethod
	err := json.Unmarshal([]byte(jsonData), &vm)
	require.ErrorContains(t, err, "failed to decode publicKeyMultibase")
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
