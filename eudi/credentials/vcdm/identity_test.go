package vcdm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTypeIdentity_JoinsContextsAndTypes(t *testing.T) {
	require.Equal(t,
		"https://www.w3.org/ns/credentials/v2 https://example.org/ctx VerifiableCredential ExampleCredential",
		TypeIdentity(
			[]string{ContextV2, "https://example.org/ctx"},
			[]string{TypeVerifiableCredential, "ExampleCredential"},
		),
	)
}

func TestTypeIdentity_SkipsEmptyEntries(t *testing.T) {
	require.Equal(t,
		"VerifiableCredential",
		TypeIdentity(nil, []string{"", TypeVerifiableCredential}),
	)
}

func TestDocumentTypeIdentity_SkipsInlineContextObjects(t *testing.T) {
	doc := Document{
		ContextKey: []any{ContextV2, map[string]any{"ex": "https://example.org/vocab#"}},
		TypeKey:    []any{TypeVerifiableCredential, "ExampleCredential"},
	}
	require.Equal(t,
		"https://www.w3.org/ns/credentials/v2 VerifiableCredential ExampleCredential",
		doc.TypeIdentity(),
	)
}

func TestDocumentTypeIdentity_IsDeterministicAcrossDocuments(t *testing.T) {
	a := Document{
		ContextKey: []any{ContextV2},
		TypeKey:    []any{TypeVerifiableCredential, "ExampleCredential"},
	}
	b := Document{
		ContextKey: []any{ContextV2},
		TypeKey:    []any{TypeVerifiableCredential, "ExampleCredential"},
	}
	require.Equal(t, a.TypeIdentity(), b.TypeIdentity())
}
