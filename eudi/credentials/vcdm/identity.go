package vcdm

import "strings"

// TypeIdentity builds the wallet-internal identity string for a VCDM
// credential type: the string `@context` entries followed by the `type`
// values, in document order, space-joined. Per the storage decision (#679) the
// per-format type identity of a VCDM credential is this @context+type
// composite; the cross-data-model normalization that would group it with other
// formats of the same logical credential is follow-up work.
//
// Neither URLs nor JSON-LD terms can contain spaces, so the space join is
// unambiguous.
func TypeIdentity(contexts, types []string) string {
	parts := make([]string, 0, len(contexts)+len(types))
	for _, c := range contexts {
		if c != "" {
			parts = append(parts, c)
		}
	}
	for _, t := range types {
		if t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, " ")
}

// TypeIdentity returns the composite type identity of the document (see the
// package-level TypeIdentity). Non-string `@context` entries (inline context
// objects) are skipped.
func (d Document) TypeIdentity() string {
	var contexts []string
	for _, c := range d.Contexts() {
		if s, ok := c.(string); ok {
			contexts = append(contexts, s)
		}
	}
	return TypeIdentity(contexts, d.Types())
}
