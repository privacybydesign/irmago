package vcdm

import "slices"

// OpenBadgeCredentialType is the Open Badges 3.0 credential type as JSON-LD
// expands it with the Open Badges context. That context defines
// AchievementCredential as another name for the same type, so both compact
// terms expand to this IRI.
const OpenBadgeCredentialType = "https://purl.imsglobal.org/spec/vc/ob/vocab.html#OpenBadgeCredential"

// IsOpenBadgesCredential reports whether a credential with these expanded
// types (ExpandTypes) is an Open Badges 3.0 credential. The compact term alone
// does not decide it: only the context gives a term its meaning, and another
// context could define "OpenBadgeCredential" as something else.
func IsOpenBadgesCredential(expandedTypes []string) bool {
	return slices.Contains(expandedTypes, OpenBadgeCredentialType)
}
