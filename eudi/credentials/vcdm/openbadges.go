package vcdm

import "slices"

// OpenBadgeCredentialType is the Open Badges 3.0 credential type as JSON-LD
// expands it with the Open Badges context. That context defines
// AchievementCredential as another name for the same type, so both compact
// terms expand to this IRI.
const OpenBadgeCredentialType = "https://purl.imsglobal.org/spec/vc/ob/vocab.html#OpenBadgeCredential"

// Open Badges 3.0 property names. An image is not a VCDM 2.0 property, but
// Open Badges gives the credential, its achievement and its issuer one.
const (
	ImageKey       = "image"
	AchievementKey = "achievement"
)

// IsOpenBadgesCredential reports whether a credential with these expanded
// types (ExpandTypes) is an Open Badges 3.0 credential. The compact term alone
// does not decide it: only the context gives a term its meaning, and another
// context could define "OpenBadgeCredential" as something else.
func IsOpenBadgesCredential(expandedTypes []string) bool {
	return slices.Contains(expandedTypes, OpenBadgeCredentialType)
}

// AchievementImage returns the `image` of the credential subject's
// `achievement` (Open Badges 3.0): the badge's picture. An Open Badges
// credential has one subject; with several, the first that has an achievement
// image gives it. See imageURI for the shapes it reads.
func (d Document) AchievementImage() (string, bool) {
	subjects, err := d.CredentialSubjects()
	if err != nil {
		return "", false
	}
	for _, subject := range subjects {
		achievement, _ := subject[AchievementKey].(map[string]any)
		if uri, ok := imageURI(achievement[ImageKey]); ok {
			return uri, true
		}
	}
	return "", false
}
