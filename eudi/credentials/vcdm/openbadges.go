package vcdm

import "slices"

// OpenBadgeCredentialType is the expanded Open Badges 3.0 credential type.
// AchievementCredential expands to it too.
const OpenBadgeCredentialType = "https://purl.imsglobal.org/spec/vc/ob/vocab.html#OpenBadgeCredential"

// Open Badges 3.0 property names.
const (
	ImageKey       = "image"
	AchievementKey = "achievement"
)

// IsOpenBadgesCredential reports whether a credential with these expanded
// types is an Open Badges 3.0 credential. The compact term alone does not
// count, since another context could give it another meaning.
func IsOpenBadgesCredential(expandedTypes []string) bool {
	return slices.Contains(expandedTypes, OpenBadgeCredentialType)
}

// AchievementImage returns the image of the subject's `achievement`: the
// badge's picture. With several subjects, the first that has one.
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
