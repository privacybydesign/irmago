package eudi

import (
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
)

// LoadLogoImage looks up a previously-saved logo by its logical key and wraps
// it as a base64-encoded clientmodels.Image. Returns nil when the key is empty,
// the manager is unavailable, or no logo is cached.
func LoadLogoImage(manager filesystem.LogoManager, key string) *clientmodels.Image {
	if key == "" || manager == nil {
		return nil
	}
	exists, err := manager.Exists(key)
	if err != nil || !exists {
		return nil
	}
	data, mimeType, err := manager.Get(key)
	if err != nil {
		return nil
	}
	return clientmodels.NewImage(data, mimeType)
}
