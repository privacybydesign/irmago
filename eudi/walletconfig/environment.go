package walletconfig

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
)

// Environment is one of the worlds a wallet can live in — production or
// staging — as a wallet build knows it. Every build compiles in every
// environment; the active one is switched at runtime, and the switch swaps the
// whole descriptor at once, so anchors of two environments are never mixed.
type Environment struct {
	// Name is what the config's `environment` field must say. It is also the key
	// a Store files this environment's config under.
	Name string

	// ConfigURL is where the current signed config for this environment is
	// published. Versioned by schema major: a breaking change gets a new path.
	ConfigURL string

	// SigningRoot is the one certificate a config's `x5c` must chain to. The only
	// compiled-in trust material; everything else comes from the config.
	SigningRoot *x509.Certificate

	// BundledConfigPath is the signed config shipped with the release, for an
	// offline first run. Verified exactly like a download; may be empty.
	BundledConfigPath string
}

// ValidateEnvironments reports what would make a set of environments unusable
// as a Manager's world: no environments, a duplicate or empty name, a missing
// root, or a URL that is not absolute.
func ValidateEnvironments(environments []Environment) error {
	if len(environments) == 0 {
		return errors.New("no environments configured")
	}
	var errs []error
	names := map[string]bool{}
	for i, env := range environments {
		at := fmt.Sprintf("environment %d (%q)", i, env.Name)
		switch {
		case env.Name == "":
			errs = append(errs, fmt.Errorf("environment %d: Name is empty", i))
		case names[env.Name]:
			errs = append(errs, fmt.Errorf("%s: Name is used by another environment", at))
		}
		names[env.Name] = true
		if env.SigningRoot == nil {
			errs = append(errs, fmt.Errorf("%s: SigningRoot is nil", at))
		}
		if parsed, err := url.Parse(env.ConfigURL); err != nil || parsed.Scheme == "" || parsed.Host == "" {
			errs = append(errs, fmt.Errorf("%s: ConfigURL %q is not an absolute URL", at, env.ConfigURL))
		}
	}
	return errors.Join(errs...)
}
