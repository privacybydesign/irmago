package walletconfig

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// Environment is one of the worlds a wallet can live in — production or
// staging — as a wallet build knows it. Every build compiles in every
// environment; the active one is switched at runtime, and the switch swaps the
// whole descriptor at once, so anchors of two environments are never mixed.
type Environment struct {
	// Name is what the config's `environment` field must say.
	Name string

	// ConfigID is what the config's `id` field must say, and the key a Store
	// files this environment's config under. Required for a published
	// environment.
	ConfigID string

	// ConfigURL is where the current signed config for this environment is
	// published. Versioned by schema major: a breaking change gets a new path.
	ConfigURL string

	// SigningRoot is the one certificate a config's `x5c` must chain to. The only
	// compiled-in trust material; everything else comes from the config.
	SigningRoot *x509.Certificate

	// BundledConfigPath is the signed config shipped with the release, for an
	// offline first run. Verified exactly like a download; may be empty.
	BundledConfigPath string

	// BuiltinEntities are trusted entities compiled into the build for this
	// environment, always in force next to whatever the signed config says.
	//
	// Transitional: the home of the anchors that were PEM constants until the
	// signed config carries them, at which point this field is deleted. An
	// environment with built-in entities and no ConfigURL is unpublished — it
	// fetches nothing and trusts only what is compiled in.
	BuiltinEntities []TrustedEntity
}

// IsPublished reports whether a signed config exists for this environment: a
// URL to fetch it from and a root to verify it against. An unpublished
// environment runs on its built-in entities alone.
func (e Environment) IsPublished() bool {
	return e.ConfigURL != "" || e.SigningRoot != nil
}

// ValidateEnvironments reports what would make a set of environments unusable
// as a Manager's world: no environments, a duplicate or empty name, a published
// environment missing its config id or root or with a URL that is not absolute,
// a config id shared by two environments (they would overwrite each other in
// the store), a bundled config on an unpublished environment (nothing could
// verify it), or a built-in entity that does not validate.
func ValidateEnvironments(environments []Environment) error {
	if len(environments) == 0 {
		return errors.New("no environments configured")
	}
	var errs []error
	names := map[string]bool{}
	configIDs := map[string]bool{}
	for i, env := range environments {
		at := fmt.Sprintf("environment %d (%q)", i, env.Name)
		switch {
		case env.Name == "":
			errs = append(errs, fmt.Errorf("environment %d: Name is empty", i))
		case names[env.Name]:
			errs = append(errs, fmt.Errorf("%s: Name is used by another environment", at))
		}
		names[env.Name] = true

		if env.IsPublished() {
			switch {
			case env.ConfigID == "":
				errs = append(errs, fmt.Errorf("%s: ConfigID is empty", at))
			case configIDs[env.ConfigID]:
				errs = append(errs, fmt.Errorf("%s: ConfigID %q is used by another environment", at, env.ConfigID))
			}
			configIDs[env.ConfigID] = true
			if env.SigningRoot == nil {
				errs = append(errs, fmt.Errorf("%s: SigningRoot is nil", at))
			}
			if parsed, err := url.Parse(env.ConfigURL); err != nil || parsed.Scheme == "" || parsed.Host == "" {
				errs = append(errs, fmt.Errorf("%s: ConfigURL %q is not an absolute URL", at, env.ConfigURL))
			}
		} else if env.BundledConfigPath != "" {
			errs = append(errs, fmt.Errorf("%s: BundledConfigPath is set but there is no SigningRoot to verify it against", at))
		}

		builtin := Config{
			SchemaVersion:   fmt.Sprintf("%d.0", SupportedSchemaMajor),
			ID:              "builtin-" + env.Name,
			Environment:     env.Name,
			Version:         1,
			IssuedAt:        NewUnixTime(time.Unix(1, 0)),
			NextUpdate:      NewUnixTime(time.Unix(2, 0)),
			Policy:          DefaultPolicy(),
			TrustedEntities: env.BuiltinEntities,
		}
		if err := builtin.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: built-in entities: %w", at, err))
		}
	}
	return errors.Join(errs...)
}
