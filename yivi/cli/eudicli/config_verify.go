package eudicli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/spf13/cobra"
)

var configVerifyCmd = &cobra.Command{
	Use:   "verify [config.jws]",
	Short: "Re-check a signed wallet configuration, and optionally against the published one",
	Long: `Re-check a signed wallet configuration with the wallet's own verifier: the
headers, the chain to --root, the signature, and the payload.

The environment and config id the document must declare normally come from
--environment and --id, as the wallet has them compiled in. Without them they
are read off the document itself, which still checks signature, chain and
payload but lets a config for one environment pass as the other's; a release
gate should pass both.

With --against, the currently published config is fetched and this document
compared to it: it must be a later issue — a higher version, or the same
version issued later — or the wallet would refuse it as a rollback. Give
--against alone, without a file, to verify the published config itself.

A document past its grace period fails: it is genuine, but publishing it would
turn every wallet's list-derived trust off.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rootPath, _ := cmd.Flags().GetString("root")
		environment, _ := cmd.Flags().GetString("environment")
		configID, _ := cmd.Flags().GetString("id")
		against, _ := cmd.Flags().GetString("against")
		atFlag, _ := cmd.Flags().GetString("at")
		asJSON, _ := cmd.Flags().GetBool("json")

		if len(args) == 0 && against == "" {
			return fmt.Errorf("give a signed config file, --against, or both")
		}
		if rootPath == "" {
			return fmt.Errorf("--root is required: the root the wallet pins for this environment")
		}
		root, err := readCertificate(rootPath)
		if err != nil {
			return err
		}
		now := time.Now()
		if atFlag != "" {
			if now, err = time.Parse(time.RFC3339, atFlag); err != nil {
				return fmt.Errorf("invalid --at: %w", err)
			}
		}

		var signed []byte
		if len(args) == 1 {
			if signed, err = os.ReadFile(args[0]); err != nil {
				return err
			}
		} else {
			// Through the wallet's own fetcher, so the gate reads the published
			// config under the same cap, timeout and status rules.
			if signed, err = walletconfig.Fetch(cmd.Context(), nil, against); err != nil {
				return fmt.Errorf("fetch the published config at %s: %w", against, err)
			}
			against = ""
		}

		env := walletconfig.Environment{Name: environment, ConfigID: configID, SigningRoot: root}
		if environment == "" || configID == "" {
			claimed, err := claimedIdentity(signed)
			if err != nil {
				return err
			}
			if environment == "" {
				env.Name = claimed.Environment
			}
			if configID == "" {
				env.ConfigID = claimed.ID
			}
			Logger.Warnf("no --environment and --id given: taking %q and %q from the document itself, which a release gate should not",
				env.Name, env.ConfigID)
		}

		verified, err := walletconfig.Verify(signed, env, now)
		if err != nil {
			return err
		}
		config := verified.Config
		Logger.Infof("verifies: %s for %s, version %d, %d entities, signed by %q",
			config.ID, config.Environment, config.Version, len(config.TrustedEntities), verified.Signer.Subject.CommonName)
		Logger.Infof("issued %s, next update %s, grace %s: %s at %s",
			config.IssuedAt.Format(time.RFC3339), config.NextUpdate.Format(time.RFC3339), config.GracePeriod(),
			config.FreshnessAt(now), now.UTC().Format(time.RFC3339))

		if asJSON {
			raw, err := configJSON(config)
			if err != nil {
				return err
			}
			if _, err := cmd.OutOrStdout().Write(raw); err != nil {
				return err
			}
		}

		switch config.FreshnessAt(now) {
		case walletconfig.Expired:
			return fmt.Errorf("this config is past its grace period (next update was %s)", config.NextUpdate.Format(time.RFC3339))
		case walletconfig.Stale:
			Logger.Warn("this config is past its next update; wallets holding it are fetching eagerly")
		}

		if against == "" {
			return nil
		}
		return compareToPublished(cmd.Context(), against, env, now, config)
	},
}

func init() {
	configCmd.AddCommand(configVerifyCmd)

	configVerifyCmd.Flags().String("root", "", "PEM root the wallet pins for this environment (required)")
	configVerifyCmd.Flags().String("environment", "", "environment the config must declare (default: read off the document)")
	configVerifyCmd.Flags().String("id", "", "config id the config must declare (default: read off the document)")
	configVerifyCmd.Flags().String("against", "",
		"URL of the currently published config; fails unless this document is a later issue")
	configVerifyCmd.Flags().String("at", "", "RFC 3339 moment to verify at (default now)")
	configVerifyCmd.Flags().Bool("json", false, "print the verified payload as JSON")
}

// claimedIdentity reads the environment and id off a signed document without
// verifying it, for the case where the caller did not say which to expect.
func claimedIdentity(signed []byte) (*walletconfig.Config, error) {
	message, err := jws.Parse(signed)
	if err != nil {
		return nil, fmt.Errorf("parse the signed config: %w", err)
	}
	var config walletconfig.Config
	if err := json.Unmarshal(message.Payload(), &config); err != nil {
		return nil, fmt.Errorf("decode the payload: %w", err)
	}
	return &config, nil
}

// compareToPublished refuses a document the wallet would not adopt over the
// published one.
func compareToPublished(ctx context.Context, url string, env walletconfig.Environment, now time.Time, candidate *walletconfig.Config) error {
	published, err := walletconfig.Fetch(ctx, nil, url)
	if err != nil {
		// A first publish and an outage look alike here, so this reports rather
		// than passing.
		return fmt.Errorf("fetch the published config at %s: %w", url, err)
	}
	live, err := walletconfig.Verify(published, env, now)
	if err != nil {
		return fmt.Errorf("the published config does not verify: %w", err)
	}

	switch {
	case candidate.Version > live.Config.Version:
		Logger.Infof("advances the published config (version %d -> %d)", live.Config.Version, candidate.Version)
	case candidate.Version == live.Config.Version && candidate.IssuedAt.After(live.Config.IssuedAt.Time):
		Logger.Infof("re-issues the published version %d (issued %s -> %s)", candidate.Version,
			live.Config.IssuedAt.Format(time.RFC3339), candidate.IssuedAt.Format(time.RFC3339))
	default:
		return fmt.Errorf("version %d issued %s does not advance the published version %d issued %s: build with --version %d",
			candidate.Version, candidate.IssuedAt.Format(time.RFC3339),
			live.Config.Version, live.Config.IssuedAt.Format(time.RFC3339), live.Config.Version+1)
	}
	return nil
}
