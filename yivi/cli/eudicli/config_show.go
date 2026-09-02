package eudicli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/spf13/cobra"
)

var configShowCmd = &cobra.Command{
	Use:   "show <config.json|config.jws>",
	Short: "Print what a wallet configuration says, without verifying it",
	Long: `Print what a wallet configuration says: its identity, freshness window, policy
and trusted entities. Takes the unsigned payload 'build' writes or the signed
document 'sign' writes.

Nothing is verified. A signed document is decoded, not checked, so this shows
what a file claims and never whether the wallet would accept it; that is
'verify'. With --json the payload is printed as 'build' writes it, so the two
can be diffed.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		asJSON, _ := cmd.Flags().GetBool("json")

		raw, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		config, signed, err := decodeConfigFile(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", args[0], err)
		}

		if asJSON {
			rendered, err := configJSON(config)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(rendered)
			return err
		}
		return printConfigSummary(cmd.OutOrStdout(), config, signed)
	},
}

func init() {
	configCmd.AddCommand(configShowCmd)

	configShowCmd.Flags().Bool("json", false, "print the payload as JSON, as 'build' writes it")
}

// decodeConfigFile reads a signed or unsigned config. A signed one is decoded
// without verification; signed reports which it was.
func decodeConfigFile(raw []byte) (config *walletconfig.Config, signed bool, err error) {
	config = &walletconfig.Config{}
	if strings.Count(strings.TrimSpace(string(raw)), ".") == 2 && !strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
		message, err := jws.Parse(raw)
		if err != nil {
			return nil, false, fmt.Errorf("parse the signed config: %w", err)
		}
		if err := json.Unmarshal(message.Payload(), config); err != nil {
			return nil, false, fmt.Errorf("decode the payload: %w", err)
		}
		return config, true, nil
	}
	if err := json.Unmarshal(raw, config); err != nil {
		return nil, false, fmt.Errorf("decode the config: %w", err)
	}
	return config, false, nil
}

func printConfigSummary(w io.Writer, config *walletconfig.Config, signed bool) error {
	if signed {
		fmt.Fprintln(w, "UNVERIFIED: this is what the signed document claims; run 'verify' to check it")
	}
	fmt.Fprintf(w, "id:                %s\n", config.ID)
	fmt.Fprintf(w, "environment:       %s\n", config.Environment)
	fmt.Fprintf(w, "schema version:    %s\n", config.SchemaVersion)
	fmt.Fprintf(w, "version:           %d\n", config.Version)
	fmt.Fprintf(w, "issued at:         %s\n", config.IssuedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "next update:       %s\n", config.NextUpdate.Format(time.RFC3339))
	fmt.Fprintf(w, "grace period:      %s\n", config.GracePeriod())
	fmt.Fprintf(w, "minimum app build: %d\n", config.MinimumAppBuild)
	fmt.Fprintf(w, "policy:            issuance >= %s, disclosure >= %s\n",
		config.Policy.MinimumTrustLevel.Issuance, config.Policy.MinimumTrustLevel.Disclosure)
	fmt.Fprintf(w, "trusted entities:  %d\n", len(config.TrustedEntities))
	for i := range config.TrustedEntities {
		entity := &config.TrustedEntities[i]
		roles := make([]string, len(entity.Roles))
		for j, role := range entity.Roles {
			roles[j] = string(role)
		}
		fmt.Fprintf(w, "  %s (%s): %s, %s\n", entity.ID, entity.Name["en"], strings.Join(roles, "+"), entity.TrustLevel)
		for j := range entity.Handles {
			fmt.Fprintf(w, "    %s\n", describeHandle(&entity.Handles[j]))
		}
		if entity.Constraints != nil {
			if entity.Constraints.Issuance != nil {
				fmt.Fprintf(w, "    may issue: %s\n", strings.Join(entity.Constraints.Issuance.AllowedCredentials, ", "))
			}
			if entity.Constraints.Disclosure != nil {
				for _, query := range entity.Constraints.Disclosure.AllowedQueries {
					attributes := "any attribute"
					if len(query.Attributes) > 0 {
						attributes = strings.Join(query.Attributes, ", ")
					}
					fmt.Fprintf(w, "    may request: %s (%s)\n", query.Credential, attributes)
				}
			}
		}
	}
	fmt.Fprintf(w, "credential catalog: %d\n", len(config.CredentialCatalog))
	for i := range config.CredentialCatalog {
		entry := &config.CredentialCatalog[i]
		flags := ""
		if entry.InStore {
			flags = ", in store"
		}
		fmt.Fprintf(w, "  %s (%d offering(s)%s)\n", entry.VCT, len(entry.Offerings), flags)
		if entry.VCTMetadataURL != "" {
			fmt.Fprintf(w, "    metadata: %s\n", entry.VCTMetadataURL)
		}
		for _, offering := range entry.Offerings {
			line := "    issue at " + offering.IssuanceURLs[walletconfig.DefaultIssuanceURLKey]
			if extra := len(offering.IssuanceURLs) - 1; extra > 0 {
				line += fmt.Sprintf(" (+%d language(s))", extra)
			}
			if offering.IssuerMetadataURL != "" {
				line += ", issuer " + offering.IssuerMetadataURL
			}
			fmt.Fprintln(w, line)
		}
	}
	return nil
}

func describeHandle(handle *walletconfig.Handle) string {
	switch handle.Type {
	case walletconfig.HandleTypeX509CA:
		description := "x509_ca"
		if handle.RootCertificate != nil && handle.RootCertificate.Certificate != nil {
			description += " root " + strconv(handle.RootCertificate.Subject.CommonName)
		}
		if len(handle.Intermediates) > 0 {
			names := make([]string, 0, len(handle.Intermediates))
			for _, intermediate := range handle.Intermediates {
				if intermediate.Certificate != nil {
					names = append(names, strconv(intermediate.Subject.CommonName))
				}
			}
			description += ", intermediates " + strings.Join(names, ", ")
		}
		if len(handle.CRLDistributionPoints) > 0 {
			description += fmt.Sprintf(", %d CRL distribution point(s)", len(handle.CRLDistributionPoints))
		}
		return description
	case walletconfig.HandleTypeX509Cert:
		if handle.Certificate != nil && handle.Certificate.Certificate != nil {
			return "x509_cert " + strconv(handle.Certificate.Subject.CommonName) + " serial " + handle.Certificate.SerialNumber.String()
		}
		return "x509_cert"
	case walletconfig.HandleTypeDID:
		return "did " + handle.DID
	}
	return fmt.Sprintf("%s (unknown to this tool)", handle.Type)
}

func strconv(s string) string {
	return fmt.Sprintf("%q", s)
}
