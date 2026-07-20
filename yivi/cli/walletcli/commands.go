package walletcli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/wallet"
	"github.com/spf13/cobra"
)

var flagJSON bool

func init() {
	WalletRootCmd.PersistentFlags().BoolVar(&flagJSON, "json", false, "Emit machine-readable JSON instead of human-readable text")

	WalletRootCmd.AddCommand(receiveCmd)
	WalletRootCmd.AddCommand(presentCmd)
	WalletRootCmd.AddCommand(listCmd)
	WalletRootCmd.AddCommand(logsCmd)
	WalletRootCmd.AddCommand(resetCmd)
}

// ---------------------------------------------------------------------------
// receive
// ---------------------------------------------------------------------------

var (
	flagRedirectURI     string
	flagTransactionCode string
	flagPromptTxCode    bool
)

var receiveCmd = &cobra.Command{
	Use:   "receive <credential-offer-uri>",
	Short: "Obtain a credential over OpenID4VCI",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		policy := wallet.FuncPolicy{
			TransactionCodeFunc: func() (string, bool) {
				if flagTransactionCode != "" {
					return flagTransactionCode, true
				}
				if flagPromptTxCode {
					code, err := prompt("Transaction code: ")
					if err != nil || code == "" {
						return "", false
					}
					return code, true
				}
				return "", false
			},
		}

		w, err := openWallet(policy)
		if err != nil {
			return err
		}
		defer w.Close()

		creds, err := w.Receive(args[0], flagRedirectURI, stdinAuthCodeResolver)
		if err != nil {
			return err
		}

		if flagJSON {
			return printJSON(creds)
		}
		fmt.Printf("Received %d credential(s):\n", len(creds))
		for _, c := range creds {
			printCredential(c)
		}
		return nil
	},
}

func init() {
	f := receiveCmd.Flags()
	f.StringVar(&flagRedirectURI, "redirect-uri", "openid4vci://callback", "OAuth redirect_uri sent to the issuer's authorization server")
	f.StringVar(&flagTransactionCode, "transaction-code", "", "Pre-authorized-code transaction code (tx_code), if the issuer requires one")
	f.BoolVar(&flagPromptTxCode, "prompt-transaction-code", false, "Prompt for the transaction code on stdin if the issuer requires one")
}

// stdinAuthCodeResolver drives the authorization-code flow interactively: it
// prints the URL the user must open and reads the pasted callback URL back.
func stdinAuthCodeResolver(authURL string) (string, error) {
	fmt.Println("\nThe issuer requires the authorization code flow.")
	fmt.Println("1. Open this URL in a browser and complete authentication:")
	fmt.Printf("\n   %s\n\n", authURL)
	fmt.Println("2. After being redirected, paste the full callback URL here.")
	return prompt("Callback URL: ")
}

// ---------------------------------------------------------------------------
// present
// ---------------------------------------------------------------------------

var presentCmd = &cobra.Command{
	Use:   "present <authorization-request-uri>",
	Short: "Disclose a credential over OpenID4VP",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// AutoApprovePolicy discloses the first fully-owned option for each
		// required query. Deny cannot be expressed on the CLI yet.
		w, err := openWallet(wallet.AutoApprovePolicy{})
		if err != nil {
			return err
		}
		defer w.Close()

		res, err := w.Present(args[0])
		if err != nil {
			return err
		}

		if flagJSON {
			return printJSON(res)
		}
		verifier := "unknown verifier"
		if res.Requestor != nil {
			verifier = translated(res.Requestor.Name)
		}
		fmt.Printf("Disclosed to %s:\n", verifier)
		if len(res.Disclosed) == 0 {
			fmt.Println("  (nothing shared)")
		}
		for _, c := range res.Disclosed {
			fmt.Printf("  • %s\n", translated(c.Name))
			for _, a := range c.Attributes {
				fmt.Printf("      %s\n", claimPathString(a.ClaimPath))
			}
		}
		return nil
	},
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored credentials",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		w, err := openWallet(nil)
		if err != nil {
			return err
		}
		defer w.Close()

		creds, err := w.Credentials()
		if err != nil {
			return err
		}
		if flagJSON {
			return printJSON(creds)
		}
		if len(creds) == 0 {
			fmt.Println("No credentials stored.")
			return nil
		}
		for _, c := range creds {
			printCredential(c)
		}
		return nil
	},
}

// ---------------------------------------------------------------------------
// logs
// ---------------------------------------------------------------------------

var flagLogsMax int

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Show session logs (issuance, disclosure, removal)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		w, err := openWallet(nil)
		if err != nil {
			return err
		}
		defer w.Close()

		logs, err := w.Logs(flagLogsMax)
		if err != nil {
			return err
		}
		if flagJSON {
			return printJSON(logs)
		}
		if len(logs) == 0 {
			fmt.Println("No logs.")
			return nil
		}
		for _, l := range logs {
			printLog(l)
		}
		return nil
	},
}

func init() {
	logsCmd.Flags().IntVar(&flagLogsMax, "max", 20, "Maximum number of log entries to show")
}

// ---------------------------------------------------------------------------
// reset
// ---------------------------------------------------------------------------

var flagResetForce bool

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Wipe all credentials, holder keys and logs",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !flagResetForce {
			ans, _ := prompt("This deletes all wallet data. Type 'yes' to continue: ")
			if strings.TrimSpace(ans) != "yes" {
				fmt.Println("Aborted.")
				return nil
			}
		}
		w, err := openWallet(nil)
		if err != nil {
			return err
		}
		defer w.Close()

		if err := w.Reset(); err != nil {
			return err
		}
		fmt.Println("Wallet reset.")
		return nil
	},
}

func init() {
	resetCmd.Flags().BoolVarP(&flagResetForce, "force", "f", false, "Do not ask for confirmation")
}

// ---------------------------------------------------------------------------
// rendering helpers
// ---------------------------------------------------------------------------

func printCredential(c *clientmodels.Credential) {
	fmt.Printf("• %s  (%s)\n", translated(c.Name), c.CredentialId)
	fmt.Printf("    issuer: %s\n", translated(c.Issuer.Name))
	if c.ExpiryDate != nil && *c.ExpiryDate > 0 {
		fmt.Printf("    expires: %s\n", time.Unix(*c.ExpiryDate, 0).Format(time.RFC3339))
	}
	for _, a := range c.Attributes {
		fmt.Printf("    %s: %s\n", claimPathString(a.ClaimPath), attributeValueString(a))
	}
}

func printLog(l clientmodels.LogInfo) {
	ts := l.Time.Format(time.RFC3339)
	switch {
	case l.IssuanceLog != nil:
		who := "unknown issuer"
		if l.IssuanceLog.Issuer != nil {
			who = translated(l.IssuanceLog.Issuer.Name)
		}
		fmt.Printf("[%s] issued %d credential(s) from %s\n", ts, len(l.IssuanceLog.Credentials), who)
	case l.DisclosureLog != nil:
		who := "unknown verifier"
		if l.DisclosureLog.Verifier != nil {
			who = translated(l.DisclosureLog.Verifier.Name)
		}
		fmt.Printf("[%s] disclosed %d credential(s) to %s\n", ts, len(l.DisclosureLog.Credentials), who)
	case l.RemovalLog != nil:
		fmt.Printf("[%s] removed %d credential(s)\n", ts, len(l.RemovalLog.Credentials))
	default:
		fmt.Printf("[%s] %s\n", ts, l.Type)
	}
}

func attributeValueString(a clientmodels.Attribute) string {
	if a.Value == nil {
		return ""
	}
	if a.Value.String != nil {
		return *a.Value.String
	}
	b, _ := json.Marshal(a.Value)
	return string(b)
}

func claimPathString(path []any) string {
	parts := make([]string, 0, len(path))
	for _, p := range path {
		parts = append(parts, fmt.Sprintf("%v", p))
	}
	return strings.Join(parts, ".")
}

// translated picks a human-readable string from a localized map, preferring
// English then the raw value then any available language.
func translated(t clientmodels.TranslatedString) string {
	if t == nil {
		return ""
	}
	for _, key := range []string{"en", ""} {
		if v, ok := t[key]; ok && v != "" {
			return v
		}
	}
	for _, v := range t {
		if v != "" {
			return v
		}
	}
	return ""
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func prompt(label string) (string, error) {
	fmt.Print(label)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	return strings.TrimSpace(line), err
}
