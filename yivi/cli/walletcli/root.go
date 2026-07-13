// Package walletcli provides the `yivi sdjwtvc-wallet` command tree: a small
// command-line driver for the standalone EUDI SD-JWT VC proof-of-concept wallet
// in eudi/wallet.
package walletcli

import (
	"crypto/sha256"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/wallet"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/pbkdf2"
)

// Logger is set by the parent CLI.
var Logger *logrus.Logger

// WalletRootCmd is the root of the sdjwtvc-wallet command tree.
var WalletRootCmd = &cobra.Command{
	Use:   "sdjwtvc-wallet [command]",
	Short: "Standalone EUDI SD-JWT VC proof-of-concept wallet",
	Long: "A headless SD-JWT VC wallet in the EUDI spectrum.\n\n" +
		"It can receive credentials over OpenID4VCI, present them over OpenID4VP,\n" +
		"and store them encrypted at rest (SQLCipher). See\n" +
		"docs/poc-sdjwtvc-wallet-design.md for the design and its limitations.",
}

// persistent flags shared by all subcommands
var (
	flagDataDir    string
	flagPassphrase string
	flagDeveloper  bool
)

func init() {
	pf := WalletRootCmd.PersistentFlags()
	pf.StringVar(&flagDataDir, "data-dir", "", "Directory for the encrypted wallet database and files (required)")
	pf.StringVar(&flagPassphrase, "passphrase", "", "Passphrase used to derive the storage encryption key (required)")
	pf.BoolVar(&flagDeveloper, "developer", false, "Enable developer mode (staging trust anchors, insecure http/did:web)")
}

// openWallet builds a Wallet from the persistent flags. The AES key is derived
// from the passphrase with PBKDF2. NOTE: the POC uses a fixed salt so a given
// passphrase always opens the same data dir; a production wallet would store a
// random per-wallet salt alongside the database.
func openWallet(policy wallet.Policy) (*wallet.Wallet, error) {
	if flagDataDir == "" {
		return nil, fmt.Errorf("--data-dir is required")
	}
	if flagPassphrase == "" {
		return nil, fmt.Errorf("--passphrase is required")
	}

	const salt = "irmago-sdjwtvc-wallet-poc-v1"
	key := pbkdf2.Key([]byte(flagPassphrase), []byte(salt), 200_000, 32, sha256.New)
	var aesKey [32]byte
	copy(aesKey[:], key)

	return wallet.New(wallet.Config{
		DataDir:       flagDataDir,
		AesKey:        aesKey,
		DeveloperMode: flagDeveloper,
		Policy:        policy,
	})
}
