//go:build cgo

package cli

import (
	"github.com/privacybydesign/irmago/yivi/cli/walletcli"
	"github.com/sirupsen/logrus"
)

// registerWalletCmd wires up the SQLCipher-backed `sdjwtvc-wallet` command tree.
// The wallet stores credentials encrypted at rest with SQLCipher, which requires
// cgo, so this is compiled only into cgo builds. The CGO_ENABLED=0 static release
// and Docker binaries omit the command (see the no-op in walletcli_nocgo.go).
func registerWalletCmd(logger *logrus.Logger) {
	walletcli.Logger = logger
	RootCmd.AddCommand(walletcli.WalletRootCmd)
}
