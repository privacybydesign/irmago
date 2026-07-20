//go:build !cgo

package cli

import "github.com/sirupsen/logrus"

// registerWalletCmd is a no-op in CGO-free builds. The `sdjwtvc-wallet` command
// depends on SQLCipher (cgo) for encrypted storage and cannot function in a
// static, CGO_ENABLED=0 binary, so it is omitted from the release and Docker
// builds. The cgo build registers it in walletcli_cgo.go.
func registerWalletCmd(_ *logrus.Logger) {}
