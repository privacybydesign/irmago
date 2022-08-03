//go:build !ios
// +build !ios

package disable_sigpipe

import "net"

func DisableSigPipe(c net.Conn) error {
	return nil
}
