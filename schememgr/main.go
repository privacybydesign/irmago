// schememgr manages signatures on IRMA scheme managers.
// It can generate public-private keypairs for signing their directory structures,
// as well as creating and verifying these signatures.
package main

import "github.com/privacybydesign/irmago/schememgr/cmd"

func main() {
	cmd.Execute()
}
