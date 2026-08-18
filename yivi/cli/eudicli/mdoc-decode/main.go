// mdoc-decode is a small standalone CLI for inspecting COSE_Sign1 / raw CBOR
// hex blobs produced by eudi/credentials/mdoc — e.g. issuerAuth, deviceAuth,
// or a full presented mdoc. It does NOT verify signatures or validate
// anything; it only decodes structure so you can eyeball what's inside.
//
// The decoding lives in internal/mdocdecode so that mdoc-demo can print the same
// view of the bytes it produces, rather than the two drifting apart.
//
// Usage, from the repository root:
//
//	go run ./yivi/cli/eudicli/mdoc-decode <hex-string>
//	go run ./yivi/cli/eudicli/mdoc-decode -    (reads hex from stdin)
//
// Example:
//
//	go run ./yivi/cli/eudicli/mdoc-decode d28443a10126a0585c84...988b
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/privacybydesign/irmago/yivi/cli/eudicli/internal/mdocdecode"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./yivi/cli/eudicli/mdoc-decode <hex-string>   (or '-' to read hex from stdin)")
		os.Exit(1)
	}

	var hexStr string
	if os.Args[1] == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
			os.Exit(1)
		}
		hexStr = string(b)
	} else {
		hexStr = os.Args[1]
	}

	hexStr = strings.TrimSpace(hexStr)
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ReplaceAll(hexStr, " ", "")

	data, err := hex.DecodeString(hexStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid hex: %v\n", err)
		os.Exit(1)
	}

	mdocdecode.Dump(data)
}
