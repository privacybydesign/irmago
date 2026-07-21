// decode is a small standalone CLI for inspecting COSE_Sign1 / raw CBOR
// hex blobs produced by the mdoc program — e.g. issuerAuth, deviceAuth,
// or a full presented mdoc. It does NOT verify signatures or validate
// anything; it only decodes structure so you can eyeball what's inside.
//
// Usage:
//
//	go run decode.go <hex-string>
//	go run decode.go -              (reads hex from stdin)
//
// Example:
//
//	go run decode.go d28443a10126a0585c84...988b
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run decode.go <hex-string>   (or '-' to read hex from stdin)")
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

	fmt.Printf("Input: %d bytes\n\n", len(data))

	if tryDecodeAsCOSESign1(data) {
		return
	}

	fmt.Println("Not recognized as a COSE_Sign1 array — falling back to generic CBOR decode:")
	printGeneric(data, 0)
}

// tryDecodeAsCOSESign1 attempts to interpret data as a COSE_Sign1
// structure: [protected_bstr, unprotected_map, payload_bstr, signature_bstr].
// Returns true if it looked like one and was printed; false otherwise.
func tryDecodeAsCOSESign1(data []byte) bool {
	var arr []any
	if err := cbor.Unmarshal(data, &arr); err != nil {
		return false
	}
	if len(arr) != 4 {
		return false
	}
	protectedRaw, ok0 := arr[0].([]byte)
	unprotected, ok1 := arr[1].(map[any]any)
	sig, ok3 := arr[3].([]byte)
	if !ok0 || !ok1 || !ok3 {
		return false
	}

	// Payload is bstr / nil per the COSE_Sign1 CDDL — nil means detached
	// content (the actual bytes were signed but not transmitted; the
	// verifier is expected to reconstruct them itself). arr[2] == nil
	// decodes from a CBOR null, not a nil []byte, so it must be checked
	// separately rather than type-asserted.
	var payload []byte
	detached := arr[2] == nil
	if !detached {
		p, ok2 := arr[2].([]byte)
		if !ok2 {
			return false
		}
		payload = p
	}

	fmt.Println("Detected: COSE_Sign1 (RFC 9052)")
	fmt.Println(strings.Repeat("=", 60))

	// --- protected header ---
	var protMap map[any]any
	if err := cbor.Unmarshal(protectedRaw, &protMap); err != nil {
		fmt.Printf("[protected header] failed to decode: %v\n", err)
	} else {
		fmt.Println("[protected header]")
		printCOSEHeader(protMap, "  ")
	}

	// --- unprotected header ---
	fmt.Println("\n[unprotected header]")
	if len(unprotected) == 0 {
		fmt.Println("  (empty)")
	} else {
		printCOSEHeader(unprotected, "  ")
	}

	// --- payload ---
	if detached {
		fmt.Println("\n[payload] null (detached)")
		fmt.Println("  the actual signed bytes are not transmitted — the receiver")
		fmt.Println("  is expected to reconstruct them itself and supply them before")
		fmt.Println("  verifying (this tool cannot verify detached signatures)")
	} else {
		fmt.Printf("\n[payload] %d bytes\n", len(payload))
		fmt.Printf("  hex: %s\n", hex.EncodeToString(payload))
		fmt.Println("  decoded:")
		printGeneric(payload, 2)
	}

	// --- signature ---
	fmt.Printf("\n[signature] %d bytes (raw ECDSA r||s, if ES256/ES384/ES512)\n", len(sig))
	fmt.Printf("  hex: %s\n", hex.EncodeToString(sig))
	if len(sig)%2 == 0 {
		half := len(sig) / 2
		r := sig[:half]
		s := sig[half:]
		fmt.Printf("  r (%d bytes): %s\n", len(r), hex.EncodeToString(r))
		fmt.Printf("  s (%d bytes): %s\n", len(s), hex.EncodeToString(s))
		switch len(sig) {
		case 64:
			fmt.Println("  (64 bytes total = 32+32, consistent with ES256/P-256)")
		case 96:
			fmt.Println("  (96 bytes total = 48+48, consistent with ES384/P-384)")
		case 132:
			fmt.Println("  (132 bytes total = 66+66, consistent with ES512/P-521)")
		default:
			fmt.Printf("  (%d bytes total — not a standard ES256/384/512 length, double-check alg)\n", len(sig))
		}
	} else {
		fmt.Printf("  (odd length %d bytes — cannot be a clean r||s split; this may be DER-encoded instead of raw)\n", len(sig))
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("NOTE: this tool only decodes structure. It does not check the")
	fmt.Println("signature, cert chain, or digests. Use the actual Verifier for that.")
	return true
}

// printCOSEHeader pretty-prints known COSE header label integers.
func printCOSEHeader(m map[any]any, indent string) {
	labels := map[int64]string{
		1:  "alg",
		2:  "crit",
		3:  "content type",
		4:  "kid",
		5:  "IV",
		6:  "Partial IV",
		33: "x5chain",
	}
	algNames := map[int64]string{
		-7:  "ES256",
		-35: "ES384",
		-36: "ES512",
	}
	for k, v := range m {
		var keyInt int64
		switch kv := k.(type) {
		case int64:
			keyInt = kv
		case uint64:
			keyInt = int64(kv)
		}
		label, known := labels[keyInt]
		if !known {
			label = fmt.Sprintf("%v", k)
		}

		if keyInt == 1 {
			// alg
			var algVal int64
			switch av := v.(type) {
			case int64:
				algVal = av
			case uint64:
				algVal = int64(av)
			}
			name, ok := algNames[algVal]
			if ok {
				fmt.Printf("%s%s (%v): %s\n", indent, label, k, name)
			} else {
				fmt.Printf("%s%s (%v): %v\n", indent, label, k, v)
			}
			continue
		}

		if keyInt == 33 {
			// x5chain — could be []byte or []any
			fmt.Printf("%s%s (%v):\n", indent, label, k)
			certs := toByteSliceList(v)
			for i, c := range certs {
				fmt.Printf("%s  cert[%d]: %d bytes (DER) — %s\n", indent, i, len(c), hex.EncodeToString(c[:min(16, len(c))])+"...")
			}
			continue
		}

		fmt.Printf("%s%s (%v): %v\n", indent, label, k, v)
	}
}

func toByteSliceList(v any) [][]byte {
	switch vv := v.(type) {
	case []byte:
		return [][]byte{vv}
	case []any:
		out := make([][]byte, 0, len(vv))
		for _, item := range vv {
			if b, ok := item.([]byte); ok {
				out = append(out, b)
			}
		}
		return out
	}
	return nil
}

// printGeneric decodes and pretty-prints arbitrary CBOR, unwrapping
// Tag-24 (embedded CBOR) automatically since the mdoc format uses it
// heavily for IssuerSignedItem framing.
func printGeneric(data []byte, depth int) {
	var raw cbor.RawTag
	if err := cbor.Unmarshal(data, &raw); err == nil && raw.Number == 24 {
		fmt.Printf("%sTag24 (embedded CBOR):\n", strings.Repeat("  ", depth))
		var inner []byte
		if err := cbor.Unmarshal(raw.Content, &inner); err == nil {
			printGeneric(inner, depth+1)
			return
		}
	}

	var generic any
	if err := cbor.Unmarshal(data, &generic); err != nil {
		fmt.Printf("%s(failed to decode: %v)\n", strings.Repeat("  ", depth), err)
		return
	}
	printValue(generic, depth)
}

// tryFormatTimestampField checks whether key looks like a known
// mdoc/COSE timestamp field (signed, validFrom, validUntil) and, if so,
// formats it as a human-readable UTC date. Handles two encodings:
// tag-0 RFC3339 strings (decoded by the CBOR library into time.Time
// automatically — this is what the AV Blueprint spec's own examples use,
// and what this program now encodes), and bare Unix epoch integers (an
// older encoding this program used previously — kept for compatibility
// with any hex captured before that change). Returns ok=false for
// anything that isn't one of these known fields, so normal printing
// takes over unchanged.
func tryFormatTimestampField(key any, val any) (string, bool) {
	keyStr, ok := key.(string)
	if !ok {
		return "", false
	}
	switch keyStr {
	case "signed", "validFrom", "validUntil":
		// fall through
	default:
		return "", false
	}

	switch v := val.(type) {
	case time.Time:
		return fmt.Sprintf("%s  (tag-0 RFC3339)", v.UTC().Format(time.RFC3339)), true
	case int64:
		t := time.Unix(v, 0).UTC()
		return fmt.Sprintf("%d  (%s, legacy bare-epoch encoding)", v, t.Format(time.RFC3339)), true
	case uint64:
		t := time.Unix(int64(v), 0).UTC()
		return fmt.Sprintf("%d  (%s, legacy bare-epoch encoding)", v, t.Format(time.RFC3339)), true
	default:
		return "", false
	}
}

func printValue(v any, depth int) {
	indent := strings.Repeat("  ", depth)
	switch vv := v.(type) {
	case map[any]any:
		for k, val := range vv {
			if formatted, ok := tryFormatTimestampField(k, val); ok {
				fmt.Printf("%s%v: %s\n", indent, k, formatted)
				continue
			}
			switch val.(type) {
			case map[any]any, []any:
				fmt.Printf("%s%v:\n", indent, k)
				printValue(val, depth+1)
			case []byte:
				b := val.([]byte)
				printBytesField(fmt.Sprintf("%v", k), b, depth)
			default:
				fmt.Printf("%s%v: %v\n", indent, k, val)
			}
		}
	case []any:
		for i, item := range vv {
			switch item.(type) {
			case map[any]any, []any:
				fmt.Printf("%s[%d]:\n", indent, i)
				printValue(item, depth+1)
			case []byte:
				b := item.([]byte)
				printBytesField(fmt.Sprintf("[%d]", i), b, depth)
			default:
				fmt.Printf("%s[%d]: %v\n", indent, i, item)
			}
		}
	case []byte:
		printBytesField("", vv, depth)
	default:
		fmt.Printf("%s%v\n", indent, vv)
	}
}

// printBytesField prints a []byte value. If the bytes look like they
// contain embedded CBOR (a Tag-24 wrapper, or a COSE_Sign1 4-element
// array), it recurses into them automatically instead of just dumping
// hex — this is what lets one decode.go call walk all the way from a
// full mdoc down through issuerAuth/deviceAuth into their COSE payloads
// and Tag-24 wrapped items, without needing separate invocations per layer.
func printBytesField(label string, b []byte, depth int) {
	indent := strings.Repeat("  ", depth)
	prefix := indent
	if label != "" {
		prefix = fmt.Sprintf("%s%s: ", indent, label)
	}

	// Heuristic: does this []byte itself decode as CBOR containing
	// something interesting (Tag24 or a 4-element array)?
	if looksLikeNestedCBOR(b) {
		fmt.Printf("%s%d bytes (embedded CBOR — decoding):\n", prefix, len(b))
		if tryDecodeAsCOSESign1(b) {
			return
		}
		printGeneric(b, depth+1)
		return
	}

	fmt.Printf("%s%d bytes = %s\n", prefix, len(b), hex.EncodeToString(b))
}

// looksLikeNestedCBOR does a cheap structural check (not a full decode)
// to decide whether a []byte is worth recursing into. Avoids false
// positives on things like raw signatures or salts that happen to be
// valid-ish CBOR prefixes but aren't meaningfully structured.
func looksLikeNestedCBOR(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	// Tag 24 (embedded CBOR) encodes as 0xd8 0x18 ...
	if b[0] == 0xd8 && b[1] == 0x18 {
		return true
	}
	// COSE_Sign1 (tag 18) encodes as 0xd2 ... ; try a real decode to
	// confirm it's a well-formed 4-element array before committing.
	if b[0] == 0xd2 {
		var arr []any
		if err := cbor.Unmarshal(b, &arr); err == nil && len(arr) == 4 {
			return true
		}
	}
	return false
}
