// vptoken-decode inspects an OpenID4VP vp_token containing mso_mdoc
// presentations and prints, per credential and per document, what was actually
// disclosed and who signed it.
//
// It exists because reading a presentation by hand is a three-step chore --
// base64url to hex, run mdoc-decode, then unwrap the Tag-24 items and the
// x5chain by eye -- and that chore was being repeated every time a device test
// produced a token. Unlike mdoc-decode, which dumps CBOR structure for any
// blob, this one knows it is looking at a presentation and reports it in those
// terms.
//
// Nothing here verifies anything: no signature check, no digest recomputation,
// no chain validation. The wallet does that, as do the integration tests. This answers "what is
// in these bytes", which is a different question from "are they genuine".
//
// Usage, from the repository root:
//
//	go run ./yivi/cli/eudicli/vptoken-decode <input>
//	go run ./yivi/cli/eudicli/vptoken-decode            (reads stdin)
//
// Input may be any of:
//
//   - a verifier's whole response: {"vp_token":{"age":["o2d2ZXJ..."]}}
//   - a bare base64url DeviceResponse: o2d2ZXJ...
//   - hex, as mdoc-decode takes it
//
// Nothing is assumed about how much is in there. Every credential id in the
// vp_token map is processed, each id may hold several presentations, each
// presentation several documents, each document several namespaces and elements.
// A query for ten credentials prints ten sections.
package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
)

func main() {
	raw, err := readInput()
	if err != nil {
		fail(err)
	}

	presentations, err := extractPresentations(raw)
	if err != nil {
		fail(err)
	}
	if len(presentations) == 0 {
		fail(fmt.Errorf("no mdoc presentation found in the input"))
	}

	for i, p := range presentations {
		if i > 0 {
			fmt.Println()
		}
		if p.credentialID != "" {
			fmt.Printf("=== credential %q (presentation %d of %d) ===\n",
				p.credentialID, p.index+1, p.total)
		} else {
			fmt.Println("=== presentation ===")
		}
		if err := dumpDeviceResponse(p.bytes); err != nil {
			fmt.Printf("  could not decode: %v\n", err)
		}
	}

	fmt.Println()
	fmt.Println("Structure only: nothing above was cryptographically verified.")
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "vptoken-decode: %v\n", err)
	os.Exit(1)
}

// presentation is one DeviceResponse together with the DCQL credential id it
// arrived under, so output stays attributable when a query asked for several.
type presentation struct {
	credentialID string
	index, total int
	bytes        []byte
}

func readInput() (string, error) {
	if len(os.Args) > 1 && os.Args[1] != "-" {
		return strings.Join(os.Args[1:], " "), nil
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	return string(b), nil
}

// vpTokenEnvelope models what a verifier returns. vp_token maps each DCQL
// credential id to its presentations; OpenID4VP permits either a single string
// or an array per id, so the value stays raw until decodeTokenList picks.
type vpTokenEnvelope struct {
	VPToken map[string]json.RawMessage `json:"vp_token"`
}

// extractPresentations turns whatever was pasted into a list of DeviceResponse
// byte strings. JSON is preferred when present, because only it carries the
// credential ids; anything else is treated as one bare token.
func extractPresentations(raw string) ([]presentation, error) {
	trimmed := strings.TrimSpace(raw)

	if strings.HasPrefix(trimmed, "{") {
		var env vpTokenEnvelope
		if err := json.Unmarshal([]byte(trimmed), &env); err != nil {
			return nil, fmt.Errorf("input looks like JSON but does not parse: %w", err)
		}
		if len(env.VPToken) == 0 {
			return nil, fmt.Errorf("JSON has no vp_token member")
		}

		// Sorted so repeated runs over one response print in a stable order;
		// Go map iteration would otherwise shuffle the sections.
		ids := make([]string, 0, len(env.VPToken))
		for id := range env.VPToken {
			ids = append(ids, id)
		}
		sort.Strings(ids)

		var out []presentation
		for _, id := range ids {
			tokens, err := decodeTokenList(env.VPToken[id])
			if err != nil {
				return nil, fmt.Errorf("credential %q: %w", id, err)
			}
			for i, tok := range tokens {
				b, err := decodeToken(tok)
				if err != nil {
					return nil, fmt.Errorf("credential %q presentation %d: %w", id, i+1, err)
				}
				out = append(out, presentation{
					credentialID: id,
					index:        i,
					total:        len(tokens),
					bytes:        b,
				})
			}
		}
		return out, nil
	}

	// Not JSON: take the longest token-shaped run, so a copied line still works
	// with a shell prompt or quotes around it.
	candidate := longestTokenRun(trimmed)
	if candidate == "" {
		return nil, fmt.Errorf("found nothing token-shaped in the input")
	}
	b, err := decodeToken(candidate)
	if err != nil {
		return nil, err
	}
	return []presentation{{index: 0, total: 1, bytes: b}}, nil
}

// decodeTokenList accepts either "abc" or ["abc","def"] for one credential id.
func decodeTokenList(rm json.RawMessage) ([]string, error) {
	var single string
	if err := json.Unmarshal(rm, &single); err == nil {
		return []string{single}, nil
	}
	var many []string
	if err := json.Unmarshal(rm, &many); err != nil {
		return nil, fmt.Errorf("value is neither a string nor an array of strings")
	}
	return many, nil
}

var tokenRun = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{40,}`)

func longestTokenRun(s string) string {
	best := ""
	for _, m := range tokenRun.FindAllString(s, -1) {
		if len(m) > len(best) {
			best = m
		}
	}
	return best
}

// decodeToken accepts base64url (padded or not), standard base64, or hex. Hex
// is tried first, and only when the string can be nothing else: hex is also
// valid base64 input, so the other order would silently decode to nonsense.
func decodeToken(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"',[] \t\r\n")

	if isHex(s) {
		return hex.DecodeString(s)
	}
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("not decodable as hex, base64url or base64")
}

func isHex(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

func dumpDeviceResponse(b []byte) error {
	var resp mdoc.DeviceResponse
	if err := cbor.Unmarshal(b, &resp); err != nil || len(resp.Documents) == 0 {
		// A bare document rather than a full response is worth handling: the
		// tests pass MDoc values around directly, and those get pasted in here
		// too.
		var single mdoc.MDoc
		if err2 := cbor.Unmarshal(b, &single); err2 != nil {
			if err == nil {
				err = fmt.Errorf("no documents present")
			}
			return fmt.Errorf("neither a DeviceResponse (%v) nor a bare MDoc (%v)", err, err2)
		}
		resp = mdoc.DeviceResponse{Version: "n/a (bare document)", Documents: []mdoc.MDoc{single}}
	}

	fmt.Printf("  %d bytes | version %s | status %d\n", len(b), resp.Version, resp.Status)
	if resp.Status != 0 {
		fmt.Println("  NOTE status is non-zero: ISO 18013-5 Table 8 treats anything but 0 as an error")
	}

	for i := range resp.Documents {
		doc := resp.Documents[i]
		fmt.Printf("\n  document %d of %d: docType %s\n", i+1, len(resp.Documents), doc.DocType)
		dumpDocument(&doc)
	}
	return nil
}

func dumpDocument(doc *mdoc.MDoc) {
	mso, cert := issuerAuthDetails(doc.IssuerSigned.IssuerAuth)

	namespaces := make([]string, 0, len(doc.IssuerSigned.NameSpaces))
	for ns := range doc.IssuerSigned.NameSpaces {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	if len(namespaces) == 0 {
		fmt.Println("    disclosed: nothing (no namespaces present)")
	}
	for _, ns := range namespaces {
		items := doc.IssuerSigned.NameSpaces[ns]

		// The MSO commits to a digest per element whether or not the item
		// travels, so its count is what the credential holds in total and the
		// difference is what stayed hidden.
		if mso != nil {
			fmt.Printf("    namespace %s: %d disclosed of %d in the credential\n",
				ns, len(items), len(mso.ValueDigests[ns]))
		} else {
			fmt.Printf("    namespace %s: %d disclosed\n", ns, len(items))
		}

		for _, wrapped := range items {
			item, err := decodeTag24Item(wrapped)
			if err != nil {
				fmt.Printf("      (undecodable item: %v)\n", err)
				continue
			}
			fmt.Printf("      %-24s = %v\n", item.ElementIdentifier, item.ElementValue)
			fmt.Printf("        digestID %d, salt %d bytes\n", item.DigestID, len(item.Random))
			// The floor the wallet enforces on receipt. Worth surfacing here
			// because a short salt makes an undisclosed element brute-forceable,
			// and this tool is where a suspicious credential gets looked at.
			if len(item.Random) < 16 {
				fmt.Println("        WARNING salt is under the 16-byte ISO 18013-5 floor")
			}
		}
	}

	if mso != nil {
		fmt.Printf("    validity: signed %s, valid %s .. %s\n",
			mso.ValidityInfo.Signed.Format("2006-01-02"),
			mso.ValidityInfo.ValidFrom.Format("2006-01-02"),
			mso.ValidityInfo.ValidUntil.Format("2006-01-02"))
		fmt.Printf("    digest algorithm: %s\n", mso.DigestAlgorithm)
	}

	if cert != nil {
		fmt.Printf("    document signer: %s\n", cert.Subject)
		fmt.Printf("      issued by %s\n", cert.Issuer)
		fmt.Printf("      valid %s .. %s\n",
			cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
		if ekus := mdocEKUs(cert); len(ekus) > 0 {
			fmt.Printf("      EKU: %s\n", strings.Join(ekus, ", "))
		} else {
			fmt.Println("      EKU: none enumerated (RFC 5280: unrestricted)")
		}
	}

	if doc.DeviceSigned == nil {
		fmt.Println("    deviceSigned: absent -- this is an issued credential, not a presentation")
		return
	}
	fmt.Printf("    deviceSigned: present, %d byte deviceAuth\n",
		len(doc.DeviceSigned.DeviceAuth.DeviceSignature))
}

// mdocEKUs renders the certificate's extended key usages. The ISO mdoc OIDs
// have no crypto/x509 enum member, so they arrive in UnknownExtKeyUsage;
// anything Go does recognise is named alongside.
func mdocEKUs(cert *x509.Certificate) []string {
	var out []string
	for _, oid := range cert.UnknownExtKeyUsage {
		switch oid.String() {
		case "1.0.18013.5.1.2":
			out = append(out, oid.String()+" (ISO 18013-5 mDL document signer)")
		case "1.0.23220.4.1.2":
			out = append(out, oid.String()+" (ISO 23220-4 mdoc document signer)")
		case "1.0.18013.5.1.6", "1.0.23220.4.1.6":
			out = append(out, oid.String()+" (reader auth -- NOT a document signer usage)")
		default:
			out = append(out, oid.String())
		}
	}
	for _, eku := range cert.ExtKeyUsage {
		out = append(out, fmt.Sprintf("x509.ExtKeyUsage(%d)", eku))
	}
	return out
}

// decodeTag24Item unwraps #6.24(bstr .cbor IssuerSignedItem).
func decodeTag24Item(wrapped mdoc.Tag24Item) (*mdoc.IssuerSignedItem, error) {
	var tag cbor.RawTag
	if err := cbor.Unmarshal(wrapped.EncodedItem, &tag); err != nil {
		return nil, fmt.Errorf("unwrap tag: %w", err)
	}
	var inner []byte
	if err := cbor.Unmarshal(tag.Content, &inner); err != nil {
		return nil, fmt.Errorf("unwrap inner bytes: %w", err)
	}
	var item mdoc.IssuerSignedItem
	if err := cbor.Unmarshal(inner, &item); err != nil {
		return nil, fmt.Errorf("decode item: %w", err)
	}
	return &item, nil
}

// issuerAuthDetails pulls the MSO and the leaf certificate out of the
// COSE_Sign1 at issuerAuth.
//
// Everything here is best effort and returns nil rather than failing: a token
// worth inspecting is often one that is malformed somewhere, and losing the
// disclosed-element listing because a header could not be parsed would defeat
// the purpose of the tool.
func issuerAuthDetails(issuerAuth cbor.RawMessage) (*mdoc.MSO, *x509.Certificate) {
	if len(issuerAuth) == 0 {
		return nil, nil
	}
	var sign1 []cbor.RawMessage
	if err := cbor.Unmarshal(issuerAuth, &sign1); err != nil || len(sign1) != 4 {
		return nil, nil
	}
	return msoFromPayload(sign1[2]), leafFromUnprotectedHeader(sign1[1])
}

// msoFromPayload decodes COSE_Sign1's payload, which is a byte string holding
// #6.24(bstr .cbor MobileSecurityObject).
func msoFromPayload(rm cbor.RawMessage) *mdoc.MSO {
	var payload []byte
	if err := cbor.Unmarshal(rm, &payload); err != nil {
		return nil
	}
	var tag cbor.RawTag
	if err := cbor.Unmarshal(payload, &tag); err != nil {
		return nil
	}
	var inner []byte
	if err := cbor.Unmarshal(tag.Content, &inner); err != nil {
		return nil
	}
	var mso mdoc.MSO
	if err := cbor.Unmarshal(inner, &mso); err != nil {
		return nil
	}
	return &mso
}

// leafFromUnprotectedHeader reads the x5chain at COSE header label 33. The
// value is either one certificate as a byte string or an array of them, leaf
// first; only the leaf is of interest here.
func leafFromUnprotectedHeader(rm cbor.RawMessage) *x509.Certificate {
	var header map[any]cbor.RawMessage
	if err := cbor.Unmarshal(rm, &header); err != nil {
		return nil
	}
	for label, value := range header {
		n, ok := label.(uint64)
		if !ok || n != 33 {
			continue
		}
		var single []byte
		if err := cbor.Unmarshal(value, &single); err == nil {
			if cert, err := x509.ParseCertificate(single); err == nil {
				return cert
			}
		}
		var chain [][]byte
		if err := cbor.Unmarshal(value, &chain); err == nil && len(chain) > 0 {
			if cert, err := x509.ParseCertificate(chain[0]); err == nil {
				return cert
			}
		}
	}
	return nil
}
