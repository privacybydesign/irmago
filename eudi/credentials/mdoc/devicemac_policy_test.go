package mdoc

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================
// THE 9.1.3.4 ONE-PURPOSE DECISION, ENFORCED
// ============================================================
//
// ISO/IEC 18013-5 9.1.3.4: "A single mdoc authentication key shall not be used to
// produce both MACs and signatures during its lifetime. An mdoc reader shall
// support both approaches."
//
// The rule binds the KEY, not the session, so it cannot be satisfied by a
// proximity-local convention: eudi/openid4vp/mdoc_dcql already authenticates with
// Holder.SignDeviceAuth, and a credential instance may be presented over either
// transport. This wallet therefore commits to deviceSignature everywhere, which
// satisfies the "shall not" by construction and removes the need for any
// per-credential record of which branch a key has served. Full reasoning in
// devicemac.go's header comment.
//
// A decision recorded only in a comment is not enforced, and this one is easy to
// breach by accident precisely because MacDeviceAuth exists, is exported, and is
// tested. So the invariant is checked structurally instead.

// macProducingFuncs are the functions that make this wallet produce a MAC with a
// credential's mdoc authentication key. Verifying or parsing an inbound deviceMac
// is NOT on this list: this package is also the mdoc reader, and 9.1.3.4 obliges a
// reader to support both approaches.
var macProducingFuncs = map[string]bool{
	"MacDeviceAuth":       true,
	"DeriveEMacKeyAsMdoc": true,
	"AttachDeviceMac":     true,
}

// macImplementationFile implements the MAC branch, so it necessarily calls the
// functions above and populates the DeviceMac field. The invariant being enforced
// is that nothing REACHES FOR the branch, not that the branch is absent — 9.1.3.4
// obliges a reader to support both approaches and this package is also the reader.
//
// Exactly one file is exempt, by name, and existence is asserted below so the
// exemption cannot quietly outlive the file it was written for.
const macImplementationFile = "devicemac.go"

// TestWalletNeverProducesDeviceMac fails if any non-test file in the module
// produces a deviceMac.
//
// It parses rather than greps, so the prose in devicemac.go that names these
// functions cannot trip it and a breach cannot hide inside a comment.
//
// If this test fails, the fix is NOT to add the caller to an exemption list. It is
// to decide 9.1.3.4 again deliberately: a wallet that produces MACs needs a
// per-credential record of the branch each key has committed to, and that record
// has to span the OpenID4VP path as well as proximity.
func TestWalletNeverProducesDeviceMac(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	var breaches []string
	var sawImplementation bool

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// testdata holds fixtures, not wallet behaviour; vendor and .git are
			// not ours to constrain.
			switch d.Name() {
			case "vendor", ".git", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Base(path) == macImplementationFile {
			sawImplementation = true
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			// A file this package cannot parse is not evidence of a breach, and
			// failing here would make an unrelated syntax error look like one.
			t.Logf("skipping unparseable %s: %v", path, err)
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if name := calleeName(node.Fun); macProducingFuncs[name] {
					breaches = append(breaches, describe(fset, node.Pos(), rel, name+" is called"))
				}
			case *ast.KeyValueExpr:
				// DeviceAuth{DeviceMac: ...} — the branch being populated on the
				// way out. A read such as len(d.DeviceMac) is a SelectorExpr and
				// is deliberately not matched.
				if key, ok := node.Key.(*ast.Ident); ok && key.Name == "DeviceMac" {
					breaches = append(breaches, describe(fset, node.Pos(), rel, "the DeviceMac branch is populated"))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	if !sawImplementation {
		t.Fatalf(
			"%s no longer exists, so its exemption is stale: either the MAC branch was removed "+
				"(delete this test) or it moved (point macImplementationFile at it)", macImplementationFile)
	}

	if len(breaches) > 0 {
		t.Errorf(
			"this wallet commits to deviceSignature for every transport, but %d place(s) produce a deviceMac.\n"+
				"ISO/IEC 18013-5 9.1.3.4: a single mdoc authentication key shall not produce both MACs and\n"+
				"signatures during its lifetime, and eudi/openid4vp/mdoc_dcql already signs with that key.\n"+
				"Read devicemac.go's header comment before changing this test.\n\t%s",
			len(breaches), strings.Join(breaches, "\n\t"))
	}
}

func describe(fset *token.FileSet, pos token.Pos, rel, what string) string {
	return rel + ":" + itoa(fset.Position(pos).Line) + ": " + what
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// calleeName returns the identifier a call expression names, for both MacDeviceAuth(...)
// and mdoc.MacDeviceAuth(...).
func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// moduleRoot walks up from the working directory to the directory holding go.mod,
// so the scan covers the whole module rather than this package.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above %s", dir)
		}
		dir = parent
	}
}
