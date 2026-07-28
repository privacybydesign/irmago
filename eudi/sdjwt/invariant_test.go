package sdjwt

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencyInvariant enforces the hard boundary : eudi/sdjwt is the pure SD-JWT core and
// must never depend on the SD-JWT VC policy layer, Token Status List, the
// scheme package, or SD-JWT VC Type Metadata — directly or transitively.
//
// It shells out to `go list -deps` rather than adding
// golang.org/x/tools/go/packages as a new module dependency just for this
// one check.
func TestDependencyInvariant(t *testing.T) {
	const pkg = "github.com/privacybydesign/irmago/eudi/sdjwt"

	forbidden := []string{
		"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc",
		"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata",
		"github.com/privacybydesign/irmago/eudi/credentials/statuslist",
		"github.com/privacybydesign/irmago/eudi/scheme",
	}

	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s failed: %v", pkg, err)
	}

	deps := make(map[string]bool)
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		deps[line] = true
	}

	for _, f := range forbidden {
		if deps[f] {
			t.Errorf("eudi/sdjwt must not depend on %s, directly or transitively — "+
				"this violates the one-directional boundary described in "+
				"eudi/sdjwt/doc.go", f)
		}
	}
}
