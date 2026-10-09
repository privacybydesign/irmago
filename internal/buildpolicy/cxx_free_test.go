// Package buildpolicy holds tests that enforce build-level invariants of this
// repository: properties that are not about what the code does, but about what
// the toolchain is allowed to need in order to compile it.
//
// Two such invariants exist, both from irmago#724, and both were true by
// accident before these tests existed. Nothing stopped a dependency from
// quietly breaking either one, and neither would have been noticed until a
// release build failed.
//
//  1. irmago never compiles C++. The zero-knowledge prover is C++ behind a C
//     ABI, and it lives in a separate module (privacybydesign/longfellow-go)
//     that irmago does not import. A contributor must be able to build and
//     test this repository with a C toolchain alone, and no CI job may need a
//     C++ one.
//
//  2. ./yivi stays free of cgo entirely. The release matrix cross-compiles it
//     for linux, darwin and windows on amd64, 386, arm and arm64 with
//     CGO_ENABLED=0 (.github/actions/build/action.yml). A cgo package anywhere
//     in that binary's import graph breaks every one of those builds at once,
//     and does so at release time rather than on the pull request that caused
//     it.
//
// Note the asymmetry: cgo itself is permitted in the repository, and used by
// eudi/storage/db/sqlcipher and irma/server/irmac. Both are C. It is C++ that
// is excluded everywhere, and cgo that is excluded from one binary.
package buildpolicy_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// cxxExtensions are the suffixes the Go toolchain treats as C++ in a cgo
// package, plus the headers that only a C++ compiler can read. A .c or .h file
// is deliberately absent: C is allowed.
var cxxExtensions = []string{
	".cc", ".cpp", ".cxx", ".c++",
	".hh", ".hpp", ".hxx", ".ipp",
	".mm",
}

// skipDirs are directories the go tool ignores or that hold material which is
// never compiled, so a C++ file inside one cannot reach a build.
var skipDirs = map[string]bool{
	".git":         true,
	"testdata":     true,
	"node_modules": true,
}

// TestNoCXXSourcesInRepository is the cheap half of invariant 1: it needs no
// toolchain and catches a C++ file the moment it is added, including one
// vendored into a directory that is not yet wired into a package.
func TestNoCXXSourcesInRepository(t *testing.T) {
	root := moduleRoot(t)

	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		for _, cxx := range cxxExtensions {
			if ext == cxx {
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					rel = path
				}
				found = append(found, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	require.NoError(t, err)

	require.Empty(t, found,
		"irmago must never compile C++ (irmago#724): C++ sources found in the repository.\n"+
			"Native C++ belongs in privacybydesign/longfellow-go, reached through the\n"+
			"eudi/credentials/mdoc/zk interface, not in this module.")
}

// TestNoCXXInBuildGraph is the other half of invariant 1: a dependency module
// can carry C++ that the file walk above never sees, and it compiles as soon
// as one of its packages is imported. `go list` reports the C++ sources of
// every package it resolves, which is exactly the set the toolchain would
// hand to a C++ compiler.
func TestNoCXXInBuildGraph(t *testing.T) {
	var offenders []string
	for _, p := range listPackages(t, "./...") {
		if p.cxxFiles > 0 || p.swigCXXFiles > 0 {
			offenders = append(offenders, p.importPath)
		}
	}

	require.Empty(t, offenders,
		"irmago must never compile C++ (irmago#724): these packages in the build\n"+
			"graph carry C++ sources. Building or testing this repository would need a\n"+
			"C++ toolchain, which contributors and lint jobs are not asked to have.")
}

// buildTags are the build tags this repository uses, as of writing: the union
// of every identifier appearing in a //go:build line. The check below lists
// with all of them set at once, so a file hidden behind one is still seen.
// Extend this when a tag is added.
var buildTags = []string{"ios", "jwx_es256k", "local_tests"}

// TestNoCXXInTaggedBuildGraph extends invariant 1 past the default build.
// #724 words the rule as "irmago never compiles C++ — not even in a tagged
// job", and a file behind //go:build something is invisible to a plain
// `go list ./...`.
func TestNoCXXInTaggedBuildGraph(t *testing.T) {
	var offenders []string
	for _, p := range listPackages(t, "./...", "-tags", strings.Join(buildTags, ",")) {
		if p.cxxFiles > 0 || p.swigCXXFiles > 0 {
			offenders = append(offenders, p.importPath)
		}
	}

	require.Empty(t, offenders,
		"irmago must never compile C++ (irmago#724), including behind a build tag:\n"+
			"these packages carry C++ sources when %s are set.",
		strings.Join(buildTags, ", "))
}

// cxxModules are modules known to compile C++, which therefore may not appear
// in go.mod at all.
//
// This is the half of invariant 1 that does not depend on build tags, and it
// is the one that actually bites. A //go:build zkp test file importing the
// prover is invisible to a listing that does not set that tag, but it cannot
// compile without a require line, and the require line is visible here
// whatever the tags are. #724 originally planned exactly such a test, with
// "longfellow-go becomes a go.mod requirement" written into the decision
// table, which contradicts the rule in the row above it. The rule wins: the
// prover is reached through the eudi/credentials/mdoc/zk interface, and the
// end-to-end test that needs a real prover lives in longfellow-go.
var cxxModules = []string{
	"github.com/privacybydesign/longfellow-go",
}

func TestCXXModulesAreNotDependencies(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), "go.mod"))
	require.NoError(t, err)

	// Comments are stripped so that naming a module in a note, as the lines
	// above do, is not itself a failure.
	var offenders []string
	for line := range strings.Lines(string(raw)) {
		if before, _, found := strings.Cut(line, "//"); found {
			line = before
		}
		line = strings.TrimSpace(line)
		for _, mod := range cxxModules {
			if strings.Contains(line, mod) {
				offenders = append(offenders, line)
			}
		}
	}

	require.Empty(t, offenders,
		"these go.mod directives name a module that compiles C++, which irmago must\n"+
			"never do (irmago#724). The prover is injected through the\n"+
			"eudi/credentials/mdoc/zk interface; nothing in this module may import it,\n"+
			"including behind a build tag.")
}

// TestYiviBinaryIsCgoFree enforces invariant 2. It asserts the property rather
// than the build, so it holds for every target in the release matrix at once
// instead of only the host's.
func TestYiviBinaryIsCgoFree(t *testing.T) {
	var offenders []string
	for _, p := range listPackages(t, "./yivi") {
		// runtime/cgo is pulled in by the toolchain, not by an import of ours,
		// and disappears under CGO_ENABLED=0. It is not a violation.
		if p.importPath == "runtime/cgo" {
			continue
		}
		if p.cgoFiles > 0 {
			offenders = append(offenders, p.importPath)
		}
	}

	require.Empty(t, offenders,
		"./yivi must cross-compile with CGO_ENABLED=0 for the release matrix\n"+
			"(.github/actions/build/action.yml): these packages in its import graph use\n"+
			"cgo. Keep native code behind an interface the server binary does not reach,\n"+
			"the way eudi/storage/db/sqlcipher stays out of it today.")
}

type pkg struct {
	importPath   string
	cxxFiles     int
	swigCXXFiles int
	cgoFiles     int
}

// listPackages resolves pattern and everything it depends on. The -e flag
// keeps a package that fails to resolve (a missing C header on a machine
// without sqlcipher, say) from failing the whole listing: such a package is
// still reported, with the fields this test reads left empty.
func listPackages(t *testing.T, pattern string, extraArgs ...string) []pkg {
	t.Helper()

	const format = "{{.ImportPath}}\t{{len .CXXFiles}}\t{{len .SwigCXXFiles}}\t{{len .CgoFiles}}"
	args := append([]string{"list", "-e", "-deps", "-f", format}, extraArgs...)
	out := runGo(t, append(args, pattern)...)

	var pkgs []pkg
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) != 4 {
			continue
		}
		p := pkg{importPath: fields[0]}
		p.cxxFiles, _ = strconv.Atoi(fields[1])
		p.swigCXXFiles, _ = strconv.Atoi(fields[2])
		p.cgoFiles, _ = strconv.Atoi(fields[3])
		pkgs = append(pkgs, p)
	}

	require.NotEmpty(t, pkgs, "go list %s returned no packages", pattern)
	return pkgs
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	gomod := strings.TrimSpace(runGo(t, "env", "GOMOD"))
	require.NotEmpty(t, gomod, "go env GOMOD is empty: these tests must run inside the module")
	require.NotEqual(t, "/dev/null", gomod, "go env GOMOD is /dev/null: these tests must run inside the module")
	return filepath.Dir(gomod)
}

func runGo(t *testing.T, args ...string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", args...)
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			stderr = string(exitErr.Stderr)
		}
		require.NoError(t, err, "go %s failed: %s", strings.Join(args, " "), stderr)
	}
	return string(out)
}
