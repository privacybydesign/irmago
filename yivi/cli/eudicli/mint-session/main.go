// mint-session starts a presentation (and optionally an issuance) against the
// local EUDI containers and prints the commands needed to drive a real phone
// through them.
//
// It shares its request-building with mdoc-e2e via internal/localstack, so the
// links a device is handed and the ones the automated demo uses cannot drift
// apart -- which they had, when this logic existed twice.
//
// Usage, from the repository root:
//
//	go run ./yivi/cli/eudicli/mint-session                    presentation only
//	go run ./yivi/cli/eudicli/mint-session -issue             issuance too
//	go run ./yivi/cli/eudicli/mint-session -value false       ask for false
//	go run ./yivi/cli/eudicli/mint-session -value any         no constraint
//
// -value constrains the DCQL query only. What -issue mints is always exactly
// localstack.DefaultAVElements, so the offer and the query can be made to
// disagree on purpose -- which is what testing a refusal requires.
//
//	go run ./yivi/cli/eudicli/mint-session -element age_over_21
//
// Prerequisites: the compose stack up, and adb reverse for 8090 (verifier) plus
// 8443 (issuer, only needed with -issue). The app needs developer mode on, and
// must be unlocked when a link arrives -- a locked app queues it at the PIN
// screen, which looks like nothing happening.
package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/privacybydesign/irmago/yivi/cli/eudicli/internal/localstack"
)

var (
	issuerURL    = flag.String("issuer", "https://localhost:8443/eudi-pid-issuer-py", "EUDI reference issuer, through the TLS proxy")
	verifierHost = flag.String("verifier", "http://127.0.0.1:8090", "EUDI reference verifier")
	testdataDir  = flag.String("testdata", "testdata", "path to the repository's testdata folder")

	docType = flag.String("doctype", "eu.europa.ec.av.1", "mdoc docType to request")
	element = flag.String("element", "age_over_18", "element to request")
	value   = flag.String("value", "true", `query value constraint: "true", "false", or "any" to omit it. Does not affect what -issue mints`)

	issue = flag.Bool("issue", false, "also mint a credential offer, so the credential can be installed first")

	reverse = flag.Bool("reverse", true, "run adb reverse for the verifier and issuer ports first, so localhost on the phone reaches this machine")

	// The decoder is named in the printed command rather than invoked, because the
	// point is to hand over something runnable after the phone has answered.
	decoder = flag.String("decoder", "", "path to a prebuilt vptoken-decode binary to name in the verify command")
)

func main() {
	flag.Parse()

	cfg := localstack.Config{
		IssuerURL:    *issuerURL,
		VerifierHost: *verifierHost,
		TestdataDir:  *testdataDir,
	}

	if _, err := os.Stat(cfg.IssuerCAPath()); err != nil {
		fail(fmt.Errorf("issuer CA not found at %s: run from the repository root, or pass -testdata", cfg.IssuerCAPath()))
	}

	// Only the issuer is behind TLS, so without this a presentation-only run
	// works and -issue fails as an unknown authority.
	if err := localstack.TrustProxyCertificate(cfg); err != nil {
		fail(err)
	}

	if *reverse {
		reversePorts(cfg, *issue)
	}

	// The constraint applies to the query only. What gets issued is whatever
	// localstack.DefaultAVElements says and nothing else: an offer that silently
	// disagreed with the source it claims to mint made the tool useless for
	// checking what the issuer actually does with a given set of values.
	var wantValue, unconstrained bool
	switch strings.ToLower(*value) {
	case "any":
		unconstrained = true
	case "true":
		wantValue = true
	case "false":
		wantValue = false
	default:
		fail(fmt.Errorf(`-value must be "true", "false" or "any", got %q`, *value))
	}

	step := 1
	if *issue {
		// The same five-element set mdoc-e2e mints, verbatim. Change what is
		// issued by editing localstack.DefaultAVElements, not by passing a flag --
		// -value constrains the query, and letting it also rewrite the offer would
		// mean the two could never be made to disagree, which is exactly what a
		// refusal test needs.
		data := localstack.DefaultAVElements()
		offer, err := localstack.CreateOffer(cfg, localstack.AVCredentialConfigID, data)
		if err != nil {
			fail(fmt.Errorf("create offer: %w", err))
		}
		fmt.Printf("%d. ISSUANCE            one-time code: %s\n\n", step, offer.TxCode)
		fmt.Println(adbCommand(offer.URI))
		fmt.Printf("\n   Unlock the app, enter %s at the one-time code prompt, accept.\n", offer.TxCode)
		fmt.Printf("   credential will hold: %s\n\n", describe(data))
		step++
	}

	req := localstack.NewSessionRequest(*docType, *element)
	if !unconstrained {
		req.Value = &wantValue
	}

	session, err := localstack.CreateSession(cfg, req)
	if err != nil {
		fail(fmt.Errorf("create session: %w", err))
	}

	constraint := "any value"
	if req.Value != nil {
		constraint = fmt.Sprintf("must equal %t", *req.Value)
	}
	fmt.Printf("%d. PRESENTATION         %s / %s, %s\n\n", step, *docType, *element, constraint)
	fmt.Println(adbCommand(session.Link))
	fmt.Print("\n   Approve on the phone.\n")
	fmt.Print("   The app then disappears. That is deliberate, not a crash: on a\n")
	fmt.Print("   same-device session irmamobile hands the user back to whatever called\n")
	fmt.Print("   it, and on Android it does that by moving its own task to the\n")
	fmt.Print("   background so the OS surfaces the previous app. Launched from adb\n")
	fmt.Print("   there is nothing to surface, so it reads as the app exiting. See the\n")
	fmt.Print("   same-device branch of session_screen.dart in irmamobile's yivi_core,\n")
	fmt.Print("   which dispatches AndroidSendToBackgroundEvent and pops; iOS shows an\n")
	fmt.Print("   ArrowBack screen there instead, lacking a way to do it itself.\n\n")
	step++

	verify := fmt.Sprintf("curl -s %s/ui/presentations/%s | ", *verifierHost, session.TransactionID)
	if *decoder != "" {
		verify += *decoder
	} else {
		verify += decoderCommand()
	}
	fmt.Printf("%d. VERIFY               what was actually disclosed\n\n", step)
	fmt.Println(verify)
	fmt.Println()
	fmt.Println("   Before you approve, that returns HTTP 400 with a state error:")
	fmt.Println("   the verifier saying \"no answer yet\", not a failure.")
}

// adbCommand wraps a wallet link for `adb shell`. The inner single quotes are
// load-bearing: adb concatenates its arguments and the device's own shell
// re-parses them, so an unquoted & would background the command there.
func adbCommand(link string) string {
	return fmt.Sprintf(`adb shell "am start -a android.intent.action.VIEW -d '%s'"`, link)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "mint-session: %v\n", err)
	os.Exit(1)
}

// decoderCommand names vptoken-decode in a way that survives being pasted into
// a shell whose working directory is not the repository.
//
// "go run ./yivi/..." only resolves from the repository root -- anywhere else it
// fails with "go.mod file not found", which reads as a broken command rather
// than a wrong directory. go's -C flag changes directory before doing anything
// else, so naming the module root explicitly makes the printed line
// copy-pasteable from a home directory, a different drive, or wherever the phone
// is being watched from.
//
// The module root is resolved at runtime rather than hardcoded, so a checkout
// somewhere else still prints something that works. If it cannot be found the
// relative form is printed unchanged: correct where it was always correct, and
// no worse anywhere else.
func decoderCommand() string {
	const pkg = "./yivi/cli/eudicli/vptoken-decode"

	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	root := strings.TrimSpace(string(out))
	if err != nil || root == "" {
		return "go run " + pkg
	}
	return fmt.Sprintf("go -C %s run %s", root, pkg)
}

// describe renders an element set in a stable order, so what a run minted can be
// compared against what a later run did.
func describe(data map[string]any) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, data[k]))
	}
	return strings.Join(parts, ", ")
}

// reversePorts points localhost on the device at this machine, for the ports the
// links about to be printed name.
//
// Forgetting this is the most common way for the demo to fail, and it fails
// misleadingly: the phone resolves localhost to itself, so the wallet reports a
// connection error that reads like the containers being down. Doing it here means
// one command sets up and mints, rather than three that have to be remembered in
// the right order.
//
// Ports come from the configured URLs rather than being hardcoded, so pointing
// -verifier or -issuer elsewhere still forwards the right thing, and the issuer
// is only forwarded when it is going to be used.
//
// Nothing here is fatal. adb may be absent because the caller only wants the
// links, to paste somewhere else or to read, so a missing adb prints the commands
// to run and gets out of the way. It is looked up once rather than per port: two
// identical "executable file not found" lines say nothing the guidance below does
// not, and they push the part worth reading off the top of the output.
func reversePorts(cfg localstack.Config, withIssuer bool) {
	specs := []string{"tcp:" + portOf(cfg.VerifierHost)}
	if withIssuer {
		specs = append(specs, "tcp:"+portOf(cfg.IssuerURL))
	}

	var failed []string
	if _, err := exec.LookPath("adb"); err != nil {
		failed = specs
	} else {
		for _, spec := range specs {
			out, err := exec.Command("adb", "reverse", spec, spec).CombinedOutput()
			if err != nil {
				failed = append(failed, spec)
				fmt.Println("   adb reverse", spec, "failed:", firstLine(err, out))
				continue
			}
			fmt.Println("   adb reverse", spec, "-> this machine")
		}
	}

	if len(failed) > 0 {
		fmt.Println("   Run these first, or the phone resolves localhost to itself and the")
		fmt.Println("   wallet reports a connection error that reads like the containers")
		fmt.Println("   being down:")
		fmt.Println()
		for _, spec := range failed {
			fmt.Println("      adb reverse", spec, spec)
		}
	}
	fmt.Println()
}

// firstLine keeps a failure to one line: adb is chatty on stderr and the useful
// part is the first line.
func firstLine(err error, out []byte) string {
	text := strings.TrimSpace(string(out))
	if text == "" {
		return err.Error()
	}
	if i := strings.IndexAny(text, "\r\n"); i >= 0 {
		text = text[:i]
	}
	return text
}

// portOf extracts the port from a base URL, defaulting per scheme when it is
// implicit.
func portOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}
