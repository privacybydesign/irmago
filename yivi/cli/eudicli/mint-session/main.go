// mint-session starts a presentation (and optionally an issuance) against the
// local EUDI containers and prints the commands needed to drive a real phone
// through them.
//
// Its request-building lives in localstack.go beside this file rather than inline
// here, so the links a device is handed are built by the same code that talks to
// the containers -- which had drifted, when this logic existed twice.
//
// Usage, from the repository root:
//
//	go run ./yivi/cli/eudicli/mint-session                    presentation only
//	go run ./yivi/cli/eudicli/mint-session -issue             issuance too
//	go run ./yivi/cli/eudicli/mint-session -value false       ask for false
//	go run ./yivi/cli/eudicli/mint-session -value any         no constraint
//
// -value constrains the DCQL query only. What -issue mints is
// DefaultAVElements unless -mint says otherwise, so the offer and the
// query can be made to disagree on purpose -- which is what testing a refusal
// requires.
//
//	go run ./yivi/cli/eudicli/mint-session -element age_over_40
//	go run ./yivi/cli/eudicli/mint-session -issue -mint age_over_42=true
//	go run ./yivi/cli/eudicli/mint-session -issue -mint "age_over_18=false,age_over_40=false"
//
// -show-query prints the DCQL query as sent. There is no other way to read it: the
// request object is single use, so fetching it to decode the query leaves nothing
// for the phone, and the verifier answers 400 until the wallet responds.
//
//	go run ./yivi/cli/eudicli/mint-session -show-query
//
// Re-issuing claims the wallet already holds is refused while the stored
// credential is still presentable and accepted once it is spent or expired, so
// -issue is the renewal path rather than a way to obtain a second identical
// credential.
//
// The issuer mints whatever -mint asks for, including element names absent from
// its advertised claim set. Presenting one is a separate matter: the relying
// party certificate's authorized set decides what may be requested, so an
// unadvertised element can be issued and then never asked for. See
// testdata/eudi/verifier/README.md for widening that set.
//
// The one-time code is never in the offer link -- see
// stripTransactionCodeValue. By default it is printed here; -email
// sends it instead, so the demo can show the code arriving on a channel the link
// did not travel on:
//
//	go run ./yivi/cli/eudicli/mint-session -issue -email
//
// That goes to the compose stack's mailhog, which captures mail and delivers
// none -- read it at http://localhost:8025. No address is needed because mailhog
// treats every recipient alike. To deliver for real, point -smtp at a relay and
// name a recipient, with credentials from the environment so they stay out of
// shell history:
//
//	SMTP_USERNAME=... SMTP_PASSWORD=... go run ./yivi/cli/eudicli/mint-session \
//	    -issue -email -mail-to you@example.com -smtp smtp.example.com:587
//
// Prerequisites: the compose stack up, and adb reverse for 8090 (verifier) plus
// 8443 (issuer, only needed with -issue). The app needs developer mode on, and
// must be unlocked when a link arrives -- a locked app queues it at the PIN
// screen, which looks like nothing happening.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

var (
	issuerURL    = flag.String("issuer", "https://localhost:8443/eudi-pid-issuer-py", "EUDI reference issuer, through the TLS proxy")
	verifierHost = flag.String("verifier", "http://127.0.0.1:8090", "EUDI reference verifier")
	testdataDir  = flag.String("testdata", "testdata", "path to the repository's testdata folder")

	docType = flag.String("doctype", "eu.europa.ec.av.1", "mdoc docType to request")
	element = flag.String("element", "age_over_18", "element to request")
	value   = flag.String("value", "true", `query value constraint: "true", "false", or "any" to omit it. Does not affect what -issue mints`)

	issue = flag.Bool("issue", false, "also mint a credential offer, so the credential can be installed first")
	mint  = flag.String("mint", "", `what -issue puts in the credential, as "age_over_18=true,age_over_40=false". Empty mints DefaultAVElements. Independent of -element/-value, which constrain the query`)

	reverse = flag.Bool("reverse", true, "run adb reverse for the verifier and issuer ports first, so localhost on the phone reaches this machine")

	// The code is never in the offer link. Printing it to the terminal is the
	// default because it keeps a solo run to one window; -email exists to show
	// the code arriving somewhere the link did not, which is the property a
	// transaction code depends on and the thing a terminal print cannot show.
	//
	// A bool rather than taking the address directly: against the default
	// mailhog every address behaves identically, because it captures mail and
	// delivers none, so requiring one would be asking for a value that changes
	// nothing. The address only starts to matter once -smtp points at a relay
	// that really delivers, which is what -mail-to is for.
	email    = flag.Bool("email", false, "send the one-time code by mail instead of printing it (needs -issue)")
	mailTo   = flag.String("mail-to", "demo@localhost", "recipient for -email; only meaningful when -smtp is a relay that actually delivers")
	smtpAddr = flag.String("smtp", "localhost:1025", "SMTP server for -email; the default is the compose stack's mailhog, read at http://localhost:8025")
	mailFrom = flag.String("mail-from", "yivi-demo@localhost", "envelope sender for -email")

	// The decoder is named in the printed command rather than invoked, because the
	// point is to hand over something runnable after the phone has answered.
	decoder = flag.String("decoder", "", "path to a prebuilt vptoken-decode binary to name in the verify command")

	// Printed from DcqlQuery rather than read back from the session,
	// because reading it back is not possible without destroying it: request_uri
	// is single use, so fetching the request object to decode the query leaves
	// nothing for the phone to fetch. The verifier cannot answer either -- it
	// returns 400 until the wallet responds, and keeps no record across a restart.
	showQuery = flag.Bool("show-query", false, "also print the DCQL query being sent, which is otherwise only readable by consuming the single-use request object")
)

func main() {
	flag.Parse()

	// Caught here rather than ignored: -email without -issue mints no offer, so
	// there is no code to send, and silently doing nothing would read as a broken
	// mail setup.
	if *email && !*issue {
		fail(fmt.Errorf("-email needs -issue: without an issuance there is no one-time code to send"))
	}

	cfg := Config{
		IssuerURL:    *issuerURL,
		VerifierHost: *verifierHost,
		TestdataDir:  *testdataDir,
	}

	if _, err := os.Stat(cfg.IssuerCAPath()); err != nil {
		fail(fmt.Errorf("issuer CA not found at %s: run from the repository root, or pass -testdata", cfg.IssuerCAPath()))
	}

	// Only the issuer is behind TLS, so without this a presentation-only run
	// works and -issue fails as an unknown authority.
	if err := TrustProxyCertificate(cfg); err != nil {
		fail(err)
	}

	if *reverse {
		reversePorts(cfg, *issue)
	}

	// The constraint applies to the query only. What gets issued is whatever
	// DefaultAVElements says and nothing else: an offer that silently
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
		// DefaultAVElements unless -mint overrides it.
		//
		// -mint is a flag of its own rather than something -value feeds into.
		// That separation is the point: -value constrains the query and -mint
		// decides the credential, so the two can be made to disagree on purpose,
		// which is what testing a refusal needs. A single flag driving both
		// would make every run agree with itself and quietly remove the ability
		// to test that value constraints are enforced at all.
		data := DefaultAVElements()
		if *mint != "" {
			parsed, err := parseMintElements(*mint)
			if err != nil {
				fail(err)
			}
			data = parsed
		}
		offer, err := CreateOffer(cfg, AVCredentialConfigID, data)
		if err != nil {
			fail(fmt.Errorf("create offer: %w", err))
		}
		delivered := "one-time code: " + offer.TxCode
		if *email {
			if err := mailTransactionCode(offer.TxCode); err != nil {
				// Failing here rather than falling back to printing: a run that
				// quietly printed the code after being asked to mail it would
				// demonstrate exactly the thing -email exists to avoid, and the
				// operator would have no reason to look at the difference.
				fail(fmt.Errorf("mail the one-time code to %s via %s: %w", *mailTo, *smtpAddr, err))
			}
			delivered = "one-time code sent to " + *mailTo
		}

		fmt.Printf("%d. ISSUANCE            %s\n\n", step, delivered)
		printAdbCommand(offer.URI)
		switch {
		case *email && isMailhog(*smtpAddr):
			// Said plainly because it has surprised someone: mailhog captures
			// mail and delivers none, so a real-looking address in -mail-to
			// never receives anything and waiting on that inbox is a dead end.
			fmt.Printf("\n   Read the code at http://localhost:8025 -- mailhog captured it and\n")
			fmt.Printf("   delivers nothing, so it did not reach %s or any other inbox.\n", *mailTo)
			fmt.Printf("   Then unlock the app, enter it at the prompt and accept.\n")
			fmt.Printf("   It is not in the link above.\n")
		case *email:
			fmt.Printf("\n   Read the code from %s, then unlock the app, enter it at the\n", *mailTo)
			fmt.Printf("   one-time code prompt and accept. It is not in the link above.\n")
		default:
			fmt.Printf("\n   Unlock the app, enter %s at the one-time code prompt, accept.\n", offer.TxCode)
		}
		fmt.Printf("   credential will hold: %s\n\n", describe(data))
		step++
	}

	req := NewSessionRequest(*docType, *element)
	if !unconstrained {
		req.Value = &wantValue
	}

	session, err := CreateSession(cfg, req)
	if err != nil {
		fail(fmt.Errorf("create session: %w", err))
	}

	constraint := "any value"
	if req.Value != nil {
		constraint = fmt.Sprintf("must equal %t", *req.Value)
	}
	fmt.Printf("%d. PRESENTATION         %s / %s, %s\n\n", step, *docType, *element, constraint)
	if *showQuery {
		printDcqlQuery(req)
	}
	printAdbCommand(session.Link)
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

	verify := fmt.Sprintf("%s -s %s/ui/presentations/%s | ", curlCommand(), *verifierHost, session.TransactionID)
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

// curlCommand names the curl a printed command can actually be pasted into a
// shell with.
//
// On Windows PowerShell, `curl` is an alias for Invoke-WebRequest, which has no
// -s and takes -Uri: pasting `curl -s <url>` there discards the URL and prompts
// interactively for one, which reads as the tool having printed a broken command.
// `curl.exe` is the binary Windows 10+ ships and resolves from PowerShell, cmd and
// Git Bash alike. Everywhere else plain curl is right.
func curlCommand() string {
	if runtime.GOOS == "windows" {
		return "curl.exe"
	}
	return "curl"
}

// printAdbCommand prints the adb command for a link, or fails the run. A link
// this tool cannot quote safely is not something to warn about and continue past:
// the command is the entire output, and printing a broken one is worse than
// printing none.
func printAdbCommand(link string) {
	command, err := AdbCommand(link)
	if err != nil {
		fail(err)
	}
	fmt.Println(command)
}

// printDcqlQuery prints the dcql_query this session carries, indented, from the
// same builder CreateSession uses -- so it shows what was sent rather than a
// reconstruction of it.
//
// This is the query as the verifier receives it. What the wallet sees is this
// object embedded in the signed request object it fetches from request_uri,
// alongside nonce, response_uri, response_mode and client_metadata.
func printDcqlQuery(req SessionRequest) {
	encoded, err := json.MarshalIndent(DcqlQuery(req), "   ", "  ")
	if err != nil {
		// Not fatal: the links below are the point of the run, and losing the
		// query dump is no reason to withhold them.
		fmt.Printf("   (could not render the DCQL query: %v)\n\n", err)
		return
	}
	fmt.Printf("   dcql_query: %s\n\n", encoded)
}

// parseMintElements turns -mint's "name=bool,name=bool" into the element map the
// issuer is handed.
//
// Values are booleans only, because every element of the AV profile is one. A
// non-boolean is refused rather than passed through as a string: the issuer does
// not validate what it is asked to mint -- it accepts any element name and any
// value, including ones absent from its own advertised claim set -- so a typo
// here would be minted silently and only surface much later as a credential that
// does not match any query.
//
// Element *names* are deliberately not checked against the issuer's advertised
// set. Minting something unadvertised is a legitimate thing to want to test, and
// the interesting boundary is not at issuance anyway: the relying party
// certificate's authorized set decides what can be asked for, so an element
// minted here that no certificate authorizes simply can never be presented.
func parseMintElements(spec string) (map[string]any, error) {
	elements := map[string]any{}
	for pair := range strings.SplitSeq(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, rawValue, found := strings.Cut(pair, "=")
		if !found {
			return nil, fmt.Errorf(`-mint entry %q must be name=value, e.g. "age_over_18=true"`, pair)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("-mint entry %q has an empty element name", pair)
		}
		switch strings.ToLower(strings.TrimSpace(rawValue)) {
		case "true":
			elements[name] = true
		case "false":
			elements[name] = false
		default:
			return nil, fmt.Errorf("-mint value for %q must be true or false, got %q", name, rawValue)
		}
	}
	if len(elements) == 0 {
		return nil, fmt.Errorf("-mint parsed to no elements; pass at least one name=value pair")
	}
	return elements, nil
}

// mailTransactionCode sends the one-time code to -email over -smtp.
//
// Unauthenticated by default, because the default target is the compose stack's
// mailhog, which accepts anything and delivers nothing -- it captures mail for
// reading at http://localhost:8025. That is the whole point for a demo: it needs
// no account, no API key and no outbound network, and the code still leaves the
// link's channel, which is the property being demonstrated.
//
// Credentials are read from the environment when present, so the same flag can
// point at a real relay without either putting a password in a shell history or
// teaching this tool about any particular provider.
func mailTransactionCode(code string) error {
	host, _, err := net.SplitHostPort(*smtpAddr)
	if err != nil {
		return fmt.Errorf("-smtp must be host:port, got %q: %w", *smtpAddr, err)
	}

	var auth smtp.Auth
	if user := os.Getenv("SMTP_USERNAME"); user != "" {
		auth = smtp.PlainAuth("", user, os.Getenv("SMTP_PASSWORD"), host)
	}

	// Assembled by hand rather than through a mail library: this is a fixed
	// three-header message with an ASCII body, and the dependency would buy
	// nothing. CRLF line endings are required by RFC 5322, and a bare LF is
	// rejected by stricter servers than mailhog.
	message := strings.Join([]string{
		"From: " + *mailFrom,
		"To: " + *mailTo,
		"Subject: Yivi demo: your one-time code is " + code,
		"",
		"One-time code: " + code,
		"",
		"Enter this at the prompt after opening the credential offer.",
		"It is deliberately not part of the offer link -- a code carried",
		"inside the link it protects would protect nothing.",
		"",
	}, "\r\n")

	if err := smtp.SendMail(*smtpAddr, auth, *mailFrom, []string{*mailTo}, []byte(message)); err != nil {
		return err
	}
	return nil
}

// isMailhog reports whether -smtp still points at the compose stack's catcher,
// so the run can say where to read the mail. A real relay gets no such line,
// because there the mail actually goes to the recipient.
func isMailhog(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return port == "1025" && (host == "localhost" || host == "127.0.0.1" || host == "mailhog" || host == "mailhog.localhost")
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
func reversePorts(cfg Config, withIssuer bool) {
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
