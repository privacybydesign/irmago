// mdoc-e2e runs one age-verification credential through the real protocols: a
// credential is issued over OpenID4VCI by the EUDI reference issuer, then
// presented over OpenID4VP to the EUDI reference verifier, with a genuine wallet
// in the middle.
//
// It is the counterpart to mdoc-demo, which shows the same story at the mdoc
// format level in-process. This one adds everything mdoc-demo leaves out —
// credential offer, pre-authorized code, nonce endpoint, proof of possession,
// DCQL matching, the session transcript, the vp_token — by driving
// client.Client, the same wallet the app embeds. Nothing here is mocked: the two
// containers are the reference implementations, and what fails here fails on a
// phone too.
//
// It needs the docker stack up:
//
//	docker compose up -d
//
// Then, from the repository root:
//
//	go run ./yivi/cli/eudicli/mdoc-e2e
//
// A wallet lives in a temporary directory that is removed on exit, so repeated
// runs start from an empty wallet.
//
// The walkthrough goes to stdout and the wallet's own log to stderr, so the two
// can be read apart or together:
//
//	go run ./yivi/cli/eudicli/mdoc-e2e 2> e2e.log      # walkthrough on screen, log to a file
//	go run ./yivi/cli/eudicli/mdoc-e2e > /dev/null     # only the wallet's log
//	go run ./yivi/cli/eudicli/mdoc-e2e 2>&1 | tee e2e.log   # both, interleaved and saved
//
// Neither of those streams is the wallet's activity log — the entries the app
// shows the user, which live as rows in the SQLCipher database and are readable
// only through the wallet's own API. Step 7 dumps them as JSON, and -logs writes
// that dump somewhere it will outlive the run:
//
//	go run ./yivi/cli/eudicli/mdoc-e2e -logs mdoc-logs.json
package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/gabi/signed"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/client/clientsettings"
	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/crypto/encryption"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/yivi/cli/eudicli/internal/localstack"
	"github.com/privacybydesign/irmago/yivi/cli/eudicli/internal/mdocdecode"
)

const (
	docType   = "eu.europa.ec.av.1"
	namespace = docType

	credentialConfigID = "eu.europa.ec.eudi.age_verification_mdoc"

	// intendedUseID is what verifier v0.11.0 requires every transaction to name
	// unless it carries a relying-party registration certificate, which this
	// wallet does not produce. "1" is the use the image configures out of the box.
	intendedUseID = "1"

	queryID = "age"

	// How long to wait for the wallet to reach its next state. Generous: the
	// containers do real crypto and the issuer signs a batch.
	stateTimeout = 60 * time.Second
)

var (
	issuerURL    = flag.String("issuer", "https://localhost:8443/eudi-pid-issuer-py", "EUDI reference issuer, through the TLS proxy")
	verifierHost = flag.String("verifier", "http://127.0.0.1:8090", "EUDI reference verifier")
	testdataDir  = flag.String("testdata", "testdata", "path to the repository's testdata folder")
	logsFile     = flag.String("logs", "", "also write the wallet's activity log to this file as JSON")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nFAILED: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nIs the stack up? docker compose up -d — and if everything 502s,\n")
		fmt.Fprintf(os.Stderr, "docker compose restart tls_proxy (nginx caches upstream container IPs).\n")
		os.Exit(1)
	}
}

func run() error {
	// The wallet's own logging is left alone: it goes to stderr at info level and
	// is the actual record of what the protocols did — every HTTP call, the CRL
	// fetches, the session state changes. Redirect stderr to read it on its own,
	// which the package comment shows.
	if err := localstack.TrustProxyCertificate(stackConfig()); err != nil {
		return err
	}

	// ── 1. A wallet ─────────────────────────────────────────────────────
	section("1. A wallet, from scratch")

	wallet, err := newWallet()
	if err != nil {
		return err
	}
	defer wallet.close()
	fmt.Printf("  storage      : %s (removed on exit)\n", wallet.storagePath)
	fmt.Printf("  trusts       : the PID issuer's CA and the test verifier's CA\n")
	fmt.Printf("  credentials  : none yet\n")

	// ── 2. The issuer offers a credential ───────────────────────────────
	section("2. OpenID4VCI — the issuer makes an offer")

	offer, err := createOffer()
	if err != nil {
		return err
	}
	fmt.Printf("  configuration: %s\n", credentialConfigID)
	fmt.Printf("  docType      : %s\n", docType)
	fmt.Printf("  claims       : age_over_18=true, age_over_21=true\n")
	fmt.Printf("  grant        : pre-authorized code, tx_code %s\n", offer.TxCode)

	// ── 3. The wallet accepts it ────────────────────────────────────────
	section("3. The wallet redeems the offer")

	if err := wallet.issue(offer); err != nil {
		return err
	}

	credentials, err := wallet.client.GetCredentials()
	if err != nil {
		return fmt.Errorf("read credentials: %w", err)
	}
	stored := findCredential(credentials, docType)
	if stored == nil {
		return fmt.Errorf("the wallet holds no %s credential after issuance", docType)
	}
	fmt.Printf("\n  stored credential:\n")
	fmt.Printf("    id         : %s (the docType, taken from the signed MSO)\n", stored.CredentialId)
	for _, attr := range stored.Attributes {
		fmt.Printf("    attribute  : %v = %s\n", attr.ClaimPath, attributeValue(attr))
	}
	if remaining, ok := stored.BatchInstanceCountsRemaining[clientmodels.Format_MsoMdoc]; ok && remaining != nil {
		fmt.Printf("    instances  : %d unused (single-use attestations, spent one per presentation)\n", *remaining)
	}

	// ── 4. A verifier asks for one claim ────────────────────────────────
	section("4. OpenID4VP — a verifier asks for age_over_18 only")

	session, err := createVerifierSession()
	if err != nil {
		return err
	}
	fmt.Printf("  verifier  : %s\n", *verifierHost)
	fmt.Printf("  requested : [%s, age_over_18]\n", docType)
	fmt.Printf("  withheld  : age_over_21 — held by the wallet, not asked for\n")
	fmt.Printf("  client_id : %s\n", session.ClientID)

	// ── 5. The wallet answers ───────────────────────────────────────────
	section("5. The wallet shows the user what is being asked, then answers")

	if err := wallet.disclose(session.Link); err != nil {
		return err
	}

	// ── 6. What the verifier received ───────────────────────────────────
	section("6. What the verifier received")

	document, err := fetchPresentedDocument(session)
	if err != nil {
		return err
	}

	disclosed := map[string]any{}
	for _, item := range document.IssuerSigned.NameSpaces[namespace] {
		decoded, err := decodeIssuerSignedItem(item)
		if err != nil {
			return fmt.Errorf("decode disclosed item: %w", err)
		}
		disclosed[decoded.ElementIdentifier] = decoded.ElementValue
	}

	fmt.Printf("  docType          : %s\n", document.DocType)
	fmt.Printf("  deviceSigned     : present=%t (signed over this session's transcript)\n", document.DeviceSigned != nil)
	fmt.Printf("  disclosed items  : %d\n", len(document.IssuerSigned.NameSpaces[namespace]))
	for identifier, value := range disclosed {
		fmt.Printf("    %s = %v\n", identifier, value)
	}

	if _, leaked := disclosed["age_over_21"]; leaked {
		return fmt.Errorf("age_over_21 reached the verifier but was never requested")
	}
	fmt.Printf("\n  age_over_21 is absent: the wallet held it, the verifier did not ask, and the\n")
	fmt.Printf("  issuer's signature still verifies over what did arrive.\n")

	// ── 7. What the wallet wrote down ───────────────────────────────────
	section("7. The wallet's own activity log")

	if err := dumpActivityLog(wallet, *logsFile); err != nil {
		return err
	}

	// ── 8. The bytes ────────────────────────────────────────────────────
	section("8. The credential as it travelled")

	subsection("the disclosed item — Tag-24 wrapped, exactly as the issuer hashed it")
	mdocdecode.Dump(document.IssuerSigned.NameSpaces[namespace][0].EncodedItem)

	section("Done")
	fmt.Printf("  Issued over OpenID4VCI with two claims, presented over OpenID4VP with one,\n")
	fmt.Printf("  and accepted by the EUDI reference verifier.\n")
	return nil
}

// ============================================================================
// The wallet
// ============================================================================

type wallet struct {
	client      *client.Client
	states      chan clientmodels.SessionState
	storagePath string
	tempRoot    string
}

// newWallet builds a real client.Client over a throwaway storage directory,
// trusting the two test CAs. This mirrors what internal/sessiontest does for the
// integration tests; the wallet itself is the production one.
func newWallet() (*wallet, error) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	tempRoot, err := os.MkdirTemp("", "mdoc-e2e-")
	if err != nil {
		return nil, fmt.Errorf("create temp storage: %w", err)
	}
	storagePath := filepath.Join(tempRoot, "client")
	irmaConfigurationPath := filepath.Join(storagePath, "irma_configuration")
	eudiAppDataPath := filepath.Join(storagePath, "eudi")

	if err := common.CopyDirectory(filepath.Join(*testdataDir, "irma_configuration"), irmaConfigurationPath); err != nil {
		return nil, fmt.Errorf("copy irma_configuration (is -testdata correct?): %w", err)
	}
	if err := common.EnsureDirectoryExists(eudiAppDataPath); err != nil {
		return nil, fmt.Errorf("create eudi storage: %w", err)
	}

	// Trust anchors go in encrypted: the EUDI filesystem storage decrypts on read.
	middleware := encryption.NewAESEncryptionMiddleware(aesKey)
	trust := func(dir, name, source string) error {
		pem, err := os.ReadFile(source)
		if err != nil {
			return fmt.Errorf("read %s: %w", source, err)
		}
		path := filepath.Join(eudiAppDataPath, dir, "certificates")
		if err := common.EnsureDirectoryExists(path); err != nil {
			return err
		}
		encrypted, err := middleware.Encrypt(pem)
		if err != nil {
			return err
		}
		return common.SaveFile(filepath.Join(path, name), encrypted)
	}
	if err := trust("issuers", "pid-issuer-ca.pem", filepath.Join(*testdataDir, "eudi-pid-issuer-py", "certs", "ca.pem")); err != nil {
		return nil, err
	}
	if err := trust("verifiers", "verifier-ca.pem", filepath.Join(*testdataDir, "eudi", "verifier", "ca.crt")); err != nil {
		return nil, err
	}

	states := make(chan clientmodels.SessionState, 32)
	signer, err := newSigner()
	if err != nil {
		return nil, err
	}

	c, err := client.New(storagePath, irmaConfigurationPath, eudiAppDataPath,
		&quietHandler{}, &channelSessionHandler{states: states}, signer, aesKey, "en")
	if err != nil {
		return nil, fmt.Errorf("create wallet: %w", err)
	}
	// Developer mode relaxes HTTP and the certificate verification mode, which
	// the local containers need; it does not relax attribute authorization.
	c.SetPreferences(clientsettings.Preferences{DeveloperMode: true})

	return &wallet{client: c, states: states, storagePath: storagePath, tempRoot: tempRoot}, nil
}

func (w *wallet) close() {
	w.client.Close()
	_ = os.RemoveAll(w.tempRoot)
}

// await blocks until the wallet reports a state, failing on an error state so a
// broken run stops at the step that broke rather than on a later timeout.
func (w *wallet) await(want clientmodels.SessionStatus) (clientmodels.SessionState, error) {
	for {
		select {
		case state := <-w.states:
			if state.Status == clientmodels.Status_Error {
				detail := ""
				if state.Error != nil {
					detail = state.Error.WrappedError
				}
				return state, fmt.Errorf("session failed while waiting for %q: %s", want, detail)
			}
			if state.Status == want {
				return state, nil
			}
			// Intermediate states (Communicating, and so on) are not interesting here.
		case <-time.After(stateTimeout):
			return clientmodels.SessionState{}, fmt.Errorf("timed out waiting for session status %q", want)
		}
	}
}

// issue drives the pre-authorized OpenID4VCI flow to completion.
func (w *wallet) issue(offer *offerResponse) error {
	request, err := json.Marshal(client.SessionRequestData{
		Qr:       irma.Qr{URL: offer.URI},
		Protocol: clientmodels.Protocol_OpenID4VCI,
		// Required even for a pre-authorized offer: the wallet refuses a session
		// that could not complete an authorization-code flow if the offer turned
		// out to need one. The app registers this as its callback URL.
		OpenID4VCIRedirectUri: "https://open.yivi.app/-/auth-callback",
	})
	if err != nil {
		return fmt.Errorf("build session request: %w", err)
	}
	w.client.NewSession(1, string(request))

	if _, err := w.await(clientmodels.Status_RequestPreAuthorizedCode); err != nil {
		return err
	}
	fmt.Printf("  wallet asks the user for the transaction code, and is given %s\n", offer.TxCode)
	go func() {
		_ = w.client.HandleUserInteraction(clientmodels.SessionUserInteraction{
			SessionId: 1,
			Type:      clientmodels.UI_PreAuthorizedCode,
			Payload: clientmodels.SessionPreAuthorizedCodeInteractionPayload{
				Proceed:         true,
				TransactionCode: &offer.TxCode,
			},
		})
	}()

	state, err := w.await(clientmodels.Status_RequestPermission)
	if err != nil {
		return err
	}
	for _, offered := range state.OfferedCredentials {
		name := offered.Name
		if name == "" {
			name = offered.CredentialId + " (the issuer publishes no display metadata)"
		}
		fmt.Printf("  wallet shows the offer to the user: %s\n", name)
	}
	fmt.Printf("  user accepts\n")
	go func() {
		_ = w.client.HandleUserInteraction(clientmodels.SessionUserInteraction{
			SessionId: 1,
			Type:      clientmodels.UI_Permission,
			Payload:   clientmodels.SessionPermissionInteractionPayload{Granted: true},
		})
	}()

	if _, err := w.await(clientmodels.Status_Success); err != nil {
		return err
	}
	fmt.Printf("  issuance succeeded — the wallet verified the MSO against the issuer's chain\n")
	fmt.Printf("  before storing anything\n")
	return nil
}

// disclose drives the OpenID4VP flow, consenting to whatever the plan offers.
func (w *wallet) disclose(link string) error {
	request, err := json.Marshal(client.SessionRequestData{
		Qr:       irma.Qr{Type: irma.ActionDisclosing, URL: link},
		Protocol: clientmodels.Protocol_OpenID4VP,
	})
	if err != nil {
		return fmt.Errorf("build session request: %w", err)
	}
	w.client.NewSession(2, string(request))

	state, err := w.await(clientmodels.Status_RequestPermission)
	if err != nil {
		return err
	}
	if state.DisclosurePlan == nil || len(state.DisclosurePlan.DisclosureChoicesOverview) == 0 {
		return fmt.Errorf("the wallet has nothing to disclose for this request")
	}

	fmt.Printf("  verifier   : %s\n", state.Requestor.Name)
	overview := state.DisclosurePlan.DisclosureChoicesOverview[0]
	if len(overview.OwnedOptions) == 0 {
		return fmt.Errorf("the wallet holds no credential satisfying the request")
	}
	chosen := overview.OwnedOptions[0]
	for _, credential := range chosen.Credentials {
		for _, attr := range credential.Attributes {
			if attr.Value == nil {
				continue // section header, not a value
			}
			fmt.Printf("  will share : %v = %s\n", attr.ClaimPath, attributeValue(attr))
		}
	}
	fmt.Printf("  user consents\n")

	go func() {
		_ = w.client.HandleUserInteraction(clientmodels.SessionUserInteraction{
			SessionId: 2,
			Type:      clientmodels.UI_Permission,
			Payload: clientmodels.SessionPermissionInteractionPayload{
				Granted:           true,
				DisclosureChoices: []clientmodels.DisclosureDisconSelection{disclosureChoice(chosen)},
			},
		})
	}()

	if _, err := w.await(clientmodels.Status_Success); err != nil {
		return err
	}
	fmt.Printf("  disclosure succeeded — the verifier accepted the DeviceResponse\n")
	return nil
}

// disclosureChoice turns the plan's option into the selection the wallet expects
// back, dropping the section headers the UI shows but that carry no value.
func disclosureChoice(bundle *clientmodels.DisclosureBundle) clientmodels.DisclosureDisconSelection {
	credentials := make([]clientmodels.SelectedCredential, 0, len(bundle.Credentials))
	for _, option := range bundle.Credentials {
		var paths [][]any
		for _, attr := range option.Attributes {
			if attr.Value == nil {
				continue
			}
			paths = append(paths, attr.ClaimPath)
		}
		credentials = append(credentials, clientmodels.SelectedCredential{
			CredentialId:   option.CredentialId,
			CredentialHash: option.Hash,
			AttributePaths: paths,
		})
	}
	return clientmodels.DisclosureDisconSelection{Credentials: credentials}
}

// ============================================================================
// The issuer and verifier, over HTTP
// ============================================================================

type offerResponse = localstack.Offer

// createOffer asks the reference issuer for a credential offer. The element set
// is this demo's own choice: age_over_18 deliberately false, so the run proves
// the verifier's value constraint below is actually enforced rather than
// coincidentally satisfied.
func createOffer() (*offerResponse, error) {
	return localstack.CreateOffer(stackConfig(), localstack.AVCredentialConfigID,
		localstack.DefaultAVElements())
}

type verifierSession = localstack.Session

// createVerifierSession starts a presentation at the reference verifier, asking
// for one element, and returns the link a wallet would receive by QR.
//
// The value constraint is false to match what createOffer minted: a demo that
// asked for true against a false credential would show the refusal path, which
// is a different demo.
func createVerifierSession() (*verifierSession, error) {
	req := localstack.NewSessionRequest(docType, "age_over_18")
	req.QueryID = queryID
	req.Namespace = namespace
	req.IntendedUseID = intendedUseID
	wantFalse := false
	req.Value = &wantFalse
	return localstack.CreateSession(stackConfig(), req)
}

// stackConfig points the shared helpers at whatever this run's flags say.
func stackConfig() localstack.Config {
	return localstack.Config{
		IssuerURL:    *issuerURL,
		VerifierHost: *verifierHost,
		TestdataDir:  *testdataDir,
	}
}

// fetchPresentedDocument reads the wallet's answer back from the verifier and
// decodes the single document inside its vp_token.
func fetchPresentedDocument(session *verifierSession) (*stdmdoc.MDoc, error) {
	resp, err := http.Get(*verifierHost + "/ui/presentations/" + session.TransactionID)
	if err != nil {
		return nil, fmt.Errorf("fetch wallet response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verifier has no wallet response: HTTP %d", resp.StatusCode)
	}

	var walletResponse map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&walletResponse); err != nil {
		return nil, fmt.Errorf("decode wallet response: %w", err)
	}

	vpToken, ok := walletResponse["vp_token"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("wallet response carries no vp_token")
	}
	entry, ok := vpToken[queryID]
	if !ok {
		return nil, fmt.Errorf("vp_token carries no entry for query %q", queryID)
	}
	encoded, ok := entry.(string)
	if !ok {
		list, isList := entry.([]any)
		if !isList || len(list) != 1 {
			return nil, fmt.Errorf("unexpected vp_token shape %T", entry)
		}
		if encoded, ok = list[0].(string); !ok {
			return nil, fmt.Errorf("unexpected vp_token entry %T", list[0])
		}
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		if raw, err = base64.StdEncoding.DecodeString(encoded); err != nil {
			return nil, fmt.Errorf("decode vp_token: %w", err)
		}
	}

	var response stdmdoc.DeviceResponse
	if err := cbor.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("decode DeviceResponse: %w", err)
	}
	if len(response.Documents) != 1 {
		return nil, fmt.Errorf("expected one document, got %d", len(response.Documents))
	}
	return &response.Documents[0], nil
}

// decodeIssuerSignedItem unwraps one Tag-24 item into its fields.
func decodeIssuerSignedItem(item stdmdoc.Tag24Item) (*stdmdoc.IssuerSignedItem, error) {
	var tagged cbor.RawTag
	if err := cbor.Unmarshal(item.EncodedItem, &tagged); err != nil {
		return nil, err
	}
	var inner []byte
	if err := cbor.Unmarshal(tagged.Content, &inner); err != nil {
		return nil, err
	}
	var decoded stdmdoc.IssuerSignedItem
	if err := cbor.Unmarshal(inner, &decoded); err != nil {
		return nil, err
	}
	return &decoded, nil
}

// ============================================================================
// Wallet plumbing the app would otherwise provide
// ============================================================================

type channelSessionHandler struct {
	states chan clientmodels.SessionState
}

func (h *channelSessionHandler) UpdateSession(state clientmodels.SessionState) {
	h.states <- state
}

// quietHandler absorbs the callbacks the app would act on. Errors are printed
// because a silent one here is indistinguishable from a hang.
type quietHandler struct{}

func (*quietHandler) CredentialsChanged()                                   {}
func (*quietHandler) ReportError(err error)                                 { fmt.Printf("  [wallet] %v\n", err) }
func (*quietHandler) EnrollmentSuccess(irma.SchemeManagerIdentifier)        {}
func (*quietHandler) EnrollmentFailure(irma.SchemeManagerIdentifier, error) {}
func (*quietHandler) ChangePinSuccess()                                     {}
func (*quietHandler) ChangePinFailure(irma.SchemeManagerIdentifier, error)  {}
func (*quietHandler) ChangePinIncorrect(irma.SchemeManagerIdentifier, int)  {}
func (*quietHandler) ChangePinBlocked(irma.SchemeManagerIdentifier, int)    {}

type ecdsaSigner struct {
	key *ecdsa.PrivateKey
}

func newSigner() (irmaclient.Signer, error) {
	key, err := signed.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &ecdsaSigner{key: key}, nil
}

func (s *ecdsaSigner) PublicKey(string) ([]byte, error) {
	return signed.MarshalPublicKey(&s.key.PublicKey)
}

func (s *ecdsaSigner) Sign(_ string, message []byte) ([]byte, error) {
	return signed.Sign(s.key, message)
}

// ============================================================================
// The activity log
// ============================================================================

// dumpActivityLog reads back the entries the wallet wrote for the two sessions
// above and prints them, as a summary and then as JSON.
//
// This is the only view of those entries there is. They are rows in
// eudi_log_entries / eudi_log_credentials inside the SQLCipher database, which is
// encrypted with the wallet's AES key, so sqlite3 cannot open it and neither
// stdout nor the wallet's stderr log carries their contents — the log a session
// writes and the log lines a session prints are unrelated things. Reading them
// means going through Client.LoadNewestLogs, holding the key, which is what this
// does.
//
// The write path is format-agnostic (CredentialToLogCredential for issuance,
// MdocDcqlHandler.buildLogCredential for the disclosure), so what shows up here
// is also what the app's activity screen shows for an mdoc.
func dumpActivityLog(w *wallet, path string) error {
	logs, err := w.client.LoadNewestLogs(100)
	if err != nil {
		return fmt.Errorf("read activity log: %w", err)
	}

	// Newest first, and this wallet never enrolled with a keyshare server, so
	// there are no IRMA entries mixed in: the disclosure, then the issuance.
	fmt.Printf("  entries   : %d (newest first)\n", len(logs))
	for _, entry := range logs {
		fmt.Printf("\n  %s at %s\n", entry.Type, entry.Time.Format(time.RFC3339))
		switch {
		case entry.IssuanceLog != nil:
			fmt.Printf("    protocol : %s\n", entry.IssuanceLog.Protocol)
			printLogParty("issuer", entry.IssuanceLog.Issuer)
			printLogCredentials(entry.IssuanceLog.Credentials)
		case entry.DisclosureLog != nil:
			fmt.Printf("    protocol : %s\n", entry.DisclosureLog.Protocol)
			printLogParty("verifier", entry.DisclosureLog.Verifier)
			printLogCredentials(entry.DisclosureLog.Credentials)
		case entry.RemovalLog != nil:
			printLogCredentials(entry.RemovalLog.Credentials)
		}
	}

	// Only the disclosure entry names age_over_18 alone. The issuance entry lists
	// both claims, because the wallet was given both — the selective part of the
	// story happened at presentation time, and the two entries together are where
	// a user can see that.
	redactImages(logs)
	dump, err := json.MarshalIndent(logs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal activity log: %w", err)
	}

	// Indented for the walkthrough only when printed; the file gets the JSON as
	// it is, so it stays diffable and parseable.
	subsection("the entries as JSON, logo payloads elided")
	fmt.Printf("  %s\n", strings.ReplaceAll(string(dump), "\n", "\n  "))

	if path == "" {
		fmt.Printf("\n  pass -logs <file> to keep this dump; the wallet's storage does not survive\n")
		fmt.Printf("  the run, so the database it came from is about to be deleted.\n")
		return nil
	}
	if err := os.WriteFile(path, append(dump, '\n'), 0600); err != nil {
		return fmt.Errorf("write activity log to %s: %w", path, err)
	}
	fmt.Printf("\n  written to %s\n", path)
	return nil
}

func printLogParty(role string, party *clientmodels.TrustedParty) {
	if party == nil {
		return
	}
	name := party.Name
	if name == "" {
		name = "(no display name published)"
	}
	fmt.Printf("    %-9s: %s [%s]\n", role, name, party.Id)
}

func printLogCredentials(credentials []clientmodels.LogCredential) {
	for _, credential := range credentials {
		fmt.Printf("    credential: %s %v\n", credential.CredentialId, credential.Formats)
		for _, attr := range credential.Attributes {
			fmt.Printf("      %v = %s\n", attr.ClaimPath, attributeValue(attr))
		}
	}
}

// redactImages replaces logo payloads with a size marker, in place.
//
// A logo is stored base64 in the entry and re-resolved from disk on every read,
// so one credential with a bitmap logo would bury the whole dump under a single
// unreadable string. The marker keeps the fact that a logo is attached, which is
// the part worth seeing, and drops the kilobytes.
func redactImages(logs []clientmodels.LogInfo) {
	redactParty := func(party *clientmodels.TrustedParty) {
		// Walks the parent chain: a scheme-verified issuer carries its trust chain
		// as nested parties, each able to have its own logo.
		for ; party != nil; party = party.Parent {
			redactImage(party.Image)
		}
	}
	redactCredentials := func(credentials []clientmodels.LogCredential) {
		for i := range credentials {
			redactImage(credentials[i].Image)
			redactParty(&credentials[i].Issuer)
		}
	}
	for _, entry := range logs {
		if log := entry.IssuanceLog; log != nil {
			redactCredentials(log.Credentials)
			redactCredentials(log.DisclosedCredentials)
			redactParty(log.Issuer)
		}
		if log := entry.DisclosureLog; log != nil {
			redactCredentials(log.Credentials)
			redactParty(log.Verifier)
		}
		if log := entry.RemovalLog; log != nil {
			redactCredentials(log.Credentials)
		}
	}
}

func redactImage(image *clientmodels.Image) {
	if image == nil || image.Base64 == "" {
		return
	}
	mimeType := "unknown type"
	if image.MimeType != nil {
		mimeType = *image.MimeType
	}
	image.Base64 = fmt.Sprintf("<%d base64 chars of %s, elided>", len(image.Base64), mimeType)
}

// ============================================================================
// Output
// ============================================================================

func findCredential(credentials []*clientmodels.Credential, id string) *clientmodels.Credential {
	for _, credential := range credentials {
		if credential.CredentialId == id {
			return credential
		}
	}
	return nil
}

func attributeValue(attr clientmodels.Attribute) string {
	switch {
	case attr.Value == nil:
		return "(no value)"
	case attr.Value.Bool != nil:
		return fmt.Sprintf("%t", *attr.Value.Bool)
	case attr.Value.String != nil:
		return *attr.Value.String
	case attr.Value.Int != nil:
		return fmt.Sprintf("%d", *attr.Value.Int)
	default:
		return "(unprintable)"
	}
}

func section(title string) {
	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("─", len(title)))
}

func subsection(title string) {
	fmt.Printf("\n  %s\n  %s\n\n", title, strings.Repeat("-", len(title)))
}
