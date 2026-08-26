// Package localstack drives the EUDI reference containers that docker-compose.yml
// brings up: asking the Python issuer for a credential offer, starting a
// presentation at the Kotlin verifier, and reading the wallet's answer back.
//
// It exists so those calls live in one place. mdoc-e2e had them inline, and the
// moment a second caller wanted a session the request shape started drifting
// between copies -- a different nonce here, a different value constraint there,
// which is exactly the kind of difference that makes two runs disagree for
// reasons unrelated to the wallet.
//
// Three things every session request must get right, each of which cost real
// debugging time to establish:
//
//   - intended_use_id is mandatory since verifier v0.11.0. Absent, the verifier
//     answers 400 MissingRegistrationCertificate; unrecognised, 400
//     UnknownIntendedUseId.
//   - request_uri_method must be "get". The verifier enforces whichever method
//     the transaction was created with, and irmago only ever GETs the request
//     object, so "post" fails at the wallet's fetch with HTTP 400.
//   - issuer_chain must name the CA that issued the credential in the wallet.
//     Passing the wrong one lets the wallet disclose happily and then has the
//     verifier refuse the response with X5CNotTrusted.
package localstack

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Config locates the containers and the repository's testdata.
type Config struct {
	// IssuerURL is the Python PID issuer, reachable only through the TLS proxy,
	// e.g. https://localhost:8443/eudi-pid-issuer-py.
	IssuerURL string
	// VerifierHost is the Kotlin verifier, e.g. http://127.0.0.1:8090.
	VerifierHost string
	// TestdataDir is the repository's testdata folder, read for the issuer CA.
	TestdataDir string
}

// DefaultConfig matches docker-compose.yml with the repository as the working
// directory.
func DefaultConfig() Config {
	return Config{
		IssuerURL:    "https://localhost:8443/eudi-pid-issuer-py",
		VerifierHost: "http://127.0.0.1:8090",
		TestdataDir:  "testdata",
	}
}

// IssuerCAPath is the anchor a verifier must be given to accept credentials the
// local Python issuer signed: CN=Yivi Test EUDI Root CA.
func (c Config) IssuerCAPath() string {
	return filepath.Join(c.TestdataDir, "eudi-pid-issuer-py", "certs", "ca.pem")
}

// SessionRequest describes the presentation to ask for. The zero value is not
// usable; use NewSessionRequest and adjust.
type SessionRequest struct {
	DocType string
	// QueryID is the DCQL credential id, and the key the vp_token comes back
	// under.
	QueryID string
	// Namespace defaults to DocType when empty, which is what the AV profile
	// does; an mDL would differ.
	Namespace string
	Element   string
	// Value is the DCQL value constraint. Nil omits the constraint entirely, so
	// any value satisfies the query -- a real distinction: with a constraint the
	// wallet refuses to match a credential holding the other value, which is the
	// only way a verifier can insist on "true" rather than merely ask.
	Value *bool
	// IntendedUseID selects the verifier's configured use case.
	IntendedUseID string
	// Nonce ties the response to this request and travels into the mdoc
	// SessionTranscript, so the device signature covers it. Empty means generate
	// a fresh random one, which is what a real deployment does; pin it only when
	// reproducible bytes matter, as the integration tests want.
	Nonce string
}

// NewSessionRequest returns a request for one element of the AV attestation,
// with the fields that must not be wrong already filled in.
func NewSessionRequest(docType, element string) SessionRequest {
	return SessionRequest{
		DocType:       docType,
		QueryID:       "age",
		Element:       element,
		IntendedUseID: "1",
	}
}

// Session is a started presentation, as the verifier reported it.
type Session struct {
	TransactionID    string
	ClientID         string
	RequestURI       string
	RequestURIMethod string
	// Link is what a wallet would receive by QR or deep link.
	Link string
}

// DcqlQuery builds the dcql_query object CreateSession sends, applying the same
// defaults it does: an empty Namespace means the docType, and an empty QueryID
// means "age".
//
// Exported so a caller can show the query it is about to send. The alternative --
// fetching the request object and decoding the JAR -- consumes it, because
// request_uri is single use: read it to inspect the query and the phone can no
// longer fetch it, so inspecting the session would destroy it. The verifier is no
// help either, answering 400 until the wallet responds and keeping nothing across
// a restart.
//
// CreateSession calls this rather than building the query inline, so what gets
// printed and what gets sent cannot drift.
func DcqlQuery(req SessionRequest) map[string]any {
	namespace := req.Namespace
	if namespace == "" {
		namespace = req.DocType
	}
	queryID := req.QueryID
	if queryID == "" {
		queryID = "age"
	}

	claim := map[string]any{"path": []string{namespace, req.Element}}
	if req.Value != nil {
		claim["values"] = []any{*req.Value}
	}

	return map[string]any{
		"credentials": []map[string]any{{
			"id":     queryID,
			"format": "mso_mdoc",
			"meta":   map[string]any{"doctype_value": req.DocType},
			"claims": []map[string]any{claim},
		}},
	}
}

// CreateSession starts a presentation at the verifier and returns the wallet
// link for it.
//
// The link is single use in two senses: the request object can be fetched once,
// after which the verifier answers "Presentation should be in state Requested
// but is in RequestObjectRetrieved", and each presentation spends one batch
// instance of the credential.
func CreateSession(cfg Config, req SessionRequest) (*Session, error) {
	if req.DocType == "" || req.Element == "" {
		return nil, fmt.Errorf("localstack: SessionRequest needs both DocType and Element")
	}
	issuerCA, err := os.ReadFile(cfg.IssuerCAPath())
	if err != nil {
		return nil, fmt.Errorf("read issuer CA: %w", err)
	}

	nonce := req.Nonce
	if nonce == "" {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			return nil, fmt.Errorf("generate nonce: %w", err)
		}
		nonce = hex.EncodeToString(nonceBytes)
	}

	body, err := json.Marshal(map[string]any{
		"type":               "vp_token",
		"dcql_query":         DcqlQuery(req),
		"nonce":              nonce,
		"jar_mode":           "by_reference",
		"request_uri_method": "get",
		"intended_use_id":    req.IntendedUseID,
		"issuer_chain":       string(issuerCA),
	})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(cfg.VerifierHost+"/ui/presentations",
		"application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("start verifier session: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("verifier refused the session request: HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	var fields map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&fields); err != nil {
		return nil, fmt.Errorf("decode verifier response: %w", err)
	}

	query := url.Values{}
	for key, value := range fields {
		query.Add(key, value)
	}
	return &Session{
		TransactionID:    fields["transaction_id"],
		ClientID:         fields["client_id"],
		RequestURI:       fields["request_uri"],
		RequestURIMethod: fields["request_uri_method"],
		Link:             "eudi-openid4vp://?" + query.Encode(),
	}, nil
}

// Offer is a credential offer the issuer minted.
type Offer struct {
	// URI is the openid-credential-offer:// link for a wallet. Its tx_code carries
	// input_mode, length and description but no value: see
	// stripTransactionCodeValue.
	URI string
	// TxCode is the one-time code the wallet must present, returned here so the
	// caller can deliver it by some channel URI does not travel on. The reference
	// issuer hands it back inside the offer, which is a convenience of the fixture
	// rather than the protocol -- OpenID4VCI's tx_code object has no value member
	// -- so it is taken out of URI and surfaced here instead.
	TxCode string
}

// AVCredentialConfigID is the configuration the Python issuer must have enabled
// in countries.AV.supported_credential_ids to mint the AV attestation.
const AVCredentialConfigID = "eu.europa.ec.eudi.age_verification_mdoc"

// CreateOffer asks the issuer for a credential offer carrying the given element
// values.
//
// data decides what the credential actually contains, and nothing else does: the
// issuer's metadata advertises thirteen age_over_NN claims, but only what is
// passed here is minted.
//
// The endpoint decodes the payload segment without verifying it, so the header
// and signature of the JWT-shaped request can be empty -- see
// app/preauthorization.py upstream.
func CreateOffer(cfg Config, credentialConfigID string, data map[string]any) (*Offer, error) {
	payload, err := json.Marshal(map[string]any{
		"credentials": []map[string]any{{
			"credential_configuration_id": credentialConfigID,
			"data":                        data,
		}},
	})
	if err != nil {
		return nil, err
	}
	jwtShaped := base64.RawURLEncoding.EncodeToString([]byte("{}")) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "."

	form := url.Values{}
	form.Set("request", jwtShaped)
	resp, err := http.Post(cfg.IssuerURL+"/credentialOfferReq2",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("post credential offer request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("issuer refused the offer request: HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	var offer map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&offer); err != nil {
		return nil, fmt.Errorf("decode offer: %w", err)
	}
	txCode, err := TransactionCode(offer)
	if err != nil {
		return nil, err
	}
	stripTransactionCodeValue(offer)

	encoded, err := json.Marshal(offer)
	if err != nil {
		return nil, err
	}
	return &Offer{
		URI:    "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(encoded)),
		TxCode: txCode,
	}, nil
}

// stripTransactionCodeValue removes tx_code.value from an offer, leaving the
// members that tell a wallet how to prompt for it: input_mode, length and
// description.
//
// The reference issuer returns the code inside the offer it hands back. That is
// a convenience of the fixture, not the protocol -- OpenID4VCI's tx_code object
// has no "value" member at all -- and a one-time code shipped inside the very
// link it is supposed to protect protects nothing: anyone who can read the link
// can read the code. Carrying it in the deep link would demonstrate the opposite
// of what a transaction code is for.
//
// Removing it costs nothing here, because irmago never reads it. The wallet's
// openid4vci.TransactionCode carries only InputMode, Length and Description, so
// it always prompts the user; a wallet that auto-filled from the offer would
// change behaviour, this one cannot tell the difference. The code itself still
// reaches the caller as Offer.TxCode, to be delivered by some channel the link
// does not travel on.
//
// Missing or malformed members are left alone rather than treated as an error:
// the caller has already extracted the code through TransactionCode by this
// point, so anything unexpected here has been reported already.
func stripTransactionCodeValue(offer map[string]any) {
	grants, ok := offer["grants"].(map[string]any)
	if !ok {
		return
	}
	preAuth, ok := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]any)
	if !ok {
		return
	}
	tx, ok := preAuth["tx_code"].(map[string]any)
	if !ok {
		return
	}
	delete(tx, "value")
}

// TransactionCode digs the one-time code out of an offer.
func TransactionCode(offer map[string]any) (string, error) {
	grants, ok := offer["grants"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("offer carries no grants")
	}
	preAuth, ok := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("offer carries no pre-authorized_code grant")
	}
	tx, ok := preAuth["tx_code"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("offer carries no tx_code")
	}
	switch value := tx["value"].(type) {
	case string:
		return value, nil
	case float64:
		return fmt.Sprintf("%d", int64(value)), nil
	default:
		return "", fmt.Errorf("offer's tx_code has no usable value")
	}
}

// WalletResponse fetches the verifier's record of a presentation. Before the
// wallet answers this is an error rather than an empty result: the verifier
// reports the presentation is not in Submitted state, which is a normal
// intermediate condition and not a failure.
func WalletResponse(cfg Config, transactionID string) ([]byte, error) {
	resp, err := http.Get(cfg.VerifierHost + "/ui/presentations/" + transactionID)
	if err != nil {
		return nil, fmt.Errorf("fetch wallet response: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read wallet response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verifier returned HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

// ProxyCertPath is the self-signed certificate the tls_proxy container serves.
func (c Config) ProxyCertPath() string {
	return filepath.Join(c.TestdataDir, "configurations", "certs", "localhost.crt")
}

// TrustProxyCertificate teaches this process about the certificate the docker
// TLS proxy serves, which nothing trusts by default. Without it every call to
// the issuer fails as an unknown authority, and only the issuer -- the verifier
// is plain HTTP -- so a presentation-only run appears to work and adding -issue
// suddenly does not.
//
// It lives here rather than in one command because both callers need it and a
// tool that forgets it fails in a way that reads like a container problem.
// Absent certificate file is not an error: a caller pointed at a stack with a
// real certificate has nothing to add.
//
// If TLS still fails with this applied, something is intercepting it -- an
// antivirus web shield will.
func TrustProxyCertificate(cfg Config) error {
	pem, err := os.ReadFile(cfg.ProxyCertPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read tls proxy certificate: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("tls proxy certificate at %s is not usable PEM", cfg.ProxyCertPath())
	}
	http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	return nil
}

// DefaultAVElements is the element set the local demos mint: five thresholds
// rather than one, so a presentation of a single element visibly discloses less
// than the credential holds -- with one element there is no selective disclosure
// to see.
//
// This is the default for what the demos issue, and the only thing mdoc-e2e ever
// issues. mint-session's -mint can supply a different set, but -value cannot:
// -value constrains the query alone, so an offer and a query can be made to
// disagree deliberately, which is what a refusal test needs. A single flag
// driving both would make every run agree with itself.
//
// That distinction is the point rather than an accident: a credential whose value
// matches the query it will face passes whether or not the value constraint is
// enforced at all, so a run that agrees with itself proves less than one that had
// to be matched on purpose.
//
// Nothing else may restate these values. mdoc-e2e once hardcoded a false value
// constraint and three narration lines describing an earlier version of this map;
// when the map changed, its happy path silently became the refusal path and
// reported it as "the wallet has nothing to disclose". Derive from this function
// instead.
func DefaultAVElements() map[string]any {
	return map[string]any{
		"age_over_18": true,
		"age_over_40": false,
		"age_over_60": false,
		"age_over_67": false,
	}
}
