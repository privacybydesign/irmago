// mdoc-violations runs a battery of protocol-violation scenarios end to end
// against the same stack mdoc-e2e uses: the EUDI reference issuer and verifier
// containers, with a real client.Client wallet in the middle.
//
// Every scenario is a full session. Nothing is stubbed, and no verification
// function is called directly — a scenario "passes" only when the real wallet or
// the real container refuses the session.
//
// Requests that have to differ from what the reference verifier would send are
// produced by taking the container's own signed request JWT, changing exactly one
// field, and re-signing with the verifier private key from testdata. Scenario 0 is
// the control for that rig: an unmodified re-signed request must still succeed,
// otherwise every later rejection would be an artifact of the minting.
//
//	docker compose up -d
//	go run ./yivi/cli/eudicli/mdoc-violations
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/privacybydesign/gabi/signed"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/client/clientsettings"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/crypto/encryption"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

const (
	docType            = "eu.europa.ec.av.1"
	namespace          = docType
	credentialConfigID = "eu.europa.ec.eudi.age_verification_mdoc"
	intendedUseID      = "1"
	queryID            = "age"
	stateTimeout       = 30 * time.Second
)

var (
	issuerURL     = flag.String("issuer", "https://localhost:8443/eudi-pid-issuer-py", "EUDI reference issuer")
	verifierJwt   = flag.String("verifier", "http://127.0.0.1:8090", "EUDI reference verifier (direct_post.jwt)")
	verifierPlain = flag.String("verifier-plain", "http://127.0.0.1:8089", "EUDI reference verifier (plain direct_post)")
	testdataDir   = flag.String("testdata", "testdata", "path to the repository's testdata folder")
	only          = flag.String("only", "", "comma-separated scenario numbers to run (default: all)")
)

// enabled reports whether scenario n should run, honouring -only.
func enabled(n int) bool {
	if *only == "" {
		return true
	}
	for _, part := range strings.Split(*only, ",") {
		if strings.TrimSpace(part) == fmt.Sprintf("%d", n) {
			return true
		}
	}
	return false
}

// ============================================================================
// Results
// ============================================================================

type outcome struct {
	n       int
	layer   string
	name    string
	spec    string
	want    string
	got     string
	verdict string // what the stack actually did
	ok      bool   // whether that is what the spec requires
	note    string
}

var results []outcome

func record(o outcome) {
	results = append(results, o)
	fmt.Printf("  [%2d] %-46s %s\n", o.n, o.name, o.verdict)
	fmt.Printf("       %s\n", o.got)
	if o.note != "" {
		fmt.Printf("       note: %s\n", o.note)
	}
}

// rejected records a scenario whose expectation is "the session must fail".
func rejected(n int, layer, name, spec, want string, err error, note string) {
	o := outcome{n: n, layer: layer, name: name, spec: spec, want: want, note: note}
	if err != nil {
		o.ok, o.verdict = true, "REFUSED"
		o.got = oneLine(err.Error())
	} else {
		o.ok, o.verdict = false, "ACCEPTED"
		o.got = "session completed — the violation was not caught"
	}
	record(o)
}

// accepted records a scenario whose expectation is "the session must succeed"
// (the controls).
func accepted(n int, layer, name, spec, want string, err error, note string) {
	o := outcome{n: n, layer: layer, name: name, spec: spec, want: want, note: note}
	if err == nil {
		o.ok, o.verdict = true, "COMPLETED"
		o.got = "ran to success, as required"
	} else {
		o.ok, o.verdict = false, "REFUSED"
		o.got = "should have completed but did not: " + oneLine(err.Error())
	}
	record(o)
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

func main() {
	flag.Parse()
	trustProxyCertificate()

	fmt.Println()
	fmt.Println("mdoc violation battery — every scenario is a real session against the containers")
	fmt.Println(strings.Repeat("=", 78))

	type step struct {
		n     int
		title string
		fn    func()
	}
	steps := []step{
		{-1, "CONTROLS — the rig itself must not manufacture failures", nil},
		{0, "", scenarioControlHappyPath},
		{1, "", scenarioControlMintedUnmodified},
		{-1, "ISSUANCE — OpenID4VCI against the reference issuer", nil},
		{2, "", scenarioWrongTxCode},
		{3, "", scenarioBogusConfigID},
		{4, "", scenarioPreAuthCodeReplay},
		{5, "", scenarioUntrustedIssuerCA},
		{6, "", scenarioOfferWithoutPreAuthCode},
		{-1, "REQUEST AUTHENTICATION — signed authorization request", nil},
		{7, "", scenarioCorruptSignature},
		{8, "", scenarioAlgNone},
		{9, "", scenarioMissingTyp},
		{10, "", scenarioClientIdSanMismatch},
		{11, "", scenarioRedirectUriClientId},
		{12, "", scenarioNoX5c},
		{13, "", scenarioUntrustedVerifierCA},
		{-1, "DCQL AND AUTHORIZATION — what the verifier may ask for", nil},
		{14, "", scenarioUnknownDocType},
		{15, "", scenarioWrongNamespace},
		{16, "", scenarioElementNotHeld},
		{17, "", scenarioForbiddenAttribute},
		{18, "", scenarioWrongFormat},
		{19, "", scenarioMalformedClaimPath},
		{-1, "SESSION BINDING — response and transcript", nil},
		{20, "", scenarioNoNonce},
		{21, "", scenarioVpTokenReplay},

		{-1, "REQUEST CLAIMS — semantics of a validly signed request", nil},
		{22, "", scenarioResponseUriElsewhere},
		{23, "", scenarioNonceAbsentFromRequest},
		{24, "", scenarioNonceEmpty},
		{25, "", scenarioResponseTypeCode},
		{26, "", scenarioDcApiOnRedirectPath},
		{27, "", scenarioUnknownResponseMode},
		{28, "", scenarioIatFarFuture},
		{29, "", scenarioIatLongExpired},
		{30, "", scenarioWrongAudience},
		{31, "", scenarioJwksMissingForEncryptedResponse},

		{-1, "REQUEST STRUCTURE — DCQL well-formedness", nil},
		{32, "", scenarioNoDcqlQuery},
		{33, "", scenarioScopeAndDcqlTogether},
		{34, "", scenarioDuplicateQueryIds},
		{35, "", scenarioClaimPathTooDeep},
		{36, "", scenarioCredentialSetsUnsatisfiable},

		{-1, "TRUST SEPARATION — which certificates may speak for a verifier", nil},
		{37, "", scenarioRogueSelfSignedCert},
		{38, "", scenarioIssuerCertAsVerifier},

		{-1, "RESPONSE POSTING — direct_post endpoint", nil},
		{39, "", scenarioWrongState},
		{40, "", scenarioDoubleSubmission},
		{41, "", scenarioEmptyConfigurationIds},

		{-1, "RP CERTIFICATE DEFECTS — chains to a trusted root, but is wrong", nil},
		{42, "", scenarioLeafExpired},
		{43, "", scenarioLeafNotYetValid},
		{44, "", scenarioCaCertUsedAsLeaf},
		{45, "", scenarioX5cLeafIsNotTheSigner},
		{46, "", scenarioX5cEmptyArray},

		{-1, "JOSE HEADER — algorithm and envelope", nil},
		{47, "", scenarioAlgConfusionHS256},
		{48, "", scenarioAlgMismatchES384},
		{49, "", scenarioTwoSegmentJwt},

		{-1, "REQUEST_URI TRANSPORT — what the wallet fetches", nil},
		{50, "", scenarioRequestUriServesHtml},
		{51, "", scenarioRequestUriServerError},
		{52, "", scenarioLinkClientIdMismatch},

		{-1, "REQUEST PARAMETERS — combinations OpenID4VP constrains", nil},
		{53, "", scenarioNonceNotUrlSafe},
		{54, "", scenarioResponseUriAbsent},
		{55, "", scenarioResponseAndRedirectUriTogether},
		{56, "", scenarioClientIdEmpty},
		{57, "", scenarioClientIdNoPrefix},

		{-1, "DCQL DETAIL — query members", nil},
		{58, "", scenarioClaimPathEmpty},
		{59, "", scenarioMdocQueryWithoutMeta},
		{60, "", scenarioCredentialSetEmptyOptions},
		{61, "", scenarioClaimValuesUnsatisfiable},
	}
	for _, s := range steps {
		if s.fn == nil {
			group(s.title)
			continue
		}
		if enabled(s.n) {
			s.fn()
		}
	}

	summary()
}

func group(title string) {
	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("-", len(title)))
}

func summary() {
	fmt.Printf("\n%s\nSUMMARY\n%s\n", strings.Repeat("=", 78), strings.Repeat("=", 78))
	var bad []outcome
	for _, o := range results {
		mark := "ok  "
		if !o.ok {
			mark = "FAIL"
			bad = append(bad, o)
		}
		fmt.Printf("  %s  [%2d] %-46s %s\n", mark, o.n, o.name, o.spec)
	}
	fmt.Printf("\n  %d scenarios, %d behaved as the spec requires, %d did not\n",
		len(results), len(results)-len(bad), len(bad))
	for _, o := range bad {
		fmt.Printf("\n  NOT AS SPECIFIED — [%d] %s\n    expected: %s\n    observed: %s\n", o.n, o.name, o.want, o.got)
	}
}

// ============================================================================
// Controls
// ============================================================================

func scenarioControlHappyPath() {
	err := func() error {
		w, err := newWallet(true, true)
		if err != nil {
			return err
		}
		defer w.close()
		if err := w.issueGood(); err != nil {
			return err
		}
		s, err := createVerifierSession(*verifierJwt, defaultDcql(docType, namespace, "age_over_18", "mso_mdoc"), nil)
		if err != nil {
			return err
		}
		return w.disclose(s.Link)
	}()
	accepted(0, "control", "unmodified flow, container's own request",
		"baseline", "issuance and disclosure both complete", err,
		"if this fails nothing below can be trusted")
}

func scenarioControlMintedUnmodified() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {})
	})
	accepted(1, "control", "request re-signed by us, nothing changed",
		"baseline", "the wallet accepts our re-signed copy", err,
		"validates the minting rig: same key, same x5c, same claims")
}

// ============================================================================
// Issuance
// ============================================================================

func scenarioWrongTxCode() {
	err := func() error {
		w, err := newWallet(true, true)
		if err != nil {
			return err
		}
		defer w.close()
		offer, err := createOffer(credentialConfigID, defaultClaims())
		if err != nil {
			return err
		}
		return w.issue(offer.URI, "00000")
	}()
	rejected(2, "issuance", "wrong pre-authorized transaction code",
		"OID4VCI 1.0 §6.1", "the token endpoint refuses and nothing is stored", err, "")
}

func scenarioBogusConfigID() {
	const bogus = "eu.europa.ec.eudi.not_a_real_configuration"
	offer, offerErr := createOffer(bogus, defaultClaims())
	if offerErr != nil {
		rejected(3, "issuance", "offer names an unknown credential configuration",
			"OID4VCI 1.0 §4.1.1", "no credential is stored for a configuration that does not exist",
			offerErr, "the issuer refused to mint the offer at all")
		return
	}
	// The reference issuer minted it anyway, so the question becomes whether the
	// wallet will complete an issuance against a configuration the issuer does
	// not publish in its metadata.
	err := func() error {
		w, err := newWallet(true, true)
		if err != nil {
			return err
		}
		defer w.close()
		return w.issue(offer.URI, offer.TxCode)
	}()
	rejected(3, "issuance", "offer names an unknown credential configuration",
		"OID4VCI 1.0 §4.1.1", "no credential is stored for a configuration that does not exist", err,
		"the reference issuer minted the offer regardless; this measures the wallet's redemption of it")
}

func scenarioPreAuthCodeReplay() {
	err := func() error {
		offer, err := createOffer(credentialConfigID, defaultClaims())
		if err != nil {
			return err
		}
		first, err := newWallet(true, true)
		if err != nil {
			return err
		}
		defer first.close()
		if err := first.issue(offer.URI, offer.TxCode); err != nil {
			return fmt.Errorf("the first redemption should have worked: %w", err)
		}
		second, err := newWallet(true, true)
		if err != nil {
			return err
		}
		defer second.close()
		return second.issue(offer.URI, offer.TxCode)
	}()
	rejected(4, "issuance", "pre-authorized code redeemed a second time",
		"OID4VCI 1.0 §4.1.1", "a pre-authorized code is single use", err, "")
}

func scenarioUntrustedIssuerCA() {
	err := func() error {
		w, err := newWallet(false, true)
		if err != nil {
			return err
		}
		defer w.close()
		return w.issueGood()
	}()
	rejected(5, "issuance", "issuer's chain not anchored in the wallet",
		"ISO 18013-5 §9.3.1", "the wallet stores nothing it cannot authenticate", err, "")
}

func scenarioOfferWithoutPreAuthCode() {
	err := func() error {
		w, err := newWallet(true, true)
		if err != nil {
			return err
		}
		defer w.close()
		raw, err := createOfferRaw(credentialConfigID, defaultClaims())
		if err != nil {
			return err
		}
		grants, _ := raw["grants"].(map[string]any)
		grant, _ := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]any)
		delete(grant, "pre-authorized_code")
		return w.issue(offerURI(raw), "12345")
	}()
	rejected(6, "issuance", "grant omits the REQUIRED pre-authorized_code",
		"OID4VCI 1.0 §4.1.1", "the wallet rejects the offer while parsing it", err, "")
}

// ============================================================================
// Request authentication
// ============================================================================

func scenarioCorruptSignature() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMintedRaw(w, func(jwt string) string {
			parts := strings.Split(jwt, ".")
			// Flip a bit in the decoded signature, not in its base64 text. A
			// 64-byte signature encodes to 86 base64url characters whose last
			// character carries four unused bits, so flipping the final
			// character can leave the decoded bytes identical and the signature
			// still valid — which made this scenario pass or fail at random.
			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil || len(sig) == 0 {
				return jwt
			}
			sig[0] ^= 0x01
			return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
		})
	})
	rejected(7, "request auth", "authorization request signature corrupted",
		"OID4VP 1.0 §5.7", "an unverifiable request is refused", err, "")
}

func scenarioAlgNone() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			hdr["alg"] = "none"
		})
	})
	rejected(8, "request auth", "alg:none, signature stripped",
		"RFC 8725 §3.1", "an unsigned request must never authenticate a verifier", err, "")
}

func scenarioMissingTyp() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			delete(hdr, "typ")
		})
	})
	rejected(9, "request auth", "typ header absent",
		"OID4VP 1.0 §5.7", "typ must be oauth-authz-req+jwt", err, "")
}

func scenarioClientIdSanMismatch() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMintedWithClientId(w, "x509_san_dns:evil.example",
			func(hdr, claims map[string]any) {
				claims["client_id"] = "x509_san_dns:evil.example"
			})
	})
	rejected(10, "request auth", "client_id names a host the cert has no SAN for",
		"OID4VP 1.0 §5.10", "client_id must bind to the signing certificate", err,
		"validly signed by the real verifier key — only the client_id differs")
}

func scenarioRedirectUriClientId() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMintedWithClientId(w, "redirect_uri:http://localhost:8090/wallet/direct_post",
			func(hdr, claims map[string]any) {
				claims["client_id"] = "redirect_uri:http://localhost:8090/wallet/direct_post"
			})
	})
	rejected(11, "request auth", "client_id scheme redirect_uri (the AV-mandated one)",
		"AV Annex A §A.6", "AV REQUIRES this scheme — a rejection is non-conformance", err,
		"listed as a violation of OUR trust model, but conformant per the AV profile")
}

func scenarioNoX5c() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			delete(hdr, "x5c")
		})
	})
	rejected(12, "request auth", "x5c header absent",
		"OID4VP 1.0 §5.10", "no certificate means no authenticated verifier", err, "")
}

func scenarioUntrustedVerifierCA() {
	err := func() error {
		w, err := newWallet(true, false)
		if err != nil {
			return err
		}
		defer w.close()
		if err := w.issueGood(); err != nil {
			return err
		}
		s, err := createVerifierSession(*verifierJwt, defaultDcql(docType, namespace, "age_over_18", "mso_mdoc"), nil)
		if err != nil {
			return err
		}
		return w.disclose(s.Link)
	}()
	rejected(13, "request auth", "verifier's chain not anchored in the wallet",
		"ISO 18013-5 §9.1.4", "an unanchored relying party is refused", err,
		"withholding the CA file only creates an untrusted verifier while that CA is "+
			"not also a compiled-in anchor in eudi/trustanchors.go; scenario 37 tests "+
			"the same property without depending on that")
}

// ============================================================================
// DCQL and authorization
// ============================================================================

func scenarioUnknownDocType() {
	err := discloseQuery(defaultDcql("eu.europa.ec.av.2", "eu.europa.ec.av.2", "age_over_18", "mso_mdoc"))
	rejected(14, "dcql", "docType eu.europa.ec.av.2 does not exist",
		"AV Annex A §A.4", "docType SHALL be eu.europa.ec.av.1", err, "")
}

func scenarioWrongNamespace() {
	err := discloseQuery(defaultDcql(docType, "org.iso.18013.5.1", "age_over_18", "mso_mdoc"))
	rejected(15, "dcql", "claim path uses the mDL namespace under av.1",
		"AV Annex A §A.4", "all attributes belong to namespace eu.europa.ec.av.1", err, "")
}

func scenarioElementNotHeld() {
	err := discloseQuery(defaultDcql(docType, namespace, "age_over_99", "mso_mdoc"))
	rejected(16, "dcql", "element age_over_99 is not in the credential",
		"OID4VP 1.0 §6", "a query with no match yields no presentation", err, "")
}

func scenarioForbiddenAttribute() {
	err := discloseQuery(defaultDcql(docType, namespace, "birth_date", "mso_mdoc"))
	rejected(17, "dcql", "birth_date requested from a proof-of-age attestation",
		"AV Annex A §A.4", "SHALL NOT include any other attribute", err, "")
}

func scenarioWrongFormat() {
	err := discloseQuery(defaultDcql(docType, namespace, "age_over_18", "dc+sd-jwt"))
	rejected(18, "dcql", "format dc+sd-jwt for an mso_mdoc credential",
		"OID4VP 1.0 §6.1", "format must match what the wallet holds", err, "")
}

func scenarioMalformedClaimPath() {
	q := map[string]any{
		"credentials": []map[string]any{{
			"id":     queryID,
			"format": "mso_mdoc",
			"meta":   map[string]any{"doctype_value": docType},
			"claims": []map[string]any{{"path": []string{"age_over_18"}}},
		}},
	}
	err := discloseQuery(q)
	rejected(19, "dcql", "mdoc claim path with one element instead of two",
		"OID4VP 1.0 §6.4.1", "an mdoc path is [namespace, elementIdentifier]", err, "")
}

// ============================================================================
// Session binding
// ============================================================================

func scenarioNoNonce() {
	_, err := createVerifierSession(*verifierJwt, defaultDcql(docType, namespace, "age_over_18", "mso_mdoc"),
		func(body map[string]any) { delete(body, "nonce") })
	rejected(20, "session", "authorization request carries no nonce",
		"AV Annex A §A.6", "a request MUST specify the nonce parameter", err, "")
}

func scenarioVpTokenReplay() {
	err := func() error {
		w, err := newWallet(true, true)
		if err != nil {
			return err
		}
		defer w.close()
		if err := w.issueGood(); err != nil {
			return err
		}

		// Both sessions run against the plain direct_post verifier, not the
		// direct_post.jwt one. On the encrypted endpoint a raw vp_token would be
		// refused for being unencrypted, which would look like replay detection
		// without being it.
		host := *verifierPlain

		// A genuine presentation, so we hold a vp_token the verifier accepted.
		first, err := createVerifierSession(host, defaultDcql(docType, namespace, "age_over_18", "mso_mdoc"), nil)
		if err != nil {
			return err
		}
		if err := w.disclose(first.Link); err != nil {
			return fmt.Errorf("the genuine presentation should have worked: %w", err)
		}
		token, err := presentedDocument(host, first)
		if err != nil {
			return err
		}

		// A second, independent session, with its own nonce and transcript. The
		// captured token is posted straight into it, without the wallet.
		second, err := createVerifierSession(host, defaultDcql(docType, namespace, "age_over_18", "mso_mdoc"), nil)
		if err != nil {
			return err
		}
		claims, err := requestClaims(second.Link)
		if err != nil {
			return err
		}
		responseUri, _ := claims["response_uri"].(string)
		state, _ := claims["state"].(string)
		if responseUri == "" {
			return fmt.Errorf("second session exposes no response_uri")
		}

		// vp_token is a JSON object keyed by DCQL query id, not a bare string.
		// Posting the raw token makes the verifier fail to parse the body, which
		// looks like a rejection but is only a malformed request.
		envelope, err := json.Marshal(map[string]any{queryID: []string{token}})
		if err != nil {
			return err
		}
		form := url.Values{}
		form.Set("vp_token", string(envelope))
		form.Set("state", state)
		resp, err := http.PostForm(responseUri, form)
		if err != nil {
			return fmt.Errorf("post replayed token: %w", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// The POST being accepted is not conclusive on its own; check whether
			// the verifier actually recorded a presentation for that transaction.
			doc, ferr := presentedDocument(host, second)
			if ferr == nil && doc != "" {
				return nil // replay landed — no error means "not rejected"
			}
			return fmt.Errorf("verifier took the POST (HTTP %d) but recorded no presentation: %v", resp.StatusCode, ferr)
		}
		return fmt.Errorf("verifier refused the replayed token: HTTP %d %s", resp.StatusCode, oneLine(string(body)))
	}()
	rejected(21, "session", "vp_token replayed into a second session",
		"ISO 18013-5 §9.1.5", "the transcript binds a response to one request", err,
		"posted directly to the second session's response_uri, bypassing the wallet")
}

// ============================================================================
// Request claims — semantics of a validly signed request
// ============================================================================

func scenarioResponseUriElsewhere() {
	var landed string
	var didLand bool
	err := withIssuedWallet(func(w *wallet) error {
		s, err := createVerifierSession(*verifierJwt, defaultDcql(docType, namespace, "age_over_18", "mso_mdoc"), nil)
		if err != nil {
			return err
		}
		real, err := fetchRequestJwt(s.Link)
		if err != nil {
			return err
		}
		// Placeholder rogue first, so we know the URL to point response_uri at.
		r, err := startRogue("")
		if err != nil {
			return err
		}
		defer r.stop()

		minted, err := mintVariant(real, func(hdr, claims map[string]any) {
			claims["response_uri"] = r.base + "/response"
			// An encrypted response would be unreadable to us anyway, and the
			// question here is where the wallet is willing to send it.
			claims["response_mode"] = "direct_post"
		})
		if err != nil {
			return err
		}
		r.serve(minted)

		discloseErr := w.disclose(r.link(s.ClientID))
		landed, didLand = r.exfiltrated()
		return discloseErr
	})
	note := "response_uri points at a host the verifier certificate says nothing about"
	if didLand {
		note = fmt.Sprintf("THE WALLET POSTED ITS RESPONSE TO THE ROGUE HOST (%d bytes captured)", len(landed))
	}
	rejected(22, "request claims", "response_uri moved to an unrelated host",
		"OID4VP 1.0 §5.10", "for x509_san_dns the response_uri host must match the certificate SAN",
		err, note)
}

func scenarioNonceAbsentFromRequest() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			delete(claims, "nonce")
		})
	})
	rejected(23, "request claims", "nonce absent from the signed request",
		"OID4VP 1.0 §5.1", "nonce is REQUIRED; without it nothing binds the response", err,
		"the container enforces this at session creation — this asks the wallet directly")
}

func scenarioNonceEmpty() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			claims["nonce"] = ""
		})
	})
	rejected(24, "request claims", "nonce present but empty",
		"OID4VP 1.0 §5.1", "an empty nonce is no nonce", err, "")
}

func scenarioResponseTypeCode() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			claims["response_type"] = "code"
		})
	})
	rejected(25, "request claims", "response_type is code, not vp_token",
		"AV Annex A §A.6", "response type MUST be vp_token", err, "")
}

func scenarioDcApiOnRedirectPath() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			claims["response_mode"] = "dc_api"
		})
	})
	rejected(26, "request claims", "dc_api response mode on a URL-invoked session",
		"OID4VP 1.0 App. A.2", "dc_api modes are only valid over the Digital Credentials API", err, "")
}

func scenarioUnknownResponseMode() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			claims["response_mode"] = "direct_post.unknown"
		})
	})
	rejected(27, "request claims", "unrecognised response_mode",
		"OID4VP 1.0 §8", "an unknown response mode has no defined handling", err, "")
}

func scenarioIatFarFuture() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			claims["iat"] = time.Now().Add(365 * 24 * time.Hour).Unix()
		})
	})
	rejected(28, "request claims", "iat one year in the future",
		"RFC 7519 §4.1.6", "a request issued in the future is not yet valid", err, "")
}

func scenarioIatLongExpired() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			claims["iat"] = time.Now().Add(-365 * 24 * time.Hour).Unix()
			claims["exp"] = time.Now().Add(-364 * 24 * time.Hour).Unix()
		})
	})
	rejected(29, "request claims", "request issued and expired a year ago",
		"RFC 7519 §4.1.4", "an expired request must not be honoured", err, "")
}

func scenarioWrongAudience() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			claims["aud"] = "https://someone.else.example"
		})
	})
	rejected(30, "request claims", "aud names a different wallet",
		"RFC 7519 §4.1.3", "a request addressed elsewhere must be refused", err, "")
}

func scenarioJwksMissingForEncryptedResponse() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			meta, ok := claims["client_metadata"].(map[string]any)
			if ok {
				delete(meta, "jwks")
			}
		})
	})
	rejected(31, "request claims", "direct_post.jwt with no jwks to encrypt to",
		"OID4VP 1.0 §8.3", "an encrypted response mode requires the verifier's key", err, "")
}

// ============================================================================
// Request structure — DCQL well-formedness
// ============================================================================

func scenarioNoDcqlQuery() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			delete(claims, "dcql_query")
		})
	})
	rejected(32, "dcql shape", "request carries neither dcql_query nor scope",
		"OID4VP 1.0 §5.1", "one of dcql_query or scope MUST be present", err, "")
}

func scenarioScopeAndDcqlTogether() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			claims["scope"] = "proof_of_age"
		})
	})
	rejected(33, "dcql shape", "scope and dcql_query both present",
		"OID4VP 1.0 §5.1", "they are mutually exclusive", err, "")
}

func scenarioDuplicateQueryIds() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			query, ok := claims["dcql_query"].(map[string]any)
			if !ok {
				return
			}
			creds, ok := query["credentials"].([]any)
			if !ok || len(creds) == 0 {
				return
			}
			query["credentials"] = []any{creds[0], creds[0]}
		})
	})
	rejected(34, "dcql shape", "two credential queries share one id",
		"OID4VP 1.0 §6.1", "credential query ids MUST be unique within a query", err, "")
}

func scenarioClaimPathTooDeep() {
	q := map[string]any{
		"credentials": []map[string]any{{
			"id":     queryID,
			"format": "mso_mdoc",
			"meta":   map[string]any{"doctype_value": docType},
			"claims": []map[string]any{{"path": []string{namespace, "age_over_18", "extra"}}},
		}},
	}
	err := discloseQuery(q)
	rejected(35, "dcql shape", "mdoc claim path with three elements",
		"OID4VP 1.0 §6.4.1", "an mdoc path is exactly [namespace, elementIdentifier]", err, "")
}

func scenarioCredentialSetsUnsatisfiable() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			query, ok := claims["dcql_query"].(map[string]any)
			if !ok {
				return
			}
			query["credential_sets"] = []any{
				map[string]any{
					"options":  []any{[]any{"absent"}},
					"required": true,
				},
			}
		})
	})
	rejected(36, "dcql shape", "required credential_set names an unknown query id",
		"OID4VP 1.0 §6.2", "a required set that cannot be satisfied fails the request", err, "")
}

// ============================================================================
// Trust separation
// ============================================================================

func scenarioRogueSelfSignedCert() {
	err := withIssuedWallet(func(w *wallet) error {
		key, der, genErr := selfSignedLocalhost()
		if genErr != nil {
			return genErr
		}
		return discloseMintedKeyed(w, key, func(hdr, claims map[string]any) {
			hdr["x5c"] = []any{base64.StdEncoding.EncodeToString(der)}
		})
	})
	rejected(37, "trust", "request signed by a self-signed localhost certificate",
		"ISO 18013-5 §9.1.4", "a certificate must chain to a trusted relying-party root", err,
		"correct SAN, correct client_id, internally consistent signature — only the anchor is wrong")
}

func scenarioIssuerCertAsVerifier() {
	err := withIssuedWallet(func(w *wallet) error {
		key, chain, loadErr := issuerSigningIdentity()
		if loadErr != nil {
			return loadErr
		}
		return discloseMintedKeyed(w, key, func(hdr, claims map[string]any) {
			encoded := make([]any, 0, len(chain))
			for _, der := range chain {
				encoded = append(encoded, base64.StdEncoding.EncodeToString(der))
			}
			hdr["x5c"] = encoded
		})
	})
	rejected(38, "trust", "request signed by the issuer's certificate",
		"ISO 18013-5 §9.1.4", "an issuer anchor must not authorize a relying party", err,
		"this chain IS trusted by the wallet — but in the issuer store, not the verifier store")
}

// ============================================================================
// Response posting
// ============================================================================

func scenarioWrongState() {
	err := postCapturedToken(func(_ *verifierSession, form url.Values) {
		form.Set("state", "not-the-state-for-this-session")
	})
	rejected(39, "response", "response posted with a state from nowhere",
		"OID4VP 1.0 §8.2", "state identifies the transaction being answered", err, "")
}

func scenarioDoubleSubmission() {
	err := func() error {
		host := *verifierPlain
		w, err := newWallet(true, true)
		if err != nil {
			return err
		}
		defer w.close()
		if err := w.issueGood(); err != nil {
			return err
		}
		s, err := createVerifierSession(host, defaultDcql(docType, namespace, "age_over_18", "mso_mdoc"), nil)
		if err != nil {
			return err
		}
		// The request object cannot be read here: request_uri is single use, and
		// consuming it would break the wallet's own fetch. Both values are
		// recoverable from the link instead — this container derives the state and
		// the direct_post path from the same identifier the request_uri carries.
		responseUri, state, err := bindingFromLink(host, s.Link)
		if err != nil {
			return err
		}

		if err := w.disclose(s.Link); err != nil {
			return fmt.Errorf("the genuine presentation should have worked: %w", err)
		}
		token, err := presentedDocument(host, s)
		if err != nil {
			return err
		}

		envelope, err := json.Marshal(map[string]any{queryID: []string{token}})
		if err != nil {
			return err
		}
		form := url.Values{}
		form.Set("vp_token", string(envelope))
		form.Set("state", state)

		// The same, genuine response submitted a second time to the very session
		// it belongs to. The transcript matches, so only single-use handling of
		// the transaction can stop it.
		resp, err := http.PostForm(responseUri, form)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		return fmt.Errorf("verifier refused the second submission: HTTP %d %s", resp.StatusCode, oneLine(string(body)))
	}()
	rejected(40, "response", "the same genuine response submitted twice",
		"OID4VP 1.0 §8.2", "a completed transaction should not accept another response", err,
		"same session, same transcript — replay of a response into its own transaction")
}

func scenarioEmptyConfigurationIds() {
	err := func() error {
		payload, err := json.Marshal(map[string]any{"credentials": []map[string]any{}})
		if err != nil {
			return err
		}
		jwtShaped := base64.RawURLEncoding.EncodeToString([]byte("{}")) + "." +
			base64.RawURLEncoding.EncodeToString(payload) + "."
		form := url.Values{}
		form.Set("request", jwtShaped)
		resp, err := http.Post(*issuerURL+"/credentialOfferReq2",
			"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("issuer refused: HTTP %d %s", resp.StatusCode, oneLine(string(body)))
		}
		return nil
	}()
	rejected(41, "issuance", "offer with an empty credentials array",
		"OID4VCI 1.0 §4.1.1", "credential_configuration_ids MUST have at least one entry", err, "")
}

// postCapturedToken runs a genuine presentation, then posts the captured token
// back with the form mutated by tweak.
func postCapturedToken(tweak func(*verifierSession, url.Values)) error {
	host := *verifierPlain
	w, err := newWallet(true, true)
	if err != nil {
		return err
	}
	defer w.close()
	if err := w.issueGood(); err != nil {
		return err
	}
	first, err := createVerifierSession(host, defaultDcql(docType, namespace, "age_over_18", "mso_mdoc"), nil)
	if err != nil {
		return err
	}
	if err := w.disclose(first.Link); err != nil {
		return fmt.Errorf("the genuine presentation should have worked: %w", err)
	}
	token, err := presentedDocument(host, first)
	if err != nil {
		return err
	}

	second, err := createVerifierSession(host, defaultDcql(docType, namespace, "age_over_18", "mso_mdoc"), nil)
	if err != nil {
		return err
	}
	claims, err := requestClaims(second.Link)
	if err != nil {
		return err
	}
	responseUri, _ := claims["response_uri"].(string)
	state, _ := claims["state"].(string)

	envelope, err := json.Marshal(map[string]any{queryID: []string{token}})
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Set("vp_token", string(envelope))
	form.Set("state", state)
	tweak(second, form)

	resp, err := http.PostForm(responseUri, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		doc, ferr := presentedDocument(host, second)
		if ferr == nil && doc != "" {
			return nil
		}
		return fmt.Errorf("verifier took the POST (HTTP %d) but recorded no presentation: %v", resp.StatusCode, ferr)
	}
	return fmt.Errorf("verifier refused: HTTP %d %s", resp.StatusCode, oneLine(string(body)))
}

// bindingFromLink recovers the response_uri and state without consuming the
// single-use request_uri, relying on this container issuing one identifier for
// the request object, the state, and the direct_post path.
func bindingFromLink(host, link string) (string, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", "", err
	}
	requestUri := u.Query().Get("request_uri")
	idx := strings.LastIndex(requestUri, "/")
	if requestUri == "" || idx < 0 {
		return "", "", fmt.Errorf("cannot derive the session identifier from %q", requestUri)
	}
	id := requestUri[idx+1:]
	return host + "/wallet/direct_post/" + id, id, nil
}

// selfSignedLocalhost mints a throwaway certificate with the right SAN and no
// path to any trusted root.
func selfSignedLocalhost() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(4242),
		Subject:               pkix.Name{CommonName: "localhost", Organization: []string{"Rogue"}},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return key, der, nil
}

// issuerSigningIdentity loads the PID issuer's document signer key and chain —
// a chain the wallet genuinely trusts, but as an issuer, not a verifier.
func issuerSigningIdentity() (*ecdsa.PrivateKey, [][]byte, error) {
	base := filepath.Join(*testdataDir, "eudi-pid-issuer-py", "certs")
	keyPEM, err := os.ReadFile(filepath.Join(base, "issuer.key"))
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("issuer key is not PEM")
	}
	var key *ecdsa.PrivateKey
	if parsed, perr := x509.ParseECPrivateKey(block.Bytes); perr == nil {
		key = parsed
	} else {
		any8, perr2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if perr2 != nil {
			return nil, nil, perr2
		}
		var ok bool
		if key, ok = any8.(*ecdsa.PrivateKey); !ok {
			return nil, nil, fmt.Errorf("issuer key is %T", any8)
		}
	}

	chainPEM, err := os.ReadFile(filepath.Join(base, "issuer-chain.pem"))
	if err != nil {
		return nil, nil, err
	}
	var chain [][]byte
	for rest := chainPEM; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			chain = append(chain, b.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, nil, fmt.Errorf("no certificates in issuer chain")
	}
	return key, chain, nil
}

// ============================================================================
// RP certificate defects
// ============================================================================
//
// These are the cases the earlier certificate scenarios cannot reach. [37] and
// [38] cover a certificate that does not chain to a trusted root at all, and [10]
// covers the genuine certificate under a client_id it has no SAN for. What
// neither can produce is a certificate the wallet's own trust store vouches for
// and that is nonetheless unusable — because minting one needs the relying-party
// CA's private key, which testdata carries.

func scenarioLeafExpired() {
	err := withIssuedWallet(func(w *wallet) error {
		key, leaf, mintErr := mintRpLeaf(
			time.Now().Add(-400*24*time.Hour),
			time.Now().Add(-30*24*time.Hour),
			[]string{"localhost"}, false)
		if mintErr != nil {
			return mintErr
		}
		return discloseMintedChain(w, key, [][]byte{leaf}, "", nil)
	})
	rejected(42, "rp cert", "relying party certificate expired a month ago",
		"RFC 5280 §6.1.3", "an expired certificate cannot authenticate a verifier", err,
		"issued by the CA the wallet trusts, correct SAN, valid signature — only the dates are wrong")
}

func scenarioLeafNotYetValid() {
	err := withIssuedWallet(func(w *wallet) error {
		key, leaf, mintErr := mintRpLeaf(
			time.Now().Add(30*24*time.Hour),
			time.Now().Add(400*24*time.Hour),
			[]string{"localhost"}, false)
		if mintErr != nil {
			return mintErr
		}
		return discloseMintedChain(w, key, [][]byte{leaf}, "", nil)
	})
	rejected(43, "rp cert", "relying party certificate not valid for another month",
		"RFC 5280 §6.1.3", "a certificate is unusable before its notBefore", err, "")
}

func scenarioCaCertUsedAsLeaf() {
	err := withIssuedWallet(func(w *wallet) error {
		caCert, caKey, loadErr := relyingPartyCA()
		if loadErr != nil {
			return loadErr
		}
		// The trust anchor itself, presented as the end-entity certificate and
		// signing the request with its own key. It is the most trusted certificate
		// the wallet holds, which is exactly why it must not be able to act as a
		// relying party.
		return discloseMintedChain(w, caKey, [][]byte{caCert.Raw}, "", nil)
	})
	rejected(44, "rp cert", "the trust anchor itself used as the signing leaf",
		"RFC 5280 §4.2.1.9", "a CA certificate must not act as an end entity", err,
		"signed by the root's own key, and the root is in the wallet's trust store")
}

func scenarioX5cLeafIsNotTheSigner() {
	err := withIssuedWallet(func(w *wallet) error {
		// Two certificates, both legitimately issued by the trusted CA for
		// localhost. The request is signed by the second key while the first is
		// presented as the leaf, so every certificate here is trustworthy and the
		// signature is well formed — they simply do not belong together.
		_, decoy, mintErr := mintRpLeaf(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour),
			[]string{"localhost"}, false)
		if mintErr != nil {
			return mintErr
		}
		signingKey, _, mintErr := mintRpLeaf(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour),
			[]string{"localhost"}, false)
		if mintErr != nil {
			return mintErr
		}
		return discloseMintedChain(w, signingKey, [][]byte{decoy}, "", nil)
	})
	rejected(45, "rp cert", "x5c leaf is a valid certificate, but not the signer's",
		"OID4VP 1.0 §5.10", "the signature must verify against the leaf that was presented", err,
		"both certificates are trusted and issued for localhost; only the pairing is wrong")
}

func scenarioX5cEmptyArray() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			hdr["x5c"] = []any{}
		})
	})
	rejected(46, "rp cert", "x5c present but an empty array",
		"OID4VP 1.0 §5.10", "an empty chain names no certificate", err,
		"distinct from [12], where the header is absent altogether")
}

// ============================================================================
// JOSE header
// ============================================================================

func scenarioAlgConfusionHS256() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMintedRaw(w, func(jwtStr string) string {
			return resignAsHS256(jwtStr)
		})
	})
	rejected(47, "jose", "alg switched to HS256 while x5c still carries a key",
		"RFC 8725 §3.1", "an asymmetric key must never be accepted as an HMAC secret", err,
		"the classic algorithm-confusion attack: the certificate's public key is public")
}

func scenarioAlgMismatchES384() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			hdr["alg"] = "ES384"
		})
	})
	rejected(48, "jose", "alg claims ES384 over a P-256 key",
		"RFC 7518 §3.4", "the algorithm must match the key's curve", err, "")
}

func scenarioTwoSegmentJwt() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMintedRaw(w, func(jwtStr string) string {
			parts := strings.Split(jwtStr, ".")
			return parts[0] + "." + parts[1] // signature segment dropped entirely
		})
	})
	rejected(49, "jose", "request object with two segments, no signature part",
		"RFC 7515 §3.1", "a JWS has three segments", err, "")
}

// ============================================================================
// request_uri transport
// ============================================================================

func scenarioRequestUriServesHtml() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseServing(w,
			"<!doctype html><html><body>not a request object</body></html>",
			http.StatusOK, "text/html")
	})
	rejected(50, "transport", "request_uri serves HTML instead of a request object",
		"OID4VP 1.0 §5.6", "a non-JWT body cannot be parsed as a request", err, "")
}

func scenarioRequestUriServerError() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseServing(w, `{"error":"server_error"}`,
			http.StatusInternalServerError, "application/json")
	})
	rejected(51, "transport", "request_uri returns HTTP 500",
		"OID4VP 1.0 §5.6", "a failed fetch must fail the session, not proceed", err, "")
}

func scenarioLinkClientIdMismatch() {
	err := withIssuedWallet(func(w *wallet) error {
		// The request object is the container's own, untouched and validly signed
		// for x509_san_dns:localhost. Only the client_id in the link the wallet was
		// handed says something else.
		return discloseMintedWithClientId(w, "x509_san_dns:other.example",
			func(hdr, claims map[string]any) {})
	})
	rejected(52, "transport", "link's client_id differs from the request object's",
		"OID4VP 1.0 §5.6", "the two must agree, or the link tells the user a different verifier", err,
		"tests whether the client_id delivered out of band is bound to the signed one")
}

// ============================================================================
// Request parameters
// ============================================================================

func scenarioNonceNotUrlSafe() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			claims["nonce"] = "nonce with spaces & symbols"
		})
	})
	rejected(53, "parameters", "nonce carries non-URL-safe characters",
		"OID4VP 1.0 §5.2", "a nonce must be ASCII URL-safe", err,
		"distinct from [23] and [24], which cover absent and empty")
}

func scenarioResponseUriAbsent() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			claims["response_mode"] = "direct_post"
			delete(claims, "response_uri")
			delete(claims, "redirect_uri")
		})
	})
	rejected(54, "parameters", "direct_post with no response_uri to answer",
		"OID4VP 1.0 §5.1", "response_uri is REQUIRED for direct_post", err, "")
}

func scenarioResponseAndRedirectUriTogether() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			claims["redirect_uri"] = "https://localhost/redirect"
		})
	})
	rejected(55, "parameters", "response_uri and redirect_uri both present",
		"OID4VP 1.0 §5.1", "when response_uri is present, redirect_uri must not be", err, "")
}

func scenarioClientIdEmpty() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMintedWithClientId(w, "x509_san_dns:localhost",
			func(hdr, claims map[string]any) {
				claims["client_id"] = ""
			})
	})
	rejected(56, "parameters", "client_id is the empty string",
		"OID4VP 1.0 §5.10", "a verifier with no identifier cannot be authenticated", err, "")
}

func scenarioClientIdNoPrefix() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMintedWithClientId(w, "some-preregistered-verifier",
			func(hdr, claims map[string]any) {
				claims["client_id"] = "some-preregistered-verifier"
			})
	})
	rejected(57, "parameters", "client_id with no scheme prefix (pre-registered)",
		"OID4VP 1.0 §5.10", "there is no registry to resolve a bare identifier against", err,
		"distinct from [11]: that names a scheme this wallet declines, this names none at all")
}

// ============================================================================
// DCQL detail
// ============================================================================

func scenarioClaimPathEmpty() {
	q := map[string]any{
		"credentials": []map[string]any{{
			"id":     queryID,
			"format": "mso_mdoc",
			"meta":   map[string]any{"doctype_value": docType},
			"claims": []map[string]any{{"path": []string{}}},
		}},
	}
	err := discloseQuery(q)
	rejected(58, "dcql", "claims entry with an empty path array",
		"OID4VP 1.0 §6.4", "a claim path must be non-empty", err, "")
}

func scenarioMdocQueryWithoutMeta() {
	q := map[string]any{
		"credentials": []map[string]any{{
			"id":     queryID,
			"format": "mso_mdoc",
			"claims": []map[string]any{{"path": []string{namespace, "age_over_18"}}},
		}},
	}
	err := discloseQuery(q)
	rejected(59, "dcql", "mso_mdoc query with no meta.doctype_value",
		"OID4VP 1.0 §6.1", "doctype_value is REQUIRED for mso_mdoc", err, "")
}

func scenarioCredentialSetEmptyOptions() {
	err := withIssuedWallet(func(w *wallet) error {
		return discloseMinted(w, func(hdr, claims map[string]any) {
			query, ok := claims["dcql_query"].(map[string]any)
			if !ok {
				return
			}
			query["credential_sets"] = []any{
				map[string]any{"options": []any{}, "required": true},
			}
		})
	})
	rejected(60, "dcql", "credential_sets entry with an empty options array",
		"OID4VP 1.0 §6.2", "options must be a non-empty array", err,
		"distinct from [36], where options name an id the query does not define")
}

func scenarioClaimValuesUnsatisfiable() {
	q := map[string]any{
		"credentials": []map[string]any{{
			"id":     queryID,
			"format": "mso_mdoc",
			"meta":   map[string]any{"doctype_value": docType},
			// The wallet holds age_over_18 = true, so a query constrained to false
			// matches nothing and must not be answered with the value it does hold.
			"claims": []map[string]any{{
				"path":   []string{namespace, "age_over_18"},
				"values": []any{false},
			}},
		}},
	}
	err := discloseQuery(q)
	rejected(61, "dcql", "claim values constraint the credential does not satisfy",
		"OID4VP 1.0 §6.4.1", "a value constraint that matches nothing yields no presentation", err,
		"the danger is answering with age_over_18=true when only false was acceptable")
}

// ============================================================================
// Certificate minting against the relying-party CA
// ============================================================================

// relyingPartyCA loads the CA the wallet trusts for verifiers, together with its
// private key. Holding the key is what lets these scenarios produce
// certificates that genuinely chain to the wallet's trust anchor.
func relyingPartyCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	base := filepath.Join(*testdataDir, "eudi", "verifier")

	certPEM, err := os.ReadFile(filepath.Join(base, "ca.crt"))
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("verifier CA is not PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err := os.ReadFile(filepath.Join(base, "ca_ec_priv.pem"))
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("verifier CA key is not PEM")
	}
	if key, perr := x509.ParseECPrivateKey(keyBlock.Bytes); perr == nil {
		return caCert, key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("verifier CA key is %T, not ECDSA", parsed)
	}
	return caCert, key, nil
}

// mintRpLeaf issues an end-entity certificate from the relying-party CA with the
// given validity window and DNS names, returning its key and DER.
func mintRpLeaf(notBefore, notAfter time.Time, dnsNames []string, isCA bool) (*ecdsa.PrivateKey, []byte, error) {
	caCert, caKey, err := relyingPartyCA()
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost", Organization: []string{"Yivi"}},
		DNSNames:              dnsNames,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	return key, der, nil
}

// resignAsHS256 rewrites the header to alg:HS256 and appends an HMAC computed
// with the leaf's public key as the secret — the shape an algorithm-confusion
// attack takes, since that key is published in the x5c header for anyone to read.
func resignAsHS256(jwtStr string) string {
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return jwtStr
	}
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return jwtStr
	}
	var hdr map[string]any
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return jwtStr
	}

	// The public key the original header advertises, used as the HMAC secret.
	secret := []byte("unknown")
	if chain, ok := hdr["x5c"].([]any); ok && len(chain) > 0 {
		if first, ok := chain[0].(string); ok {
			if der, derr := base64.StdEncoding.DecodeString(first); derr == nil {
				if cert, cerr := x509.ParseCertificate(der); cerr == nil {
					if spki, serr := x509.MarshalPKIXPublicKey(cert.PublicKey); serr == nil {
						secret = spki
					}
				}
			}
		}
	}

	hdr["alg"] = "HS256"
	newHdr, err := json.Marshal(hdr)
	if err != nil {
		return jwtStr
	}
	input := base64.RawURLEncoding.EncodeToString(newHdr) + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// discloseMintedChain re-signs the container's request with the given key and
// presents the given x5c chain. clientID defaults to the session's own.
func discloseMintedChain(
	w *wallet,
	key *ecdsa.PrivateKey,
	chain [][]byte,
	clientID string,
	mutate func(hdr, claims map[string]any),
) error {
	return discloseMintedKeyed(w, key, func(hdr, claims map[string]any) {
		encoded := make([]any, 0, len(chain))
		for _, der := range chain {
			encoded = append(encoded, base64.StdEncoding.EncodeToString(der))
		}
		hdr["x5c"] = encoded
		if mutate != nil {
			mutate(hdr, claims)
		}
	})
}

// discloseServing points the wallet at a request_uri returning an arbitrary body
// and status, for the cases where the transport itself is what misbehaves.
func discloseServing(w *wallet, body string, status int, contentType string) error {
	s, err := createVerifierSession(*verifierJwt, defaultDcql(docType, namespace, "age_over_18", "mso_mdoc"), nil)
	if err != nil {
		return err
	}
	r, err := startRogue("")
	if err != nil {
		return err
	}
	defer r.stop()
	r.serveRaw(body, status, contentType)
	return w.disclose(r.link(s.ClientID))
}

// ============================================================================
// Scenario plumbing
// ============================================================================

func defaultClaims() map[string]any {
	return map[string]any{"age_over_18": true, "age_over_21": true}
}

func defaultDcql(dt, ns, element, format string) map[string]any {
	return map[string]any{
		"credentials": []map[string]any{{
			"id":     queryID,
			"format": format,
			"meta":   map[string]any{"doctype_value": dt},
			"claims": []map[string]any{{"path": []string{ns, element}}},
		}},
	}
}

// withIssuedWallet gives the body a wallet that already holds a good credential.
func withIssuedWallet(body func(*wallet) error) error {
	w, err := newWallet(true, true)
	if err != nil {
		return err
	}
	defer w.close()
	if err := w.issueGood(); err != nil {
		return err
	}
	return body(w)
}

// discloseQuery issues a credential, asks the real verifier for the given query,
// and drives the wallet at it.
func discloseQuery(q map[string]any) error {
	return withIssuedWallet(func(w *wallet) error {
		s, err := createVerifierSession(*verifierJwt, q, nil)
		if err != nil {
			return err
		}
		return w.disclose(s.Link)
	})
}

// discloseMinted takes the container's real request, applies mutate to its header
// and claims, re-signs, serves it locally, and points the wallet at it.
func discloseMinted(w *wallet, mutate func(hdr, claims map[string]any)) error {
	return discloseMintedWithClientId(w, "", mutate)
}

// discloseMintedKeyed is discloseMinted with the request re-signed by a key
// other than the reference verifier's.
func discloseMintedKeyed(w *wallet, key *ecdsa.PrivateKey, mutate func(hdr, claims map[string]any)) error {
	s, err := createVerifierSession(*verifierJwt, defaultDcql(docType, namespace, "age_over_18", "mso_mdoc"), nil)
	if err != nil {
		return err
	}
	real, err := fetchRequestJwt(s.Link)
	if err != nil {
		return err
	}
	minted, err := mintVariantWith(real, key, mutate)
	if err != nil {
		return err
	}
	r, err := startRogue(minted)
	if err != nil {
		return err
	}
	defer r.stop()
	return w.disclose(r.link(s.ClientID))
}

func discloseMintedWithClientId(w *wallet, clientID string, mutate func(hdr, claims map[string]any)) error {
	s, err := createVerifierSession(*verifierJwt, defaultDcql(docType, namespace, "age_over_18", "mso_mdoc"), nil)
	if err != nil {
		return err
	}
	real, err := fetchRequestJwt(s.Link)
	if err != nil {
		return err
	}
	minted, err := mintVariant(real, mutate)
	if err != nil {
		return err
	}
	if clientID == "" {
		clientID = s.ClientID
	}
	r, err := startRogue(minted)
	if err != nil {
		return err
	}
	defer r.stop()
	return w.disclose(r.link(clientID))
}

// discloseMintedRaw is discloseMinted for changes that operate on the serialized
// JWT rather than its decoded parts.
func discloseMintedRaw(w *wallet, mutate func(string) string) error {
	s, err := createVerifierSession(*verifierJwt, defaultDcql(docType, namespace, "age_over_18", "mso_mdoc"), nil)
	if err != nil {
		return err
	}
	real, err := fetchRequestJwt(s.Link)
	if err != nil {
		return err
	}
	r, err := startRogue(mutate(real))
	if err != nil {
		return err
	}
	defer r.stop()
	return w.disclose(r.link(s.ClientID))
}

// ============================================================================
// Minting adversarial requests
// ============================================================================

func verifierKey() (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(filepath.Join(*testdataDir, "eudi", "verifier", "verifier_ec_priv.pem"))
	if err != nil {
		return nil, fmt.Errorf("read verifier key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("verifier key is not PEM")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	any8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse verifier key: %w", err)
	}
	key, ok := any8.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("verifier key is %T, not ECDSA", any8)
	}
	return key, nil
}

func signES256(key *ecdsa.PrivateKey, input string) (string, error) {
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func mintVariant(realJwt string, mutate func(hdr, claims map[string]any)) (string, error) {
	return mintVariantWith(realJwt, nil, mutate)
}

// mintVariantWith re-signs with key, or with the reference verifier's own key
// when key is nil.
func mintVariantWith(realJwt string, key *ecdsa.PrivateKey, mutate func(hdr, claims map[string]any)) (string, error) {
	parts := strings.Split(realJwt, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("request is not a three-part JWS (%d parts)", len(parts))
	}
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode header: %w", err)
	}
	claimRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode claims: %w", err)
	}
	var hdr, claims map[string]any
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return "", fmt.Errorf("parse header: %w", err)
	}
	if err := json.Unmarshal(claimRaw, &claims); err != nil {
		return "", fmt.Errorf("parse claims: %w", err)
	}

	mutate(hdr, claims)

	newHdr, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	newClaims, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(newHdr) + "." +
		base64.RawURLEncoding.EncodeToString(newClaims)

	if hdr["alg"] == "none" {
		return input + ".", nil
	}
	if key == nil {
		key, err = verifierKey()
		if err != nil {
			return "", err
		}
	}
	sig, err := signES256(key, input)
	if err != nil {
		return "", err
	}
	return input + "." + sig, nil
}

// rogue serves one request JWT, standing in for the verifier's request_uri. It
// also exposes a /response endpoint so a scenario can tell whether the wallet
// was willing to send its answer somewhere the verifier's certificate says
// nothing about.
type rogue struct {
	srv      *http.Server
	base     string
	jwt      atomic.Pointer[string]
	raw      atomic.Pointer[rawResponse]
	captured chan string
}

func startRogue(jwt string) (*rogue, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &rogue{captured: make(chan string, 4)}
	r.jwt.Store(&jwt)
	mux := http.NewServeMux()
	mux.HandleFunc("/request.jwt", func(w http.ResponseWriter, _ *http.Request) {
		if override := r.raw.Load(); override != nil {
			w.Header().Set("Content-Type", override.contentType)
			w.WriteHeader(override.status)
			_, _ = io.WriteString(w, override.body)
			return
		}
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		if current := r.jwt.Load(); current != nil {
			_, _ = io.WriteString(w, *current)
		}
	})
	mux.HandleFunc("/response", func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		select {
		case r.captured <- string(body):
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	})
	r.srv = &http.Server{Handler: mux}
	r.base = "http://" + ln.Addr().String()
	go func() { _ = r.srv.Serve(ln) }()
	return r, nil
}

// serve sets the JWT this server hands out, for scenarios that need the
// server's own URL before the request can be built.
func (r *rogue) serve(jwt string) { r.jwt.Store(&jwt) }

// rawResponse replaces the request_uri response wholesale, so a scenario can
// misbehave at the transport level rather than in the request object.
type rawResponse struct {
	body        string
	status      int
	contentType string
}

func (r *rogue) serveRaw(body string, status int, contentType string) {
	r.raw.Store(&rawResponse{body: body, status: status, contentType: contentType})
}

// exfiltrated reports whether the wallet posted anything to the rogue host.
func (r *rogue) exfiltrated() (string, bool) {
	select {
	case body := <-r.captured:
		return body, true
	case <-time.After(2 * time.Second):
		return "", false
	}
}

func (r *rogue) link(clientID string) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("request_uri", r.base+"/request.jwt")
	q.Set("request_uri_method", "get")
	return "eudi-openid4vp://?" + q.Encode()
}

func (r *rogue) stop() { _ = r.srv.Close() }

// ============================================================================
// The issuer and verifier, over HTTP
// ============================================================================

type offerResponse struct {
	URI    string
	TxCode string
}

func createOfferRaw(configID string, data map[string]any) (map[string]any, error) {
	payload, err := json.Marshal(map[string]any{
		"credentials": []map[string]any{{
			"credential_configuration_id": configID,
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
	resp, err := http.Post(*issuerURL+"/credentialOfferReq2",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("post credential offer request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("issuer refused the offer request: HTTP %d %s", resp.StatusCode, oneLine(string(body)))
	}
	var offer map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&offer); err != nil {
		return nil, fmt.Errorf("decode offer: %w", err)
	}
	if _, ok := offer["credential_issuer"]; !ok {
		return nil, fmt.Errorf("issuer returned no credential offer: %v", offer)
	}
	return offer, nil
}

func createOffer(configID string, data map[string]any) (*offerResponse, error) {
	raw, err := createOfferRaw(configID, data)
	if err != nil {
		return nil, err
	}
	code, err := transactionCode(raw)
	if err != nil {
		return nil, err
	}
	return &offerResponse{URI: offerURI(raw), TxCode: code}, nil
}

func offerURI(offer map[string]any) string {
	encoded, _ := json.Marshal(offer)
	return "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(encoded))
}

func transactionCode(offer map[string]any) (string, error) {
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

type verifierSession struct {
	TransactionID string
	ClientID      string
	Link          string
}

func createVerifierSession(host string, dcqlQuery map[string]any, tweak func(map[string]any)) (*verifierSession, error) {
	issuerCA, err := os.ReadFile(filepath.Join(*testdataDir, "eudi-pid-issuer-py", "certs", "ca.pem"))
	if err != nil {
		return nil, fmt.Errorf("read issuer CA: %w", err)
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}

	body := map[string]any{
		"type":               "vp_token",
		"dcql_query":         dcqlQuery,
		"nonce":              base64.RawURLEncoding.EncodeToString(nonceBytes),
		"jar_mode":           "by_reference",
		"request_uri_method": "get",
		"intended_use_id":    intendedUseID,
		"issuer_chain":       string(issuerCA),
	}
	if tweak != nil {
		tweak(body)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(host+"/ui/presentations", "application/json", strings.NewReader(string(encoded)))
	if err != nil {
		return nil, fmt.Errorf("start verifier session: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("verifier refused the session request: HTTP %d %s", resp.StatusCode, oneLine(string(raw)))
	}
	var fields map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&fields); err != nil {
		return nil, fmt.Errorf("decode verifier response: %w", err)
	}
	query := url.Values{}
	for key, value := range fields {
		query.Add(key, value)
	}
	return &verifierSession{
		TransactionID: fields["transaction_id"],
		ClientID:      fields["client_id"],
		Link:          "eudi-openid4vp://?" + query.Encode(),
	}, nil
}

func fetchRequestJwt(link string) (string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", err
	}
	requestUri := u.Query().Get("request_uri")
	if requestUri == "" {
		return "", fmt.Errorf("link carries no request_uri")
	}
	resp, err := http.Get(requestUri)
	if err != nil {
		return "", fmt.Errorf("fetch request jwt: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func requestClaims(link string) (map[string]any, error) {
	jwt, err := fetchRequestJwt(link)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("request jwt has %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// presentedDocument returns the base64 vp_token entry the verifier recorded for
// a transaction, or an error if it recorded none.
func presentedDocument(host string, s *verifierSession) (string, error) {
	resp, err := http.Get(host + "/ui/presentations/" + s.TransactionID)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("verifier has no wallet response: HTTP %d", resp.StatusCode)
	}
	var walletResponse map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&walletResponse); err != nil {
		return "", err
	}
	vpToken, ok := walletResponse["vp_token"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no vp_token in the recorded response")
	}
	entry, ok := vpToken[queryID]
	if !ok {
		return "", fmt.Errorf("no vp_token entry for query %q", queryID)
	}
	if encoded, ok := entry.(string); ok {
		return encoded, nil
	}
	list, ok := entry.([]any)
	if !ok || len(list) == 0 {
		return "", fmt.Errorf("unexpected vp_token shape %T", entry)
	}
	encoded, ok := list[0].(string)
	if !ok {
		return "", fmt.Errorf("unexpected vp_token entry %T", list[0])
	}
	return encoded, nil
}

// ============================================================================
// The wallet
// ============================================================================

type wallet struct {
	client   *client.Client
	states   chan clientmodels.SessionState
	tempRoot string
	session  int
}

func newWallet(trustIssuer, trustVerifier bool) (*wallet, error) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	tempRoot, err := os.MkdirTemp("", "mdoc-violations-")
	if err != nil {
		return nil, err
	}
	storagePath := filepath.Join(tempRoot, "client")
	irmaConfigurationPath := filepath.Join(storagePath, "irma_configuration")
	eudiAppDataPath := filepath.Join(storagePath, "eudi")

	if err := common.CopyDirectory(filepath.Join(*testdataDir, "irma_configuration"), irmaConfigurationPath); err != nil {
		return nil, fmt.Errorf("copy irma_configuration: %w", err)
	}
	if err := common.EnsureDirectoryExists(eudiAppDataPath); err != nil {
		return nil, err
	}

	middleware := encryption.NewAESEncryptionMiddleware(aesKey)
	trust := func(dir, name, source string) error {
		raw, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		path := filepath.Join(eudiAppDataPath, dir, "certificates")
		if err := common.EnsureDirectoryExists(path); err != nil {
			return err
		}
		encrypted, err := middleware.Encrypt(raw)
		if err != nil {
			return err
		}
		return common.SaveFile(filepath.Join(path, name), encrypted)
	}
	if trustIssuer {
		if err := trust("issuers", "pid-issuer-ca.pem",
			filepath.Join(*testdataDir, "eudi-pid-issuer-py", "certs", "ca.pem")); err != nil {
			return nil, err
		}
	}
	if trustVerifier {
		if err := trust("verifiers", "verifier-ca.pem",
			filepath.Join(*testdataDir, "eudi", "verifier", "ca.crt")); err != nil {
			return nil, err
		}
	}

	states := make(chan clientmodels.SessionState, 64)
	signer, err := newSigner()
	if err != nil {
		return nil, err
	}
	c, err := client.New(storagePath, irmaConfigurationPath, eudiAppDataPath,
		&quietHandler{}, &channelSessionHandler{states: states}, signer, aesKey, "en")
	if err != nil {
		return nil, fmt.Errorf("create wallet: %w", err)
	}
	c.SetPreferences(clientsettings.Preferences{DeveloperMode: true})
	return &wallet{client: c, states: states, tempRoot: tempRoot}, nil
}

func (w *wallet) close() {
	w.client.Close()
	_ = os.RemoveAll(w.tempRoot)
}

func (w *wallet) nextSession() int {
	w.session++
	return w.session
}

func (w *wallet) await(want clientmodels.SessionStatus) (clientmodels.SessionState, error) {
	return w.awaitOneOf(want)
}

// awaitOneOf blocks until the wallet reports any of want. More than one is
// needed because a rejected transaction code does not surface as an error state:
// the wallet returns to the code prompt so the user can try again, and a caller
// watching only for the next step would sit there until the timeout.
func (w *wallet) awaitOneOf(want ...clientmodels.SessionStatus) (clientmodels.SessionState, error) {
	matches := func(s clientmodels.SessionStatus) bool {
		for _, candidate := range want {
			if s == candidate {
				return true
			}
		}
		return false
	}
	for {
		select {
		case state := <-w.states:
			if state.Status == clientmodels.Status_Error {
				detail := ""
				if state.Error != nil {
					detail = state.Error.WrappedError
					if detail == "" {
						detail = state.Error.ErrorType
					}
				}
				return state, fmt.Errorf("%s", detail)
			}
			if state.Status == clientmodels.Status_Dismissed {
				return state, fmt.Errorf("session dismissed by the wallet")
			}
			if matches(state.Status) {
				return state, nil
			}
		case <-time.After(stateTimeout):
			return clientmodels.SessionState{}, fmt.Errorf("timed out waiting for %v", want)
		}
	}
}

func (w *wallet) issueGood() error {
	offer, err := createOffer(credentialConfigID, defaultClaims())
	if err != nil {
		return err
	}
	return w.issue(offer.URI, offer.TxCode)
}

func (w *wallet) issue(offerURI, txCode string) error {
	id := w.nextSession()
	request, err := json.Marshal(client.SessionRequestData{
		Qr:                    irma.Qr{URL: offerURI},
		Protocol:              clientmodels.Protocol_OpenID4VCI,
		OpenID4VCIRedirectUri: "https://open.yivi.app/-/auth-callback",
	})
	if err != nil {
		return err
	}
	w.client.NewSession(id, string(request))

	if _, err := w.await(clientmodels.Status_RequestPreAuthorizedCode); err != nil {
		return err
	}
	go func() {
		_ = w.client.HandleUserInteraction(clientmodels.SessionUserInteraction{
			SessionId: id,
			Type:      clientmodels.UI_PreAuthorizedCode,
			Payload: clientmodels.SessionPreAuthorizedCodeInteractionPayload{
				Proceed:         true,
				TransactionCode: &txCode,
			},
		})
	}()

	// Either the wallet moves on to the permission prompt, or it comes back to
	// the code prompt — which is how a token endpoint that refused the code
	// surfaces, since the wallet lets the user retry rather than erroring out.
	state, err := w.awaitOneOf(clientmodels.Status_RequestPermission, clientmodels.Status_RequestPreAuthorizedCode)
	if err != nil {
		return err
	}
	if state.Status == clientmodels.Status_RequestPreAuthorizedCode {
		return fmt.Errorf("the token endpoint refused the pre-authorized code; the wallet re-prompted for it")
	}

	go func() {
		_ = w.client.HandleUserInteraction(clientmodels.SessionUserInteraction{
			SessionId: id,
			Type:      clientmodels.UI_Permission,
			Payload:   clientmodels.SessionPermissionInteractionPayload{Granted: true},
		})
	}()

	_, err = w.await(clientmodels.Status_Success)
	return err
}

func (w *wallet) disclose(link string) error {
	id := w.nextSession()
	request, err := json.Marshal(client.SessionRequestData{
		Qr:       irma.Qr{Type: irma.ActionDisclosing, URL: link},
		Protocol: clientmodels.Protocol_OpenID4VP,
	})
	if err != nil {
		return err
	}
	w.client.NewSession(id, string(request))

	state, err := w.await(clientmodels.Status_RequestPermission)
	if err != nil {
		return err
	}
	if state.DisclosurePlan == nil || len(state.DisclosurePlan.DisclosureChoicesOverview) == 0 {
		return fmt.Errorf("the wallet produced no disclosure plan for this request")
	}
	overview := state.DisclosurePlan.DisclosureChoicesOverview[0]
	if len(overview.OwnedOptions) == 0 {
		return fmt.Errorf("the wallet holds no credential satisfying the request")
	}
	chosen := overview.OwnedOptions[0]

	go func() {
		_ = w.client.HandleUserInteraction(clientmodels.SessionUserInteraction{
			SessionId: id,
			Type:      clientmodels.UI_Permission,
			Payload: clientmodels.SessionPermissionInteractionPayload{
				Granted:           true,
				DisclosureChoices: []clientmodels.DisclosureDisconSelection{disclosureChoice(chosen)},
			},
		})
	}()

	_, err = w.await(clientmodels.Status_Success)
	return err
}

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
// Wallet plumbing
// ============================================================================

type channelSessionHandler struct {
	states chan clientmodels.SessionState
}

func (h *channelSessionHandler) UpdateSession(state clientmodels.SessionState) {
	h.states <- state
}

type quietHandler struct{}

func (*quietHandler) CredentialsChanged()                                   {}
func (*quietHandler) ReportError(error)                                     {}
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
		return nil, err
	}
	return &ecdsaSigner{key: key}, nil
}

func (s *ecdsaSigner) PublicKey(string) ([]byte, error) {
	return signed.MarshalPublicKey(&s.key.PublicKey)
}

func (s *ecdsaSigner) Sign(_ string, message []byte) ([]byte, error) {
	return signed.Sign(s.key, message)
}

func trustProxyCertificate() {
	raw, err := os.ReadFile(filepath.Join(*testdataDir, "configurations", "certs", "localhost.crt"))
	if err != nil {
		return
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM(raw)
	http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
}
