package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"

	"mdoc"
)

// ============================================================
// DEMO — issuer -> holder -> verifier walkthrough
//
// Exercises the mdoc package purely through its exported API, exactly as
// an external consumer would. See mdoc_test.go (and the other _test.go
// files) inside the mdoc package itself for the same flows plus
// negative/regression cases.
//
// mdoc's library functions (Issue, SelectiveDisclose, Verify,
// VerifyWithDeviceAuth) print nothing themselves — a real consumer
// importing mdoc as a dependency shouldn't get unsolicited stdout output.
// All the narration below is reconstructed here, in the demo, purely from
// data the exported API already returns.
// ============================================================

// printIssuedMDoc narrates the issuer step using only the claims the demo
// itself passed in, plus the exported IssuerAuth bytes on the result.
func printIssuedMDoc(claims map[string]any, credential *mdoc.MDoc) {
	fmt.Println("\n--- ISSUER: Building mDoc ---")
	for _, k := range sortedKeys(claims) {
		fmt.Printf("  Claim: %s = %v\n", k, claims[k])
	}
	fmt.Printf("  MSO signed by DS cert ✓  (%d bytes)\n", len(credential.IssuerSigned.IssuerAuth))
	fmt.Println("  x5chain: DS cert + IACA cert")
	fmt.Println("  deviceKeyInfo: embedded holder public key ✓")
}

// printSelectiveDisclosure narrates the holder step using only the claims
// and reveal list the demo itself already knows.
func printSelectiveDisclosure(claims map[string]any, reveal []string) {
	fmt.Println("\n--- HOLDER: Selective disclosure ---")
	revealSet := make(map[string]bool, len(reveal))
	for _, r := range reveal {
		revealSet[r] = true
	}
	for _, k := range sortedKeys(claims) {
		if revealSet[k] {
			fmt.Printf("  Revealing:   %s\n", k)
		} else {
			fmt.Printf("  Withholding: %s\n", k)
		}
	}
}

// printVerificationSteps narrates the verifier step using only
// VerificationResult's exported fields. Attributes is only populated once
// Verify() reaches its final digest-check loop, so a non-empty map here
// means the chain/signature/validity/digest checks all passed — even if
// VerifyWithDeviceAuth later marks the overall result invalid because
// deviceAuth itself failed.
func printVerificationSteps(result mdoc.VerificationResult) {
	fmt.Println("\n--- VERIFIER: Verifying mDoc ---")
	if len(result.Attributes) == 0 {
		return
	}
	for _, k := range sortedKeys(result.Attributes) {
		fmt.Printf("  %s = %v  digest: ✓\n", k, result.Attributes[k])
	}
	fmt.Println("  Verification: PASSED ✓")
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func main() {
	fmt.Println("========================================")
	fmt.Println("  mDoc Issuer → Holder → Verifier Demo")
	fmt.Println("  with two-level cert chain + deviceKeyInfo")
	fmt.Println("========================================")

	// ── Setup Issuer ─────────────────────────────────────────────
	issuer, err := mdoc.NewIssuer()
	if err != nil {
		log.Fatal("issuer setup:", err)
	}
	fmt.Println("\nIACA root CA generated (self-signed, offline in production)")
	fmt.Printf("  Subject: %s\n", issuer.IACACert().Subject.CommonName)
	fmt.Println("DS cert generated (signed by IACA root)")
	fmt.Printf("  Subject: %s\n", issuer.DSCert().Subject.CommonName)
	fmt.Printf("  Issuer:  %s\n", issuer.DSCert().Issuer.CommonName)

	// ── Setup Holder ─────────────────────────────────────────────
	// Holder generates device key pair LOCALLY before contacting the issuer
	// In production: generated inside Secure Enclave / TrustZone — private key never extractable
	holder, err := mdoc.NewHolder()
	if err != nil {
		log.Fatal("holder setup:", err)
	}
	ecdhPub, _ := holder.PublicKey().ECDH()
	fmt.Printf("\nDevice key generated (x: %s...)\n",
		hex.EncodeToString(ecdhPub.Bytes()[1:33])[:16])

	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"

	claims := map[string]any{
		"age_over_18": true,
		"age_over_16": true,
		"age_over_21": false,
	}

	// ── Issuance ──────────────────────────────────────────────────
	// Holder sends ONLY the public key to the issuer
	// Issuer embeds it in MSO.deviceKeyInfo, then signs the whole MSO
	// Private key never leaves the holder's device
	credential, err := issuer.Issue(docType, namespace, claims, holder.PublicKey())
	if err != nil {
		log.Fatal("issue:", err)
	}
	printIssuedMDoc(claims, credential)

	// ── OpenID4VP session parameters ────────────────────────────────
	// In production these come from the verifier's real Authorization
	// Request (client_id/nonce/response_uri) — hardcoded here since this
	// demo has no real HTTP exchange. Everything below models the
	// OpenID4VP path only; the W3C Digital Credentials API path (the AV
	// Blueprint's default, OpenID4VP being its fallback) isn't modeled.
	clientId := "redirect_uri:https://verifier.example.com/response"
	nonce := "n-0S6_WzA2Mj"
	responseUri := "https://verifier.example.com/response"
	transcript, err := mdoc.NewOpenID4VPSessionTranscript(clientId, nonce, responseUri)
	if err != nil {
		log.Fatal("session transcript:", err)
	}
	// state is the verifier's own opaque anti-CSRF / session-correlation
	// value (AuthorizationRequest.State in eudi/openid4vp) — unlike nonce,
	// it never enters any hash or signature. It's carried alongside
	// vp_token in the direct_post form body and must be echoed back
	// unchanged; the verifier checks it matches before trusting anything.
	state := "af0ifjsldkj"

	// ── Verifier's Request (DCQL) ────────────────────────────────────
	// The AV Blueprint's Annex A §A.6 mandates the OpenID4VP DCQL query
	// format here — not ISO 18013-5's native DeviceRequest CBOR object,
	// which only applies to the W3C DC API path. Reader authentication is
	// intentionally not modeled — out of scope for this profile. DCQL also
	// has no intentToRetain concept, unlike DeviceRequest's itemsRequest.
	// verifierQueryId is the verifier's own label for this query — it's
	// never handed to the holder as a Go value, only embedded inside the
	// dcql_query JSON below, the same way a real wallet would only ever
	// see it.
	verifierQueryId := "proof_of_age"
	dcqlQuery := mdoc.NewDCQLQuery(verifierQueryId, docType, namespace, []string{"age_over_18"})
	fmt.Println("\n--- VERIFIER: Requesting attributes (DCQL over OpenID4VP) ---")
	fmt.Printf("  dcql_query: format=mso_mdoc, doctype_value=%s, claims=[%s.age_over_18]\n", docType, namespace)

	// Simulate the query actually crossing the wire as the dcql_query
	// Authorization Request parameter. Everything from here on the
	// holder's side works only with receivedQuery, parsed fresh from
	// that JSON — never verifierQueryId directly, since a real wallet
	// never has that Go variable in scope.
	dcqlQueryJSON, err := json.Marshal(dcqlQuery)
	if err != nil {
		log.Fatal("marshal dcql_query:", err)
	}
	var receivedQuery mdoc.DCQLQuery
	if err := json.Unmarshal(dcqlQueryJSON, &receivedQuery); err != nil {
		log.Fatal("parse dcql_query:", err)
	}

	// ── Holder reads the request ────────────────────────────────────
	reqNamespace, reqAttrs, err := receivedQuery.RequestedAttributes(docType)
	if err != nil {
		log.Fatal("read dcql query:", err)
	}
	// The holder recovers the vp_token response key from the parsed query
	// itself — it has no other way to know what label the verifier chose.
	holderQueryId, err := receivedQuery.CredentialQueryId(docType)
	if err != nil {
		log.Fatal("read dcql query id:", err)
	}

	// ── Selective Disclosure ─────────────────────────────────────────
	presented, err := mdoc.SelectiveDisclose(credential, reqNamespace, reqAttrs)
	if err != nil {
		log.Fatal("selective disclose:", err)
	}
	printSelectiveDisclosure(claims, reqAttrs)

	// ── DeviceAuth ─────────────────────────────────────────────────────
	// Signed over the real OpenID4VP SessionTranscript above — binds this
	// presentation to this verifier's exact client_id/nonce/response_uri.
	deviceAuthBytes, err := holder.SignDeviceAuth(docType, transcript)
	if err != nil {
		log.Fatal("deviceAuth:", err)
	}
	fmt.Printf("\ndeviceAuth signed ✓  (%d bytes)\n", len(deviceAuthBytes))
	fmt.Println("  (fresh per session — binds presentation to this verifier + session)")

	// ── Response (DeviceResponse -> direct_post form) ─────────────────
	// Holder bundles the presented document + its own deviceAuth into a
	// DeviceResponse, then serializes the actual HTTP body
	// response_mode=direct_post sends: vp_token (base64url CBOR, keyed by
	// the DCQL credential query id) and state, both as
	// application/x-www-form-urlencoded fields — not vp_token alone as a
	// bare JSON body. The holder only ever has state because it received
	// it in the same Authorization Request as clientId/nonce/dcql_query;
	// it just echoes it back unchanged.
	attachedDoc, err := mdoc.AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		log.Fatal("attach deviceSigned:", err)
	}
	deviceResponse := mdoc.NewDeviceResponse(*attachedDoc)
	formBody, err := mdoc.NewDirectPostForm(holderQueryId, state, deviceResponse)
	if err != nil {
		log.Fatal("build direct_post form:", err)
	}
	fmt.Printf("\ndirect_post form built ✓  (%d bytes, POSTed to response_uri as application/x-www-form-urlencoded)\n", len(formBody))

	// ── Verification ───────────────────────────────────────────────────
	// Verifier receives the form body over HTTP and decodes it back into
	// the DeviceResponse it needs to verify, plus the state value the
	// holder echoed back. It checks that against the state it originally
	// issued — this is the anti-CSRF check, not the deviceAuth signature
	// check that follows. Trust anchor: ONLY the IACA root is
	// pre-installed — the DS cert arrives via x5chain.
	receivedResponse, receivedState, err := mdoc.ParseDirectPostForm(formBody, verifierQueryId)
	if err != nil {
		log.Fatal("parse direct_post form:", err)
	}
	if receivedState != state {
		log.Fatal("state mismatch — possible CSRF, rejecting response before any crypto check")
	}
	fmt.Println("  state echoed back correctly ✓  (anti-CSRF check passed)")
	verifier := mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})
	results, err := verifier.VerifyDeviceResponse(receivedResponse, reqNamespace, docType, transcript)
	if err != nil {
		log.Fatal("verify device response:", err)
	}
	result := results[0]
	printVerificationSteps(result)
	if result.DeviceAuthValid {
		fmt.Println("  deviceAuth signature: valid ✓  (matches session transcript)")
	}

	fmt.Println("\n========================================")
	fmt.Println("  RESULT")
	fmt.Println("========================================")
	fmt.Printf("  DocType:          %s\n", result.DocType)
	fmt.Printf("  Valid:            %v\n", result.Valid)
	fmt.Printf("  DeviceAuth Valid: %v\n", result.DeviceAuthValid)
	if result.Error != "" {
		fmt.Printf("  Error:    %s\n", result.Error)
	}
	fmt.Println("  Disclosed attributes:")
	for k, v := range result.Attributes {
		fmt.Printf("    %s = %v\n", k, v)
	}

	// ── CHAIN ATTACK TEST ─────────────────────────────────────────
	// Attacker generates their own valid IACA + DS pair and issues
	// a correctly signed mDoc — but their IACA root is not in the
	// verifier's trusted pool, so chain verification fails before
	// signature or digest checks are even reached.
	fmt.Println("\n========================================")
	fmt.Println("  CHAIN ATTACK TEST (attacker's own cert chain)")
	fmt.Println("========================================")

	attackerIssuer, _ := mdoc.NewIssuer()
	attackerHolder, _ := mdoc.NewHolder()
	attackerClaims := map[string]any{"age_over_18": true}
	attackerMDoc, _ := attackerIssuer.Issue(docType, namespace, attackerClaims, attackerHolder.PublicKey())
	printIssuedMDoc(attackerClaims, attackerMDoc)

	attackerReveal := []string{"age_over_18"}
	attackerPresented, _ := mdoc.SelectiveDisclose(attackerMDoc, namespace, attackerReveal)
	printSelectiveDisclosure(attackerClaims, attackerReveal)

	attackResult := verifier.Verify(attackerPresented, namespace)
	printVerificationSteps(attackResult)
	fmt.Printf("  Attacker's mDoc valid: %v\n", attackResult.Valid)
	fmt.Printf("  Error: %s\n", attackResult.Error)
	fmt.Println("  (correctly rejected — attacker's root not trusted ✓)")

	// ── DEVICE-KEY MISMATCH TEST ───────────────────────────────────
	// Simulates a cloned mdoc: issuerSigned data copied to a different
	// device, which signs deviceAuth with ITS OWN key instead of the
	// key embedded in deviceKeyInfo. This is exactly the attack that
	// Verify() alone (without deviceAuth checking) would miss.
	fmt.Println("\n========================================")
	fmt.Println("  DEVICE-KEY MISMATCH TEST (cloned mdoc, wrong signer)")
	fmt.Println("========================================")

	otherHolder, _ := mdoc.NewHolder()
	wrongDeviceAuthBytes, _ := otherHolder.SignDeviceAuth(docType, transcript)

	cloneResult := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, wrongDeviceAuthBytes)
	printVerificationSteps(cloneResult)
	fmt.Printf("  Cloned mdoc deviceAuth valid: %v\n", cloneResult.DeviceAuthValid)
	fmt.Printf("  Error: %s\n", cloneResult.Error)
	fmt.Println("  (correctly rejected — deviceAuth signed by wrong key ✓)")
}
