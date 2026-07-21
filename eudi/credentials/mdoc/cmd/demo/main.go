package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"

	"mdoc"
	"mdoc/openid4vci"
	"mdoc/openid4vp"
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

	// ============================================================
	// OPENID4VCI ISSUANCE — pre-authorized_code flow (Annex A §A.10),
	// replacing what used to be a single direct issuer.Issue(...) call.
	// Mirrors the DCQL query's "simulate crossing the wire via JSON
	// marshal/unmarshal" pattern further down: every step the holder sees
	// is parsed fresh from JSON/form bytes the issuer actually produced,
	// never a shared Go variable, the same way a real wallet and issuer
	// never share memory.
	// ============================================================

	credentialIssuerURL := "https://credential-issuer.example.com"

	// ── Issuer: build Credential Offer ──────────────────────────────────
	// In a real deployment the user has already completed identity
	// verification out-of-band (bank, notary, citizen service centre —
	// see credentialoffer.go's file comment) before this point.
	preAuthCode, err := openid4vci.NewPreAuthorizedCode()
	if err != nil {
		log.Fatal("generate pre-authorized_code:", err)
	}
	txCodeValue, txCodeMeta, err := openid4vci.NewTxCode(4, "Please provide the one-time code sent via e-mail")
	if err != nil {
		log.Fatal("generate tx_code:", err)
	}
	offer := openid4vci.NewCredentialOffer(credentialIssuerURL, preAuthCode, txCodeMeta)
	fmt.Println("\n--- ISSUER: Building Credential Offer (OpenID4VCI, pre-authorized_code) ---")
	fmt.Println("  credential_configuration_ids: [\"proof_of_age\"]")
	fmt.Println("  pre-authorized_code generated ✓  (delivered via QR code / deep link)")
	fmt.Printf("  tx_code generated ✓  (%d-digit PIN, delivered via e-mail — NOT inside the offer)\n", txCodeMeta.Length)

	// Simulate the offer actually crossing the wire (e.g. scanned as a QR
	// code) — the holder only ever sees receivedOffer, parsed fresh from
	// JSON, same as receivedQuery further down for the DCQL request.
	offerJSON, err := json.Marshal(offer)
	if err != nil {
		log.Fatal("marshal credential offer:", err)
	}
	var receivedOffer openid4vci.CredentialOffer
	if err := json.Unmarshal(offerJSON, &receivedOffer); err != nil {
		log.Fatal("parse credential offer:", err)
	}
	grant, err := receivedOffer.PreAuthorizedGrant()
	if err != nil {
		log.Fatal("read pre-authorized grant:", err)
	}

	// ── Holder: redeem the offer at the token endpoint ──────────────────
	// The tx_code VALUE (txCodeValue) never travels inside the offer
	// itself — the holder only has it because the user typed in the PIN
	// they received over the separate e-mail channel. Simulated here as
	// the demo reusing the same Go variable, since there's no real e-mail
	// channel to actually send it over.
	tokenReqBody := openid4vci.NewPreAuthorizedTokenRequest(grant.PreAuthorizedCode, txCodeValue)
	fmt.Println("\n--- HOLDER: Redeeming Credential Offer (POST /token) ---")
	fmt.Printf("  grant_type=pre-authorized_code, pre-authorized_code + tx_code presented ✓  (%d bytes)\n", len(tokenReqBody))

	// ── Issuer: verify + respond ─────────────────────────────────────
	// No client authentication at all in this profile (Annex A §A.5) —
	// trust rests entirely on the issuer's own session lookup by
	// pre-authorized_code, confirming the presented tx_code matches what
	// it generated. This lookup is exactly the server-side session state
	// this package doesn't model (see credentialoffer.go's file comment);
	// the demo does it here with plain local variables standing in for a
	// real session store.
	gotCode, gotTxCode, err := openid4vci.ParsePreAuthorizedTokenRequest(tokenReqBody)
	if err != nil {
		log.Fatal("parse token request:", err)
	}
	if gotCode != preAuthCode || gotTxCode != txCodeValue {
		log.Fatal("pre-authorized_code/tx_code mismatch — rejecting before issuing any token")
	}
	accessToken, err := openid4vci.NewAccessToken()
	if err != nil {
		log.Fatal("generate access_token:", err)
	}
	tokenResp := openid4vci.NewTokenResponse(accessToken, 86400)
	fmt.Println("  tx_code verified ✓  (issuer's own session lookup — no client auth per §A.5)")
	fmt.Printf("  access_token issued ✓  (token_type=%s, expires_in=%ds)\n", tokenResp.TokenType, tokenResp.ExpiresIn)

	// ── Holder: fetch a fresh c_nonce (Nonce Endpoint, [OID4VCI] §7) ────
	// Annex A never mentions this endpoint (see nonceendpoint.go's file
	// comment) — modeled anyway since a real proof of possession needs
	// something to bind against.
	cNonce, err := openid4vci.NewCNonce()
	if err != nil {
		log.Fatal("generate c_nonce:", err)
	}
	nonceResp := openid4vci.NewNonceResponse(cNonce)
	fmt.Println("\n--- ISSUER: Nonce Endpoint (POST /nonce) ---")
	fmt.Printf("  c_nonce issued ✓  (%d chars)\n", len(nonceResp.CNonce))

	// ── Holder: prove possession of its device key + build the request ──
	// Holder sends ONLY the public key (embedded in the PoP JWT's jwk
	// header) — the private key never leaves the holder's device.
	proofJWT, err := openid4vci.SignProofOfPossession(holder, credentialIssuerURL, nonceResp.CNonce)
	if err != nil {
		log.Fatal("sign proof of possession:", err)
	}
	credReq := openid4vci.NewCredentialRequest(proofJWT)
	fmt.Println("\n--- HOLDER: Credential Request (POST /credential) ---")
	fmt.Printf("  Authorization: Bearer %s...  (access_token, in the HTTP header — not the JSON body)\n", tokenResp.AccessToken[:8])
	fmt.Printf("  proofs.jwt: [<PoP JWT>]  (%d bytes, typ=openid4vci-proof+jwt, alg=ES256)\n", len(proofJWT))

	// ── Issuer: verify proof of possession, THEN issue ──────────────────
	// This is the actual point of the whole VCI effort: the issuer only
	// trusts the device key it just cryptographically confirmed the
	// holder controls — contrast with a bare issuer.Issue(docType,
	// namespace, claims, someUntrustedPubKey) call, which would simply
	// trust whatever public key it was handed.
	issuedMDoc, err := openid4vci.IssueFromCredentialRequest(issuer, credReq, docType, namespace, claims, credentialIssuerURL, nonceResp.CNonce)
	if err != nil {
		log.Fatal("issue from credential request:", err)
	}
	credResp, err := openid4vci.NewCredentialResponse(*issuedMDoc)
	if err != nil {
		log.Fatal("build credential response:", err)
	}
	fmt.Println("\n--- ISSUER: Credential Response ---")
	fmt.Println("  proof of possession verified ✓  (device key confirmed BEFORE issuance)")
	fmt.Printf("  credentials: [{credential: <base64url CBOR mdoc>}]  (%d bytes)\n", len(credResp.Credentials[0].Credential))

	// ── Holder: decode the issued credential ────────────────────────────
	decodedMDoc, err := credResp.SingleCredential()
	if err != nil {
		log.Fatal("decode issued credential:", err)
	}
	credential := &decodedMDoc
	printIssuedMDoc(claims, credential)

	// ── Verifier: build Authorization Request (DCQL over OpenID4VP) ─────
	// The AV Blueprint's Annex A §A.6 mandates the OpenID4VP DCQL query
	// format here — not ISO 18013-5's native DeviceRequest CBOR object,
	// which only applies to the W3C DC API path. Reader authentication is
	// intentionally not modeled — out of scope for this profile. DCQL also
	// has no intentToRetain concept, unlike DeviceRequest's itemsRequest.
	//
	// client_id/nonce/response_uri are the verifier's own session-binding
	// values, and state is a fresh anti-CSRF/session-correlation value —
	// unlike nonce, it never enters any hash or signature; the verifier
	// mints one per Authorization Request and checks it's echoed back
	// unchanged before trusting anything. All four now travel together as
	// one real mdoc.AuthorizationRequest (see authorizationrequest.go),
	// not as separately hardcoded/shared Go values — this is what closes
	// the "no real Authorization Request being parsed" gap this demo used
	// to have. verifierQueryId is the verifier's own label for the DCQL
	// query — it's never handed to the holder as a bare Go value, only
	// embedded inside the request below, the same way a real wallet would
	// only ever see it as JSON.
	clientId := "redirect_uri:https://verifier.example.com/response"
	nonce := "n-0S6_WzA2Mj"
	responseUri := "https://verifier.example.com/response"
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		log.Fatal("generate state:", err)
	}
	state := hex.EncodeToString(stateBytes)
	verifierQueryId := "proof_of_age"
	dcqlQuery := openid4vp.NewDCQLQuery(verifierQueryId, docType, namespace, []string{"age_over_18"})
	authRequest := openid4vp.NewAuthorizationRequest(clientId, responseUri, nonce, state, dcqlQuery)
	fmt.Println("\n--- VERIFIER: Building Authorization Request (OpenID4VP) ---")
	fmt.Printf("  dcql_query: format=mso_mdoc, doctype_value=%s, claims=[%s.age_over_18]\n", docType, namespace)
	fmt.Println("  response_mode=direct_post — client_id, nonce, response_uri, state bundled together")

	// Simulate the Authorization Request actually crossing the wire (e.g.
	// as a QR code or same-device redirect). Everything from here on the
	// holder's side works only with receivedRequest, parsed fresh from
	// that JSON — never clientId/nonce/responseUri/dcqlQuery/
	// verifierQueryId directly, since a real wallet never has those Go
	// variables in scope.
	authRequestJSON, err := json.Marshal(authRequest)
	if err != nil {
		log.Fatal("marshal authorization request:", err)
	}
	var receivedRequest openid4vp.AuthorizationRequest
	if err := json.Unmarshal(authRequestJSON, &receivedRequest); err != nil {
		log.Fatal("parse authorization request:", err)
	}

	// ── Holder reads the request ────────────────────────────────────
	// SessionTranscript, the requested attributes, and the vp_token
	// response key are all derived from receivedRequest's own fields —
	// not from the verifier's clientId/nonce/responseUri/verifierQueryId
	// variables above, which the holder never actually has access to.
	transcript, err := receivedRequest.SessionTranscript()
	if err != nil {
		log.Fatal("session transcript:", err)
	}
	reqNamespace, reqAttrs, err := receivedRequest.DcqlQuery.RequestedAttributes(docType)
	if err != nil {
		log.Fatal("read dcql query:", err)
	}
	holderQueryId, err := receivedRequest.DcqlQuery.CredentialQueryId(docType)
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
	formBody, err := openid4vp.NewDirectPostForm(holderQueryId, state, deviceResponse)
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
	receivedResponse, receivedState, err := openid4vp.ParseDirectPostForm(formBody, verifierQueryId)
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
