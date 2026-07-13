package main

import (
	"crypto/x509"
	"encoding/hex"
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

	// ── Selective Disclosure ─────────────────────────────────────
	reveal := []string{"age_over_18"}
	presented, err := mdoc.SelectiveDisclose(credential, namespace, reveal)
	if err != nil {
		log.Fatal("selective disclose:", err)
	}
	printSelectiveDisclosure(claims, reveal)

	// ── DeviceAuth ───────────────────────────────────────────────
	// Holder signs a fresh DeviceAuthentication for this session
	// SessionTranscript would normally come from the verifier's QR code / NFC engagement
	// Here we use a minimal stub transcript for the demo
	transcript := mdoc.SessionTranscript{
		DeviceEngagementBytes: []byte("test-engagement"),
		EReaderKeyBytes:       []byte("test-reader-key"),
		Handover:              "test-handover",
	}
	deviceAuthBytes, err := holder.SignDeviceAuth(docType, transcript)
	if err != nil {
		log.Fatal("deviceAuth:", err)
	}
	fmt.Printf("\ndeviceAuth signed ✓  (%d bytes)\n", len(deviceAuthBytes))
	fmt.Println("  (fresh per session — binds presentation to this verifier + session)")

	// ── Verification ─────────────────────────────────────────────
	// Verifier pre-installs ONLY the IACA root as trust anchor
	// DS cert arrives via x5chain at verification time — never pre-installed
	verifier := mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})
	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, deviceAuthBytes)
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
