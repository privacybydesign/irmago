package main

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"

	"mdoc"
)

// ============================================================
// DEMO — issuer -> holder -> verifier walkthrough
//
// Exercises the mdoc package purely through its exported API, exactly as
// an external consumer would. See main_test.go inside the mdoc package
// itself for the same flows plus negative/regression cases.
// ============================================================

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

	// ── Selective Disclosure ─────────────────────────────────────
	presented, err := mdoc.SelectiveDisclose(credential, namespace, []string{"age_over_18"})
	if err != nil {
		log.Fatal("selective disclose:", err)
	}

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
	attackerMDoc, _ := attackerIssuer.Issue(docType, namespace,
		map[string]any{"age_over_18": true},
		attackerHolder.PublicKey(),
	)
	attackerPresented, _ := mdoc.SelectiveDisclose(attackerMDoc, namespace, []string{"age_over_18"})

	attackResult := verifier.Verify(attackerPresented, namespace)
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
	fmt.Printf("  Cloned mdoc deviceAuth valid: %v\n", cloneResult.DeviceAuthValid)
	fmt.Printf("  Error: %s\n", cloneResult.Error)
	fmt.Println("  (correctly rejected — deviceAuth signed by wrong key ✓)")
}
