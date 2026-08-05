package mdoc

import (
	"strings"
	"testing"
)

// MDoc.DocType sits in the document map beside issuerSigned and is covered by
// no digest and no signature; MSO.docType is inside the signed MSO. These tests
// pin that the two must agree, at every entry point that reports a docType or
// consumes one.
//
// The consequence of not comparing them is not abstract: eudi/services' mdoc
// parser stores the value it reads as the credential's VerifiableCredentialType,
// which is what DCQL doctype_value matching and the scheme's relying-party
// authorization key off. Before this check, all three entry points below
// returned Valid=true while reporting the attacker's docType.

const attackerDocType = "eu.europa.ec.eudi.pid.1"

func TestTamperedEnvelopeDocTypeIsRejectedByVerify(t *testing.T) {
	_, _, verifier, presented, _, _, docType, namespace := buildHappyPathMDoc(t)

	tampered := *presented
	tampered.DocType = attackerDocType

	result := verifier.Verify(&tampered, namespace)
	if result.Valid {
		t.Fatalf("a document whose envelope docType was re-labelled to %q verified as valid, "+
			"and reported DocType=%q", attackerDocType, result.DocType)
	}
	if !strings.Contains(result.Error, "docType mismatch") {
		t.Errorf("error was %q, want it to name the docType mismatch", result.Error)
	}
	if result.DocType == attackerDocType {
		t.Errorf("result carries the attacker's docType %q", result.DocType)
	}
	// Sanity: the untampered document still verifies, and reports the signed value.
	if ok := verifier.Verify(presented, namespace); !ok.Valid || ok.DocType != docType {
		t.Errorf("untampered document: valid=%v docType=%q, want true/%q", ok.Valid, ok.DocType, docType)
	}
}

func TestTamperedEnvelopeDocTypeIsRejectedAtIssuanceVerification(t *testing.T) {
	issuer, holder, verifier, _, _, _, docType, namespace := buildHappyPathMDoc(t)

	// VerifyAllDisclosedNamespaces is the issuance-time entry point, so use a
	// freshly issued (not yet selectively disclosed) document.
	issued, err := issuer.Issue(docType, namespace, map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	issued.DocType = attackerDocType

	resolved, result := verifier.VerifyAllDisclosedNamespaces(issued)
	if result.Valid {
		t.Fatalf("re-labelled document passed issuance verification, reporting DocType=%q with claims %v",
			result.DocType, resolved)
	}
	if !strings.Contains(result.Error, "docType mismatch") {
		t.Errorf("error was %q, want it to name the docType mismatch", result.Error)
	}
}

func TestVerifierRequestedDocTypeMustMatchSignedMSO(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, _, namespace := buildHappyPathMDoc(t)

	// A verifier asking for a different docType than the issuer signed must be
	// told so plainly, rather than being left to infer it from a failed device
	// signature (the reconstructed DeviceAuthentication payload would differ).
	result := verifier.VerifyWithDeviceAuth(presented, namespace, attackerDocType, transcript, deviceAuthBytes)
	if result.Valid {
		t.Fatalf("verification succeeded for a docType the issuer never signed")
	}
	if !strings.Contains(result.Error, "docType mismatch") {
		t.Errorf("error was %q, want it to name the docType mismatch rather than an opaque signature failure", result.Error)
	}
}

func TestSignedDocTypeIsReportedNotTheEnvelopeValue(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, docType, namespace := buildHappyPathMDoc(t)

	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, deviceAuthBytes)
	if !result.Valid || !result.DeviceAuthValid {
		t.Fatalf("happy path failed: valid=%v deviceAuth=%v err=%q", result.Valid, result.DeviceAuthValid, result.Error)
	}
	if result.DocType != docType {
		t.Errorf("DocType=%q, want the signed %q", result.DocType, docType)
	}
}
