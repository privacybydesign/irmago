package mdoc

import (
	"crypto/x509"
	"testing"
)

// TestVerifyAllDisclosedNamespaces_HappyPath verifies a freshly issued (not
// yet selectively disclosed) mdoc across every namespace it carries — the
// issuance-time verification shape, unlike Verify's single-namespace
// presentation-time shape.
func TestVerifyAllDisclosedNamespaces_HappyPath(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}

	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"
	claims := map[string]any{"age_over_18": true, "age_over_16": true}

	issued, err := issuer.Issue(docType, namespace, claims, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	verifier := NewVerifier([]*x509.Certificate{issuer.IACACert()})
	resolved, result := verifier.VerifyAllDisclosedNamespaces(issued)
	if !result.Valid {
		t.Fatalf("expected valid result, got error: %s", result.Error)
	}
	if result.DocType != docType {
		t.Fatalf("expected DocType %q, got %q", docType, result.DocType)
	}

	nsAttrs, ok := resolved[namespace]
	if !ok {
		t.Fatalf("expected namespace %q in resolved claims, got %v", namespace, resolved)
	}
	if nsAttrs["age_over_18"] != true || nsAttrs["age_over_16"] != true {
		t.Fatalf("expected both claims resolved, got %v", nsAttrs)
	}
}

// TestVerifyAllDisclosedNamespaces_TamperedDigestIsRejected mirrors
// TestTamperedDigestIsRejected for the multi-namespace entry point.
func TestVerifyAllDisclosedNamespaces_TamperedDigestIsRejected(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"
	issued, err := issuer.Issue(docType, namespace, map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	tamperedItem := IssuerSignedItem{
		DigestID:          0,
		Random:            []byte("attacker-does-not-know-real-salt"),
		ElementIdentifier: "age_over_18",
		ElementValue:      false, // flipped from true
	}
	tamperedWrapped, err := tag24Wrap(tamperedItem)
	if err != nil {
		t.Fatalf("tag24Wrap: %v", err)
	}
	tamperedMDoc := &MDoc{
		DocType: issued.DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{namespace: {{EncodedItem: tamperedWrapped}}},
			IssuerAuth: issued.IssuerSigned.IssuerAuth,
		},
	}

	verifier := NewVerifier([]*x509.Certificate{issuer.IACACert()})
	_, result := verifier.VerifyAllDisclosedNamespaces(tamperedMDoc)
	if result.Valid {
		t.Fatalf("expected tampered claim to be rejected, but it was accepted")
	}
}

// TestVerify_PopulatesDeviceKeyAndValidityInfo confirms the new
// VerificationResult fields are populated on a successful Verify, and that
// DeviceKey matches the holder's actual public key embedded at issuance.
func TestVerify_PopulatesDeviceKeyAndValidityInfo(t *testing.T) {
	issuer, holder, verifier, presented, _, _, _, namespace := buildHappyPathMDoc(t)

	result := verifier.Verify(presented, namespace)
	if !result.Valid {
		t.Fatalf("expected valid result, got error: %s", result.Error)
	}

	if result.DeviceKey == nil {
		t.Fatalf("expected DeviceKey to be populated")
	}
	if !result.DeviceKey.Equal(holder.PublicKey()) {
		t.Fatalf("expected DeviceKey to match holder's public key")
	}

	if result.ValidityInfo.ValidFrom.IsZero() || result.ValidityInfo.ValidUntil.IsZero() {
		t.Fatalf("expected ValidityInfo to be populated, got %+v", result.ValidityInfo)
	}

	_ = issuer
}

// TestNewVerifierFromPool confirms NewVerifierFromPool behaves identically
// to NewVerifier when given an equivalent trust-root pool.
func TestNewVerifierFromPool(t *testing.T) {
	issuer, _, _, presented, _, _, _, namespace := buildHappyPathMDoc(t)

	pool := x509.NewCertPool()
	pool.AddCert(issuer.IACACert())
	verifier := NewVerifierFromPool(pool)

	result := verifier.Verify(presented, namespace)
	if !result.Valid {
		t.Fatalf("expected valid result, got error: %s", result.Error)
	}
}
