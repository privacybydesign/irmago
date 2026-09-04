package mdoc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// PROFILE SEPARATION
//
// The rule under test throughout: a restriction the AV Blueprint imposes must
// apply to eu.europa.ec.av.1 and to nothing else. Each test below therefore has
// a general-docType twin, because a check that only ever runs against AV
// documents cannot show that it stays off for the rest.
// ============================================================

const generalDocType = "org.iso.18013.5.1.mDL"

// issueUnderProfile mints and verifies a single-namespace document under
// docType and returns the verification result. The namespace is docType, which
// is how both profiles in play here name theirs.
func issueUnderProfile(t *testing.T, docType string, claims map[string]any) VerificationResult {
	t.Helper()

	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	doc, err := issuer.Issue(docType, docType, claims, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return NewVerifier([]*x509.Certificate{issuer.IACACert()}).Verify(doc, docType)
}

// TestClosedAttributeSetAppliesToAVOnly covers the AV Blueprint's "A Proof of Age
// Attestation SHALL NOT include any other attribute".
//
// The same non-age element under a non-AV docType has to sail through: ISO/IEC
// 18013-5 places no restriction whatsoever on element identifiers, so applying
// AV's closed set generally would reject conformant mDLs — and would do it with a
// message about age attributes, on a document that has nothing to do with age.
func TestClosedAttributeSetAppliesToAVOnly(t *testing.T) {
	t.Run("AV refuses a non-age attribute", func(t *testing.T) {
		result := issueUnderProfile(t, AgeVerificationDocType, map[string]any{
			"age_over_18": true,
			"nationality": "NL",
		})

		if result.Valid {
			t.Fatal("the AV profile permits only age_over_NN; a document carrying nationality must be refused")
		}
		if !strings.Contains(result.Error, "nationality") {
			t.Errorf("rejection should name the offending attribute, got: %s", result.Error)
		}
	})

	t.Run("AV accepts age_over_NN", func(t *testing.T) {
		result := issueUnderProfile(t, AgeVerificationDocType, map[string]any{
			"age_over_18": true,
			"age_over_65": false,
		})

		if !result.Valid {
			t.Fatalf("age_over_NN is exactly what the AV profile permits, got: %s", result.Error)
		}
	})

	t.Run("a general docType is unaffected", func(t *testing.T) {
		result := issueUnderProfile(t, generalDocType, map[string]any{
			"family_name":     "Doe",
			"birth_date":      "1990-01-01",
			"issuing_country": "NL",
		})

		if !result.Valid {
			t.Fatalf("ISO 18013-5 restricts no element identifier; a non-AV docType must not "+
				"inherit the AV profile's closed set. Got: %s", result.Error)
		}
	})
}

// TestValidityCoarseningIsProfileDriven pins that the timestamp policy is decided
// per docType rather than hardcoded.
//
// Both profiles coarsen today — 9.1.2.4 recommends it for any mdoc and the AV
// Blueprint makes it a SHALL — so this asserts the shared outcome while keeping
// the two paths visibly distinct. It is also the test that fails first if anyone
// changes the coarsening without reading why 9.3.1 step 5 depends on it.
func TestValidityCoarseningIsProfileDriven(t *testing.T) {
	// A wallclock instant well past midnight, so coarsening is observable rather
	// than coincidental.
	issuedAt, err := time.Parse(time.RFC3339, "2026-09-02T10:03:53Z")
	if err != nil {
		t.Fatalf("parse issuedAt: %v", err)
	}

	for _, docType := range []string{AgeVerificationDocType, generalDocType} {
		t.Run(docType, func(t *testing.T) {
			info := profileFor(docType).issuedValidityInfo(issuedAt)

			if got := info.Signed.Format("15:04:05"); got != "00:00:00" {
				t.Errorf("signed should be coarsened to midnight UTC, got %s", got)
			}
			if !info.ValidFrom.Equal(info.Signed) {
				t.Errorf("validFrom %s should equal signed %s", info.ValidFrom, info.Signed)
			}
			if !info.ValidUntil.After(info.ValidFrom) {
				t.Errorf("validUntil %s must be later than validFrom %s", info.ValidUntil, info.ValidFrom)
			}
		})
	}

	// The AV Blueprint's "maximum period of three (3) months from the date of
	// issuance" is the only ceiling either profile has.
	av := profileFor(AgeVerificationDocType)
	if av.validityPeriod > 90*24*time.Hour {
		t.Errorf("AV validity period %s exceeds the Blueprint's three-month maximum", av.validityPeriod)
	}
}

// TestGeneralProfileAllowsHolderAssertedClaims is the positive half of the
// device-namespaces split: ISO/IEC 18013-5 9.1.3.4 permits holder-asserted
// elements when the MSO's keyAuthorizations covers them, and only a profile with
// no holder-asserted attributes may refuse them outright.
//
// Exercised against checkDeviceSignedNameSpaces directly rather than through a
// full presentation, because reaching it end to end needs an issuer that emits
// keyAuthorizations, which this test issuer deliberately does not (see
// DeviceKeyInfo — the fields are modelled for reading, not writing).
func TestGeneralProfileAllowsHolderAssertedClaims(t *testing.T) {
	deviceNameSpaces := map[string]map[string]cbor.RawMessage{
		"org.iso.18013.5.1": {"self_asserted_address": cbor.RawMessage{0xf5}},
	}

	t.Run("authorized by namespace", func(t *testing.T) {
		err := profileFor(generalDocType).checkDeviceSignedNameSpaces(deviceNameSpaces,
			&KeyAuthorizations{NameSpaces: []string{"org.iso.18013.5.1"}})
		if err != nil {
			t.Fatalf("a whole-namespace authorization covers every element under it: %v", err)
		}
	})

	t.Run("authorized by element", func(t *testing.T) {
		err := profileFor(generalDocType).checkDeviceSignedNameSpaces(deviceNameSpaces,
			&KeyAuthorizations{DataElements: map[string][]string{
				"org.iso.18013.5.1": {"self_asserted_address"},
			}})
		if err != nil {
			t.Fatalf("the element is named in dataElements: %v", err)
		}
	})

	t.Run("no authorizations at all", func(t *testing.T) {
		err := profileFor(generalDocType).checkDeviceSignedNameSpaces(deviceNameSpaces, nil)
		if err == nil {
			t.Fatal("9.1.3.4 authorizes the device key to assert only what keyAuthorizations names; absent means nothing")
		}
		if !strings.Contains(err.Error(), "keyAuthorizations") {
			t.Errorf("rejection should name the missing structure, got: %v", err)
		}
	})

	t.Run("authorized for a different element", func(t *testing.T) {
		err := profileFor(generalDocType).checkDeviceSignedNameSpaces(deviceNameSpaces,
			&KeyAuthorizations{DataElements: map[string][]string{
				"org.iso.18013.5.1": {"something_else"},
			}})
		if err == nil {
			t.Fatal("an authorization for a different element must not cover this one")
		}
		if !strings.Contains(err.Error(), "self_asserted_address") {
			t.Errorf("rejection should name the unauthorized element, got: %v", err)
		}
	})

	t.Run("AV refuses regardless of authorizations", func(t *testing.T) {
		err := profileFor(AgeVerificationDocType).checkDeviceSignedNameSpaces(deviceNameSpaces,
			&KeyAuthorizations{NameSpaces: []string{"org.iso.18013.5.1"}})
		if err == nil {
			t.Fatal("the AV profile has no holder-asserted attributes; an issuer authorization cannot create one")
		}
	})

	t.Run("empty deviceNameSpaces is fine under either profile", func(t *testing.T) {
		for _, docType := range []string{AgeVerificationDocType, generalDocType} {
			if err := profileFor(docType).checkDeviceSignedNameSpaces(nil, nil); err != nil {
				t.Errorf("%s: a holder asserting nothing needs no authorization: %v", docType, err)
			}
		}
	})
}

// TestKeyAuthorizationsRoundTripDoesNotChangeSignedBytes guards the reason
// DeviceKeyInfo's new fields are omitempty: they are modelled so a document that
// carries them can be verified, not so this issuer emits them. If they ever
// started encoding, every previously issued credential's MSO digest would change
// and nothing would verify.
func TestKeyAuthorizationsRoundTripDoesNotChangeSignedBytes(t *testing.T) {
	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	deviceKey, err := coseKeyFromECDSA(holder.PublicKey())
	if err != nil {
		t.Fatalf("coseKeyFromECDSA: %v", err)
	}

	encoded, err := cbor.Marshal(DeviceKeyInfo{DeviceKey: deviceKey})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// One entry: deviceKey. 0xa1 is a definite-length map of one pair.
	if encoded[0] != 0xa1 {
		t.Fatalf("DeviceKeyInfo with no authorizations must encode as a single-entry map "+
			"(0xa1), got 0x%02x — keyAuthorizations or keyInfo is being emitted, which changes "+
			"the signed MSO bytes of every credential", encoded[0])
	}

	var round DeviceKeyInfo
	if err := mdocDecMode.Unmarshal(encoded, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if round.KeyAuthorizations != nil || round.KeyInfo != nil {
		t.Error("absent optional fields should decode to nil")
	}
}

// ============================================================
// REVOCATION
// ============================================================

// staticTrustSource is the minimal TrustSource a test needs: fixed anchors and a
// fixed CRL set.
type staticTrustSource struct {
	roots *x509.CertPool
	crls  []*x509.RevocationList
}

func (s staticTrustSource) GetVerificationOptionsTemplate() x509.VerifyOptions {
	return x509.VerifyOptions{Roots: s.roots}
}
func (s staticTrustSource) GetRevocationLists() []*x509.RevocationList { return s.crls }

// revokeCert issues a CRL from issuerCert/issuerKey listing revoked's serial.
func revokeCert(t *testing.T, issuerCert *x509.Certificate, issuerKey *ecdsa.PrivateKey, revoked ...*x509.Certificate) *x509.RevocationList {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, c := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   c.SerialNumber,
			RevocationTime: time.Now().Add(-time.Hour),
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
	}, issuerCert, issuerKey)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	return crl
}

// TestRevokedDocumentSignerIsRefused closes the 9.3.3 gap: "mdoc readers ...
// performing certification path validation ... shall have access to certificate
// revocation information".
//
// The credential here is entirely genuine — real chain, real signature, valid
// dates — and the only thing wrong with it is that its document signer has been
// withdrawn. Chain validation cannot see that, which is the whole point: a
// compromised key stays inside its validity window until it expires.
func TestRevokedDocumentSignerIsRefused(t *testing.T) {
	const dt = AgeVerificationDocType

	build := func(t *testing.T) (*Issuer, *MDoc, *x509.CertPool) {
		t.Helper()
		iss, err := NewIssuer()
		if err != nil {
			t.Fatalf("NewIssuer: %v", err)
		}
		h, err := NewHolder()
		if err != nil {
			t.Fatalf("NewHolder: %v", err)
		}
		doc, err := iss.Issue(dt, dt, map[string]any{"age_over_18": true}, h.PublicKey())
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(iss.IACACert())
		return iss, doc, pool
	}

	t.Run("no CRLs means no revocation checking", func(t *testing.T) {
		iss, doc, pool := build(t)
		_ = iss
		v := NewVerifierFromTrustSource(staticTrustSource{roots: pool})
		if r := v.Verify(doc, dt); !r.Valid {
			t.Fatalf("an unrevoked signer with no CRLs available must still verify: %s", r.Error)
		}
	})

	t.Run("an unrelated CRL does not reject", func(t *testing.T) {
		iss, doc, pool := build(t)
		other, err := NewIssuer()
		if err != nil {
			t.Fatalf("NewIssuer: %v", err)
		}
		// A CRL from a different CA, revoking a different serial.
		crl := revokeCert(t, other.IACACert(), other.iacakey, other.DSCert())
		v := NewVerifierFromTrustSource(staticTrustSource{roots: pool, crls: []*x509.RevocationList{crl}})
		if r := v.Verify(doc, dt); !r.Valid {
			t.Fatalf("a CRL from an unrelated issuer must not reject this signer: %s", r.Error)
		}
		_ = iss
	})

	t.Run("the document signer's own revocation rejects", func(t *testing.T) {
		iss, doc, pool := build(t)
		crl := revokeCert(t, iss.IACACert(), iss.iacakey, iss.DSCert())
		v := NewVerifierFromTrustSource(staticTrustSource{roots: pool, crls: []*x509.RevocationList{crl}})

		r := v.Verify(doc, dt)
		if r.Valid {
			t.Fatal("a credential signed by a revoked document signer must be refused")
		}
		if !strings.Contains(r.Error, "revoked") {
			t.Errorf("rejection should say the certificate is revoked, got: %s", r.Error)
		}
		// The operator acting on this needs to know which certificate, not just that
		// something in the chain was withdrawn.
		if !strings.Contains(r.Error, iss.DSCert().Subject.String()) {
			t.Errorf("rejection should name the revoked certificate, got: %s", r.Error)
		}
	})

	t.Run("options-only verifiers still skip revocation", func(t *testing.T) {
		iss, doc, pool := build(t)
		crl := revokeCert(t, iss.IACACert(), iss.iacakey, iss.DSCert())
		_ = crl
		// NewVerifier has no trust source, so it has no lists — unchanged behaviour,
		// pinned so the options-only constructors keep working for tests and demos.
		if r := NewVerifier([]*x509.Certificate{iss.IACACert()}).Verify(doc, dt); !r.Valid {
			t.Fatalf("a verifier built without a trust source cannot check revocation: %s", r.Error)
		}
		_ = pool
	})
}
