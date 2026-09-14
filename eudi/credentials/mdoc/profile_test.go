package mdoc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err, "NewIssuer: %v", err)
	holder, err := NewHolder()
	require.NoError(t, err, "NewHolder: %v", err)
	doc, err := issuer.Issue(docType, docType, claims, holder.PublicKey())
	require.NoError(t, err, "Issue: %v", err)
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

		require.False(t, result.Valid, "the AV profile permits only age_over_NN; a document carrying nationality must be refused")
		require.Contains(t, result.Error, "nationality", "rejection should name the offending attribute, got: %s", result.Error)
	})

	t.Run("AV accepts age_over_NN", func(t *testing.T) {
		result := issueUnderProfile(t, AgeVerificationDocType, map[string]any{
			"age_over_18": true,
			"age_over_65": false,
		})

		require.True(t, result.Valid, "age_over_NN is exactly what the AV profile permits, got: %s", result.Error)
	})

	t.Run("a general docType is unaffected", func(t *testing.T) {
		result := issueUnderProfile(t, generalDocType, map[string]any{
			"family_name":     "Doe",
			"birth_date":      "1990-01-01",
			"issuing_country": "NL",
		})

		require.True(t, result.Valid, "ISO 18013-5 restricts no element identifier; a non-AV docType must not "+
			"inherit the AV profile's closed set. Got: %s", result.Error)
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
	require.NoError(t, err, "parse issuedAt: %v", err)

	for _, docType := range []string{AgeVerificationDocType, generalDocType} {
		t.Run(docType, func(t *testing.T) {
			info := profileFor(docType).issuedValidityInfo(issuedAt)

			got := info.Signed.Format("15:04:05")
			require.Equal(t, "00:00:00", got, "signed should be coarsened to midnight UTC, got %s", got)
			require.True(t, info.ValidFrom.Equal(info.Signed), "validFrom %s should equal signed %s", info.ValidFrom, info.Signed)
			require.True(t, info.ValidUntil.After(info.ValidFrom), "validUntil %s must be later than validFrom %s", info.ValidUntil, info.ValidFrom)
		})
	}

	// The AV Blueprint's "maximum period of three (3) months from the date of
	// issuance" is the only ceiling either profile has.
	av := profileFor(AgeVerificationDocType)
	require.LessOrEqual(t, av.validityPeriod, 90*24*time.Hour, "AV validity period %s exceeds the Blueprint's three-month maximum", av.validityPeriod)
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
		require.NoError(t, err, "a whole-namespace authorization covers every element under it: %v", err)
	})

	t.Run("authorized by element", func(t *testing.T) {
		err := profileFor(generalDocType).checkDeviceSignedNameSpaces(deviceNameSpaces,
			&KeyAuthorizations{DataElements: map[string][]string{
				"org.iso.18013.5.1": {"self_asserted_address"},
			}})
		require.NoError(t, err, "the element is named in dataElements: %v", err)
	})

	t.Run("no authorizations at all", func(t *testing.T) {
		err := profileFor(generalDocType).checkDeviceSignedNameSpaces(deviceNameSpaces, nil)
		require.Error(t, err, "9.1.3.4 authorizes the device key to assert only what keyAuthorizations names; absent means nothing")
		require.ErrorContains(t, err, "keyAuthorizations", "rejection should name the missing structure, got: %v", err)
	})

	t.Run("authorized for a different element", func(t *testing.T) {
		err := profileFor(generalDocType).checkDeviceSignedNameSpaces(deviceNameSpaces,
			&KeyAuthorizations{DataElements: map[string][]string{
				"org.iso.18013.5.1": {"something_else"},
			}})
		require.Error(t, err, "an authorization for a different element must not cover this one")
		require.ErrorContains(t, err, "self_asserted_address", "rejection should name the unauthorized element, got: %v", err)
	})

	t.Run("AV refuses regardless of authorizations", func(t *testing.T) {
		err := profileFor(AgeVerificationDocType).checkDeviceSignedNameSpaces(deviceNameSpaces,
			&KeyAuthorizations{NameSpaces: []string{"org.iso.18013.5.1"}})
		require.Error(t, err, "the AV profile has no holder-asserted attributes; an issuer authorization cannot create one")
	})

	t.Run("empty deviceNameSpaces is fine under either profile", func(t *testing.T) {
		for _, docType := range []string{AgeVerificationDocType, generalDocType} {
			err := profileFor(docType).checkDeviceSignedNameSpaces(nil, nil)
			require.NoError(t, err, "%s: a holder asserting nothing needs no authorization: %v", docType, err)
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
	require.NoError(t, err, "NewHolder: %v", err)
	deviceKey, err := coseKeyFromECDSA(holder.PublicKey())
	require.NoError(t, err, "coseKeyFromECDSA: %v", err)

	encoded, err := cbor.Marshal(DeviceKeyInfo{DeviceKey: deviceKey})
	require.NoError(t, err, "marshal: %v", err)

	// One entry: deviceKey. 0xa1 is a definite-length map of one pair.
	require.Equal(t, byte(0xa1), encoded[0], "DeviceKeyInfo with no authorizations must encode as a single-entry map "+
		"(0xa1), got 0x%02x — keyAuthorizations or keyInfo is being emitted, which changes "+
		"the signed MSO bytes of every credential", encoded[0])

	var round DeviceKeyInfo
	err = mdocDecMode.Unmarshal(encoded, &round)
	require.NoError(t, err, "unmarshal: %v", err)
	require.Nil(t, round.KeyAuthorizations, "absent optional fields should decode to nil")
	require.Nil(t, round.KeyInfo, "absent optional fields should decode to nil")
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
	require.NoError(t, err, "CreateRevocationList: %v", err)
	crl, err := x509.ParseRevocationList(der)
	require.NoError(t, err, "ParseRevocationList: %v", err)
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
		require.NoError(t, err, "NewIssuer: %v", err)
		h, err := NewHolder()
		require.NoError(t, err, "NewHolder: %v", err)
		doc, err := iss.Issue(dt, dt, map[string]any{"age_over_18": true}, h.PublicKey())
		require.NoError(t, err, "Issue: %v", err)
		pool := x509.NewCertPool()
		pool.AddCert(iss.IACACert())
		return iss, doc, pool
	}

	t.Run("no CRLs means no revocation checking", func(t *testing.T) {
		iss, doc, pool := build(t)
		_ = iss
		v := NewVerifierFromTrustSource(staticTrustSource{roots: pool})
		r := v.Verify(doc, dt)
		require.True(t, r.Valid, "an unrevoked signer with no CRLs available must still verify: %s", r.Error)
	})

	t.Run("an unrelated CRL does not reject", func(t *testing.T) {
		iss, doc, pool := build(t)
		other, err := NewIssuer()
		require.NoError(t, err, "NewIssuer: %v", err)
		// A CRL from a different CA, revoking a different serial.
		crl := revokeCert(t, other.IACACert(), other.iacakey, other.DSCert())
		v := NewVerifierFromTrustSource(staticTrustSource{roots: pool, crls: []*x509.RevocationList{crl}})
		r := v.Verify(doc, dt)
		require.True(t, r.Valid, "a CRL from an unrelated issuer must not reject this signer: %s", r.Error)
		_ = iss
	})

	t.Run("the document signer's own revocation rejects", func(t *testing.T) {
		iss, doc, pool := build(t)
		crl := revokeCert(t, iss.IACACert(), iss.iacakey, iss.DSCert())
		v := NewVerifierFromTrustSource(staticTrustSource{roots: pool, crls: []*x509.RevocationList{crl}})

		r := v.Verify(doc, dt)
		require.False(t, r.Valid, "a credential signed by a revoked document signer must be refused")
		require.Contains(t, r.Error, "revoked", "rejection should say the certificate is revoked, got: %s", r.Error)
		// The operator acting on this needs to know which certificate, not just that
		// something in the chain was withdrawn.
		require.Contains(t, r.Error, iss.DSCert().Subject.String(), "rejection should name the revoked certificate, got: %s", r.Error)
	})

	t.Run("options-only verifiers still skip revocation", func(t *testing.T) {
		iss, doc, pool := build(t)
		crl := revokeCert(t, iss.IACACert(), iss.iacakey, iss.DSCert())
		_ = crl
		// NewVerifier has no trust source, so it has no lists — unchanged behaviour,
		// pinned so the options-only constructors keep working for tests and demos.
		r := NewVerifier([]*x509.Certificate{iss.IACACert()}).Verify(doc, dt)
		require.True(t, r.Valid, "a verifier built without a trust source cannot check revocation: %s", r.Error)
		_ = pool
	})
}
