package testissuer_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc/testissuer"
)

// TestBuildAVCredentialParsesAsMdoc proves the fake issuer emits bytes that
// the wallet-side parser in eudi/credentials/mdoc accepts. Without this the
// rest of Phase 2 has no test input to work with.
func TestBuildAVCredentialParsesAsMdoc(t *testing.T) {
	cred := mustBuild(t, testissuer.AVRequest{
		AgeOver18: true,
		AgeOverNN: map[int]bool{21: true},
	})

	issuerSigned, err := mdoc.ParseIssuerSigned(cred.IssuerSignedCBOR)
	require.NoError(t, err)

	mso, err := issuerSigned.IssuerAuth.MobileSecurityObject()
	require.NoError(t, err)

	assert.Equal(t, testissuer.AVDocType, cred.DocType)
	assert.Equal(t, testissuer.AVDocType, mso.DocType)
	assert.Equal(t, mdoc.SHA256, mso.DigestAlgorithm)

	items, ok := issuerSigned.Namespaces[testissuer.AVNamespace]
	require.True(t, ok, "expected namespace %q", testissuer.AVNamespace)
	require.Len(t, items, 2, "want age_over_18 + age_over_21")

	got := map[string]bool{}
	for _, it := range items {
		b, err := decodeBool(it.ElementValue)
		require.NoError(t, err, "elem %s", it.ElementIdentifier)
		got[it.ElementIdentifier] = b
	}
	assert.Equal(t, map[string]bool{"age_over_18": true, "age_over_21": true}, got)
}

// TestAVCredentialDigestsMatchMSO enforces the selective-disclosure invariant
// from ISO 18013-5 §9.1.2.5: every IssuerSignedItem emitted by the issuer must
// hash to the digest committed to in the MSO.
func TestAVCredentialDigestsMatchMSO(t *testing.T) {
	cred := mustBuild(t, testissuer.AVRequest{AgeOver18: true})

	issuerSigned, err := mdoc.ParseIssuerSigned(cred.IssuerSignedCBOR)
	require.NoError(t, err)
	mso, err := issuerSigned.IssuerAuth.MobileSecurityObject()
	require.NoError(t, err)

	for ns, items := range issuerSigned.Namespaces {
		nsDigests, ok := mso.ValueDigests[ns]
		require.True(t, ok, "MSO missing namespace %q", ns)
		for _, it := range items {
			want, ok := nsDigests[it.DigestID]
			require.True(t, ok, "MSO missing digestID %d for %s", it.DigestID, it.ElementIdentifier)
			got, err := it.Digest(mso.DigestAlgorithm)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(want, got),
				"digest mismatch for %s/%s", ns, it.ElementIdentifier)
		}
	}
}

// TestAVCredentialDeviceKeyInMSO checks that the deviceKey inside the MSO
// matches the public half of the DeviceKey returned alongside the credential.
// The wallet needs the private half to prove possession during disclosure.
func TestAVCredentialDeviceKeyInMSO(t *testing.T) {
	cred := mustBuild(t, testissuer.AVRequest{AgeOver18: true})

	issuerSigned, err := mdoc.ParseIssuerSigned(cred.IssuerSignedCBOR)
	require.NoError(t, err)
	mso, err := issuerSigned.IssuerAuth.MobileSecurityObject()
	require.NoError(t, err)

	require.NotNil(t, mso.DeviceKey)
	pub := cred.DeviceKey.PublicKey
	assert.Equal(t, padLeft(pub.X.Bytes(), 32), mso.DeviceKey.X)
	assert.Equal(t, padLeft(pub.Y.Bytes(), 32), mso.DeviceKey.Y)
}

// TestAVCredentialCOSESign1VerifiesWithDSCert verifies the issuerAuth
// signature using the Document Signer's public key. Without this the wallet
// cannot tell whether the credential is authentic.
func TestAVCredentialCOSESign1VerifiesWithDSCert(t *testing.T) {
	cred := mustBuild(t, testissuer.AVRequest{AgeOver18: true})

	issuerSigned, err := mdoc.ParseIssuerSigned(cred.IssuerSignedCBOR)
	require.NoError(t, err)

	auth := issuerSigned.IssuerAuth
	require.NotEmpty(t, auth.ProtectedHeader)
	require.NotEmpty(t, auth.Payload)
	require.NotEmpty(t, auth.Signature)

	// COSE_Sign1 Sig_structure for ES256 (RFC 9052 §4.4):
	//   ["Signature1", bstr(protected), bstr(""), bstr(payload)]
	sigStruct, err := cbor.Marshal([]any{
		"Signature1",
		auth.ProtectedHeader,
		[]byte{},
		auth.Payload,
	})
	require.NoError(t, err)

	digest := sha256.Sum256(sigStruct)
	require.Equal(t, 64, len(auth.Signature), "ES256 signature must be 64 bytes (r||s)")
	r := new(big.Int).SetBytes(auth.Signature[:32])
	s := new(big.Int).SetBytes(auth.Signature[32:])
	ok := ecdsa.Verify(&cred.DSKey.PublicKey, digest[:], r, s)
	assert.True(t, ok, "COSE_Sign1 signature did not verify against DS public key")
}

// TestDSCertificateChainsToIACA rejects the credential unless the DS cert was
// issued by the IACA root — mirroring the wallet's future trust check.
func TestDSCertificateChainsToIACA(t *testing.T) {
	cred := mustBuild(t, testissuer.AVRequest{AgeOver18: true})

	roots := x509.NewCertPool()
	roots.AddCert(cred.IACACert)

	_, err := cred.DSCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	assert.NoError(t, err)
}

// TestAVCredentialValidityDefaults checks that the validity window defaults
// to "now .. now + 3 months" per AV spec §7.2 when the caller does not set it.
func TestAVCredentialValidityDefaults(t *testing.T) {
	before := time.Now().Add(-1 * time.Minute)
	cred := mustBuild(t, testissuer.AVRequest{AgeOver18: true})
	after := time.Now().Add(1 * time.Minute)

	issuerSigned, err := mdoc.ParseIssuerSigned(cred.IssuerSignedCBOR)
	require.NoError(t, err)
	mso, err := issuerSigned.IssuerAuth.MobileSecurityObject()
	require.NoError(t, err)

	v := mso.ValidityInfo
	assert.True(t, !v.ValidFrom.Before(before) && !v.ValidFrom.After(after),
		"validFrom %v not within [%v, %v]", v.ValidFrom, before, after)
	// Spec mandates max 3 months.
	span := v.ValidUntil.Sub(v.ValidFrom)
	assert.LessOrEqual(t, span, 93*24*time.Hour, "validity window exceeds 3 months")
	assert.GreaterOrEqual(t, span, 80*24*time.Hour, "validity window suspiciously short")
}

// ---- helpers ---------------------------------------------------------------

func mustBuild(t *testing.T, req testissuer.AVRequest) *testissuer.AVCredential {
	t.Helper()
	cred, err := testissuer.BuildAVCredential(req)
	require.NoError(t, err)
	require.NotNil(t, cred)
	return cred
}

func decodeBool(raw []byte) (bool, error) {
	var b bool
	if err := cbor.Unmarshal(raw, &b); err != nil {
		return false, err
	}
	return b, nil
}

// padLeft pads b to size with leading zeros; if b is already longer it is
// returned unchanged.
func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
