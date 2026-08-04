package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// Chaining to a trusted IACA root does not by itself make a certificate a
// document signer. These tests pin that the DS certificate's extended key
// usage is checked, so a certificate issued for some other role beneath the
// same root cannot sign an MSO the wallet accepts.

// issueWithDSEKU builds an IACA→DS chain where the DS certificate carries
// exactly the given extended key usages, signs a minimal MSO with it, and
// returns an mdoc plus a verifier trusting the IACA root.
func issueWithDSEKU(t *testing.T, eku []x509.ExtKeyUsage, unknownEKU []asn1.ObjectIdentifier) (*MDoc, *Verifier) {
	t.Helper()

	iacaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate IACA key: %v", err)
	}
	iacaTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test IACA"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	iacaDER, err := x509.CreateCertificate(rand.Reader, iacaTemplate, iacaTemplate, &iacaKey.PublicKey, iacaKey)
	if err != nil {
		t.Fatalf("create IACA cert: %v", err)
	}
	iacaCert, err := x509.ParseCertificate(iacaDER)
	if err != nil {
		t.Fatalf("parse IACA cert: %v", err)
	}

	dsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate DS key: %v", err)
	}
	dsTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test DS"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           eku,
		UnknownExtKeyUsage:    unknownEKU,
	}
	dsDER, err := x509.CreateCertificate(rand.Reader, dsTemplate, iacaCert, &dsKey.PublicKey, iacaKey)
	if err != nil {
		t.Fatalf("create DS cert: %v", err)
	}
	dsCert, err := x509.ParseCertificate(dsDER)
	if err != nil {
		t.Fatalf("parse DS cert: %v", err)
	}

	// Minimal signed MSO — only the chain is under test, so a single claim in
	// one namespace is enough for verifyIssuerAuthAndMSO to run end to end.
	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	deviceKey, err := coseKeyFromECDSA(holder.PublicKey())
	if err != nil {
		t.Fatalf("coseKeyFromECDSA: %v", err)
	}
	const docType = "eu.europa.ec.av.1"
	item := IssuerSignedItem{DigestID: 0, Random: make([]byte, 16), ElementIdentifier: "age_over_18", ElementValue: true}
	digest, err := hashTag24Item(item)
	if err != nil {
		t.Fatalf("hashTag24Item: %v", err)
	}
	now := time.Now().UTC()
	mso := MSO{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		ValueDigests:    map[string]map[uint64][]byte{docType: {0: digest}},
		DocType:         docType,
		ValidityInfo:    ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(24 * time.Hour)},
		DeviceKeyInfo:   DeviceKeyInfo{DeviceKey: deviceKey},
	}
	msoBytes, err := tag24WrapWithMode(mso, avTimeEncMode)
	if err != nil {
		t.Fatalf("wrap mso: %v", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, dsKey)
	if err != nil {
		t.Fatalf("cose.NewSigner: %v", err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = msoBytes
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Unprotected[int64(33)] = [][]byte{dsCert.Raw, iacaCert.Raw}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign mso: %v", err)
	}
	coseBytes, err := cbor.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal cose: %v", err)
	}
	wrapped, err := tag24Wrap(item)
	if err != nil {
		t.Fatalf("wrap item: %v", err)
	}

	doc := &MDoc{
		DocType: docType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{docType: {{EncodedItem: wrapped}}},
			IssuerAuth: coseBytes,
		},
	}
	return doc, NewVerifier([]*x509.Certificate{iacaCert})
}

func TestDocumentSignerEKUIsEnforced(t *testing.T) {
	const namespace = "eu.europa.ec.av.1"

	t.Run("DS cert with the ISO mdoc document-signer EKU is accepted", func(t *testing.T) {
		doc, v := issueWithDSEKU(t, nil, []asn1.ObjectIdentifier{isoMdocDocumentSignerEKU})
		if result := v.Verify(doc, namespace); !result.Valid {
			t.Fatalf("expected valid, got error: %s", result.Error)
		}
	})

	t.Run("DS cert with no EKU extension is accepted as unrestricted", func(t *testing.T) {
		// RFC 5280 4.2.1.12: an absent EKU means the certificate is not
		// restricted as to purpose, so there is nothing to contradict.
		doc, v := issueWithDSEKU(t, nil, nil)
		if result := v.Verify(doc, namespace); !result.Valid {
			t.Fatalf("expected valid, got error: %s", result.Error)
		}
	})

	t.Run("DS cert with anyExtKeyUsage is accepted", func(t *testing.T) {
		doc, v := issueWithDSEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, nil)
		if result := v.Verify(doc, namespace); !result.Valid {
			t.Fatalf("expected valid, got error: %s", result.Error)
		}
	})

	t.Run("DS cert issued for TLS server auth is rejected", func(t *testing.T) {
		// The finding this test exists for: a certificate legitimately issued
		// beneath the same IACA root, but for an unrelated role, must not be
		// able to sign an MSO.
		doc, v := issueWithDSEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
		result := v.Verify(doc, namespace)
		if result.Valid {
			t.Fatal("a TLS server certificate must not be accepted as an mdoc document signer")
		}
		if !strings.Contains(result.Error, "not authorized to sign mdocs") {
			t.Fatalf("expected an EKU rejection, got: %s", result.Error)
		}
	})

	t.Run("DS cert issued for TLS client auth is rejected", func(t *testing.T) {
		// This is the exact shape of the EUDI reference issuer's test
		// certificate (testdata/eudi-pid-issuer-py/certs/issuer.pem carries
		// clientAuth), recorded here so the interop consequence is visible in
		// the test suite rather than discovered during integration.
		doc, v := issueWithDSEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
		result := v.Verify(doc, namespace)
		if result.Valid {
			t.Fatal("a TLS client certificate must not be accepted as an mdoc document signer")
		}
		if !strings.Contains(result.Error, "not authorized to sign mdocs") {
			t.Fatalf("expected an EKU rejection, got: %s", result.Error)
		}
	})

	t.Run("the reader-auth EKU is rejected", func(t *testing.T) {
		// 1.0.18013.5.1.6 is the sibling OID for reader authentication — an
		// 18013-5 role, but the verifier's role, not the issuer's.
		readerAuth := asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}
		doc, v := issueWithDSEKU(t, nil, []asn1.ObjectIdentifier{readerAuth})
		result := v.Verify(doc, namespace)
		if result.Valid {
			t.Fatal("a reader-auth certificate must not be accepted as a document signer")
		}
	})
}
