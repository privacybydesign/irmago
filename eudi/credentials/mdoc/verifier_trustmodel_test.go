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

// The tests here cover where a Verifier gets its trust anchors from, rather
// than what it does with a credential once the chain is settled. Two
// properties are at stake, both of which the wallet depends on and neither of
// which the rest of this package exercises, because every other test issues
// through Issuer: a self-signed IACA that signs the document signer directly
// and travels inside x5chain.
//
// Real deployments are one level deeper. Yivi's staging PKI is
//
//	Yivi Staging Requestors Root CA (self-signed)
//	    - Yivi Staging Attestation Providers CA
//	        - document signer
//
// and the wallet's trust model splits a pinned chain by that shape: the
// self-signed root goes into VerifyOptions.Roots and everything above the leaf
// into VerifyOptions.Intermediates. An issuer whose x5chain carries only its
// document signer is then verifiable only if both halves are used.

// buildPinnedChainMDoc issues a minimal credential under a three-level PKI and
// returns it with the two CA certificates. x5chain deliberately carries the
// document signer alone, which is what makes the intermediate load-bearing:
// there is no path from the DS to the root without it.
func buildPinnedChainMDoc(t *testing.T) (doc *MDoc, root, intermediate *x509.Certificate) {
	t.Helper()

	newCA := func(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, serial int64, pathLen int) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate %s key: %v", cn, err)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn, Organization: []string{"Yivi Test"}},
			NotBefore:             time.Now().Add(-5 * time.Minute),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            pathLen,
			MaxPathLenZero:        pathLen == 0,
		}
		signingCert, signingKey := template, key
		if parent != nil {
			signingCert, signingKey = parent, parentKey
		}
		der, err := x509.CreateCertificate(rand.Reader, template, signingCert, &key.PublicKey, signingKey)
		if err != nil {
			t.Fatalf("create %s cert: %v", cn, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse %s cert: %v", cn, err)
		}
		return cert, key
	}

	rootCert, rootKey := newCA("Test Requestors Root CA", nil, nil, 1, 1)
	interCert, interKey := newCA("Test Attestation Providers CA", rootCert, rootKey, 2, 0)

	dsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate DS key: %v", err)
	}
	dsTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(0xC0FFEE),
		Subject:               pkix.Name{CommonName: "Test DS under intermediate", Organization: []string{"Yivi Test"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{isoMdocDocumentSignerEKU},
	}
	dsDER, err := x509.CreateCertificate(rand.Reader, dsTemplate, interCert, &dsKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("create DS cert: %v", err)
	}
	dsCert, err := x509.ParseCertificate(dsDER)
	if err != nil {
		t.Fatalf("parse DS cert: %v", err)
	}

	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	deviceKey, err := coseKeyFromECDSA(holder.PublicKey())
	if err != nil {
		t.Fatalf("coseKeyFromECDSA: %v", err)
	}

	const docType = "eu.europa.ec.av.1"
	item := IssuerSignedItem{DigestID: 0, Random: make([]byte, saltLength), ElementIdentifier: "age_over_18", ElementValue: true}
	digest, err := hashTag24Item(item)
	if err != nil {
		t.Fatalf("hashTag24Item: %v", err)
	}
	now := time.Now().UTC()
	msoBytes, err := tag24WrapWithMode(MSO{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		ValueDigests:    map[string]map[uint64][]byte{docType: {0: digest}},
		DocType:         docType,
		ValidityInfo:    ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(24 * time.Hour)},
		DeviceKeyInfo:   DeviceKeyInfo{DeviceKey: deviceKey},
	}, tdateEncMode)
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
	// The document signer alone, so no CA travels with the credential.
	msg.Headers.Unprotected[int64(33)] = [][]byte{dsCert.Raw}
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

	return &MDoc{
		DocType: docType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{docType: {{EncodedItem: wrapped}}},
			IssuerAuth: coseBytes,
		},
	}, rootCert, interCert
}

// TestVerifierUsesPinnedIntermediates holds the verifier to using both halves
// of a pinned chain. Before it did, a wallet with the whole staging chain
// installed still rejected staging-issued mdocs as signed by an unknown
// authority, because the CA that signs document signers is an intermediate and
// only Roots was passed on.
func TestVerifierUsesPinnedIntermediates(t *testing.T) {
	doc, root, intermediate := buildPinnedChainMDoc(t)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)

	verifier := NewVerifierFromOptions(func() x509.VerifyOptions {
		return x509.VerifyOptions{Roots: roots, Intermediates: intermediates}
	})

	resolved, result := verifier.VerifyAllDisclosedNamespaces(doc)
	if !result.Valid {
		t.Fatalf("expected the pinned intermediate to complete the chain, got %q", result.Error)
	}
	if got := resolved["eu.europa.ec.av.1"]["age_over_18"]; got != true {
		t.Errorf("age_over_18 = %v, want true", got)
	}
}

// TestVerifierRejectsUnbridgeableChain is the other side of it: a root on its
// own is not enough when nothing supplies the CA in between, and the rejection
// has to name the document signer. The bare x509 error cannot distinguish an
// issuer whose CA is not pinned at all from one a level too deep, and that
// distinction is the whole diagnosis when a wallet meets a new issuer.
func TestVerifierRejectsUnbridgeableChain(t *testing.T) {
	doc, root, _ := buildPinnedChainMDoc(t)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	verifier := NewVerifierFromPool(roots)

	_, result := verifier.VerifyAllDisclosedNamespaces(doc)
	if result.Valid {
		t.Fatal("expected rejection: no path from the document signer to the root")
	}
	if !strings.Contains(result.Error, "chain verification failed") {
		t.Errorf("error = %q, want it to report the chain failure", result.Error)
	}
	if !strings.Contains(result.Error, "Test DS under intermediate") {
		t.Errorf("error = %q, want it to name the document signer", result.Error)
	}
	if !strings.Contains(result.Error, "Test Attestation Providers CA") {
		t.Errorf("error = %q, want it to name the CA that signed the document signer", result.Error)
	}
	// The serial is what turns the rejection into a certificate search at the
	// CA that issued it.
	if !strings.Contains(result.Error, "serial C0FFEE") {
		t.Errorf("error = %q, want it to carry the document signer's serial", result.Error)
	}
}

// TestVerifierReadsAnchorsPerVerification pins the second property: anchors are
// read per verification, not captured at construction. The wallet rebuilds both
// trust models on every Configuration.Reload, which is how toggling developer
// mode adds and drops the staging anchors, and rebuilding replaces the pools
// rather than mutating them.
//
// Both directions are asserted. Anchors appearing later have to take effect
// without reconstructing the verifier, and, the direction that actually
// matters, anchors that were dropped must stop being honoured: a wallet that
// keeps accepting staging-issued credentials after developer mode is switched
// off is a trust relaxation outliving the setting that authorized it.
func TestVerifierReadsAnchorsPerVerification(t *testing.T) {
	doc, root, intermediate := buildPinnedChainMDoc(t)

	trusted := x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	trusted.Roots.AddCert(root)
	trusted.Intermediates.AddCert(intermediate)

	// current stands in for the trust model: Reload hands out a whole new pair
	// of pools, so the verifier cannot be holding either one.
	current := x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	verifier := NewVerifierFromOptions(func() x509.VerifyOptions { return current })

	if _, result := verifier.VerifyAllDisclosedNamespaces(doc); result.Valid {
		t.Fatal("expected rejection while no anchors are loaded")
	}

	current = trusted
	if _, result := verifier.VerifyAllDisclosedNamespaces(doc); !result.Valid {
		t.Fatalf("expected anchors loaded after construction to take effect, got %q", result.Error)
	}

	current = x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	if _, result := verifier.VerifyAllDisclosedNamespaces(doc); result.Valid {
		t.Fatal("expected rejection once the anchors were dropped again")
	}
}
