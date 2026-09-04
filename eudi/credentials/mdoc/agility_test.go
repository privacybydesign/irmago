package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	cose "github.com/veraison/go-cose"
)

// ============================================================
// ALGORITHM AND CURVE AGILITY
//
// 9.1.2.4: "For verifying the signature, the mdoc reader shall support all of
// these signature algorithms and curves" — ES256, ES384, ES512, EdDSA.
// 9.1.2.5: the issuer picks SHA-256, SHA-384 or SHA-512 and declares which.
// Table 22: "Support for all curves is mandatory for an mdoc reader."
//
// Every case below was rejected before, and rejected with a message pointing
// somewhere else: an ES384 credential failed as an opaque algorithm mismatch, a
// SHA-384 one as a digest mismatch on a named element that was in fact intact.
// ============================================================

// issuerOn builds an IACA + DS chain on the given curve.
func issuerOn(t *testing.T, curve elliptic.Curve) *Issuer {
	t.Helper()

	newCert := func(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatalf("create certificate: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse certificate: %v", err)
		}
		return cert
	}

	iacaKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate IACA key: %v", err)
	}
	iacaTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Agility IACA " + curve.Params().Name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	iacaCert := newCert(iacaTmpl, iacaTmpl, &iacaKey.PublicKey, iacaKey)

	dsKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate DS key: %v", err)
	}
	dsTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Agility DS " + curve.Params().Name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	dsCert := newCert(dsTmpl, iacaCert, &dsKey.PublicKey, iacaKey)

	return &Issuer{iacakey: iacaKey, iacacert: iacaCert, dskey: dsKey, dscert: dsCert}
}

// signMSO signs mso with iss's DS key using alg, and assembles the document.
func signMSO(t *testing.T, iss *Issuer, alg cose.Algorithm, namespace string, mso MSO, items [][]byte) *MDoc {
	t.Helper()

	msoBytes, err := tag24WrapWithMode(mso, tdateEncMode)
	if err != nil {
		t.Fatalf("wrap mso: %v", err)
	}
	signer, err := cose.NewSigner(alg, iss.dskey)
	if err != nil {
		t.Fatalf("cose.NewSigner(%v): %v", alg, err)
	}
	msg := cose.UntaggedSign1Message{Headers: cose.NewSign1Message().Headers, Payload: msoBytes}
	msg.Headers.Protected.SetAlgorithm(alg)
	msg.Headers.Unprotected[int64(33)] = [][]byte{iss.dscert.Raw, iss.iacacert.Raw}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	coseBytes, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	tag24 := make([]Tag24Item, len(items))
	for i, b := range items {
		tag24[i] = Tag24Item{EncodedItem: b}
	}
	return &MDoc{
		DocType: mso.DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{namespace: tag24},
			IssuerAuth: coseBytes,
		},
	}
}

// msoOver is a valid MSO over one digest, bound to holderPub.
func msoOver(t *testing.T, namespace, digestAlgorithm string, digest []byte, holderPub *ecdsa.PublicKey) MSO {
	t.Helper()
	deviceKey, err := coseKeyFromECDSA(holderPub)
	if err != nil {
		t.Fatalf("coseKeyFromECDSA: %v", err)
	}
	now := time.Now().UTC()
	return MSO{
		Version:         "1.0",
		DigestAlgorithm: digestAlgorithm,
		ValueDigests:    map[string]map[uint64][]byte{namespace: {0: digest}},
		DocType:         namespace,
		ValidityInfo:    ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(time.Hour)},
		DeviceKeyInfo:   DeviceKeyInfo{DeviceKey: deviceKey},
	}
}

// TestIssuerAuthAlgorithmAgility covers the three ECDSA algorithms across their
// matching curves. Each case is a complete, genuine credential; the only thing
// varying is the algorithm the document signer used.
func TestIssuerAuthAlgorithmAgility(t *testing.T) {
	const ns = "org.iso.18013.5.1.mDL"

	for _, tc := range []struct {
		curve elliptic.Curve
		alg   cose.Algorithm
	}{
		{elliptic.P256(), cose.AlgorithmES256},
		{elliptic.P384(), cose.AlgorithmES384},
		{elliptic.P521(), cose.AlgorithmES512},
	} {
		t.Run(tc.curve.Params().Name, func(t *testing.T) {
			iss := issuerOn(t, tc.curve)
			holder, err := NewHolder()
			if err != nil {
				t.Fatalf("NewHolder: %v", err)
			}
			encoded, digest := wrapItem(t, IssuerSignedItem{
				DigestID: 0, Random: make([]byte, minSaltLength),
				ElementIdentifier: "family_name", ElementValue: "Doe",
			})

			doc := signMSO(t, iss, tc.alg, ns, msoOver(t, ns, "SHA-256", digest, holder.PublicKey()), [][]byte{encoded})
			result := NewVerifier([]*x509.Certificate{iss.IACACert()}).Verify(doc, ns)

			if !result.Valid {
				t.Fatalf("%v over %s is one of the four algorithms 9.1.2.4 obliges a reader to support: %s",
					tc.alg, tc.curve.Params().Name, result.Error)
			}
			if result.Attributes["family_name"] != "Doe" {
				t.Errorf("attribute did not survive: %v", result.Attributes)
			}
		})
	}
}

// TestPermittedSignatureAlgorithms pins the allow-list itself: reading alg from
// the header must not degrade into accepting whatever the document declares.
// go-cose implements RSA-PSS, which ISO/IEC 18013-5 does not permit for an MSO.
func TestPermittedSignatureAlgorithms(t *testing.T) {
	for _, required := range []cose.Algorithm{
		cose.AlgorithmES256, cose.AlgorithmES384, cose.AlgorithmES512, cose.AlgorithmEdDSA,
	} {
		if !slices.Contains(mdocSignatureAlgorithms, required) {
			t.Errorf("%v is required by 9.1.2.4 but is not in the permitted set", required)
		}
	}
	for _, forbidden := range []cose.Algorithm{
		cose.AlgorithmPS256, cose.AlgorithmPS384, cose.AlgorithmPS512,
	} {
		if slices.Contains(mdocSignatureAlgorithms, forbidden) {
			t.Errorf("%v is not permitted by ISO/IEC 18013-5 but is in the set", forbidden)
		}
	}
}

// TestDigestAlgorithmAgility covers 9.1.2.5's three permitted digests.
func TestDigestAlgorithmAgility(t *testing.T) {
	const ns = "org.iso.18013.5.1.mDL"

	for _, tc := range []struct {
		name   string
		digest func([]byte) []byte
	}{
		{"SHA-256", sha256Digest},
		{"SHA-384", func(b []byte) []byte { s := sha512.Sum384(b); return s[:] }},
		{"SHA-512", func(b []byte) []byte { s := sha512.Sum512(b); return s[:] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iss, err := NewIssuer()
			if err != nil {
				t.Fatalf("NewIssuer: %v", err)
			}
			holder, err := NewHolder()
			if err != nil {
				t.Fatalf("NewHolder: %v", err)
			}
			encoded, err := tag24Wrap(IssuerSignedItem{
				DigestID: 0, Random: make([]byte, minSaltLength),
				ElementIdentifier: "family_name", ElementValue: "Doe",
			})
			if err != nil {
				t.Fatalf("tag24Wrap: %v", err)
			}

			mso := msoOver(t, ns, tc.name, tc.digest(encoded), holder.PublicKey())
			doc := signMSO(t, iss, cose.AlgorithmES256, ns, mso, [][]byte{encoded})
			result := NewVerifier([]*x509.Certificate{iss.IACACert()}).Verify(doc, ns)

			if !result.Valid {
				t.Fatalf("%s is permitted by 9.1.2.5 Table 21: %s", tc.name, result.Error)
			}
			if result.Attributes["family_name"] != "Doe" {
				t.Errorf("attribute did not survive: %v", result.Attributes)
			}
		})
	}

	t.Run("an algorithm outside Table 21 is refused by name", func(t *testing.T) {
		_, err := digestFuncFor("SHA-1")
		if err == nil {
			t.Fatal("SHA-1 must be refused; Table 21 permits only SHA-256, SHA-384 and SHA-512")
		}
		if !strings.Contains(err.Error(), "SHA-1") {
			t.Errorf("rejection should name the declared algorithm, got: %v", err)
		}
	})
}

// TestDeviceKeyCurveAgility covers Table 22 for the device key. A P-384 or P-521
// deviceKeyInfo previously encoded to a corrupt key labelled P-256, and decoded
// to nothing at all.
func TestDeviceKeyCurveAgility(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}

			coseKey, err := coseKeyFromECDSA(&key.PublicKey)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			// The coordinates must be the curve's own width, not P-256's. This is the
			// assertion that would have caught the silent truncation.
			wantLen := coordinateLen(curve)
			if len(coseKey.X) != wantLen || len(coseKey.Y) != wantLen {
				t.Fatalf("coordinates are %d/%d bytes, want %d each for %s",
					len(coseKey.X), len(coseKey.Y), wantLen, curve.Params().Name)
			}

			back, err := ecdsaPublicKeyFromCOSE(coseKey)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !back.Equal(&key.PublicKey) {
				t.Fatal("round trip did not preserve the key — the curve label or the coordinate width is wrong")
			}
		})
	}

	t.Run("an unsupported EC2 curve is refused by identifier", func(t *testing.T) {
		// 256 is brainpoolP256r1 in the IANA COSE registry: permitted by Table 22,
		// absent from the Go standard library, and therefore refused rather than
		// mis-decoded as something else.
		_, err := ecdsaPublicKeyFromCOSE(COSEKey{Kty: 2, Crv: 256, X: []byte{1}, Y: []byte{2}})
		if err == nil {
			t.Fatal("an unsupported curve must be refused, not mis-decoded")
		}
		if !strings.Contains(err.Error(), "256") {
			t.Errorf("rejection should name the curve identifier, got: %v", err)
		}
	})

	t.Run("an OKP key is refused with a diagnosis", func(t *testing.T) {
		_, err := ecdsaPublicKeyFromCOSE(COSEKey{Kty: 1, Crv: 6, X: []byte{1}})
		if err == nil {
			t.Fatal("an Ed25519 OKP key must be refused rather than read as EC2")
		}
		if !strings.Contains(err.Error(), "OKP") {
			t.Errorf("rejection should say the key is OKP rather than malformed, got: %v", err)
		}
	})
}

// TestDeviceAuthOnEveryCurve is the end-to-end counterpart: a device key on each
// curve signs a presentation and the verifier accepts it, with the algorithm
// resolved from the curve independently on both sides.
func TestDeviceAuthOnEveryCurve(t *testing.T) {
	const dt = "org.iso.18013.5.1.mDL"

	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			deviceKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("generate device key: %v", err)
			}
			holder, err := NewHolderFromPrivateKey(deviceKey)
			if err != nil {
				t.Fatalf("NewHolderFromPrivateKey: %v", err)
			}
			iss, err := NewIssuer()
			if err != nil {
				t.Fatalf("NewIssuer: %v", err)
			}
			doc, err := iss.Issue(dt, dt, map[string]any{"family_name": "Doe"}, holder.PublicKey())
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			presented, err := SelectiveDisclose(doc, dt, []string{"family_name"})
			if err != nil {
				t.Fatalf("SelectiveDisclose: %v", err)
			}
			transcript := SessionTranscript{Handover: "test-handover"}
			deviceAuth, err := holder.SignDeviceAuth(dt, transcript)
			if err != nil {
				t.Fatalf("SignDeviceAuth: %v", err)
			}

			result := NewVerifier([]*x509.Certificate{iss.IACACert()}).
				VerifyWithDeviceAuth(presented, dt, dt, transcript, deviceAuth)
			if !result.Valid || !result.DeviceAuthValid {
				t.Fatalf("a %s device key is conformant: valid=%v deviceAuth=%v err=%q",
					curve.Params().Name, result.Valid, result.DeviceAuthValid, result.Error)
			}
		})
	}
}
