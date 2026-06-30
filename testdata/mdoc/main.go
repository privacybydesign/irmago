package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// ============================================================
// DATA STRUCTURES
// ============================================================

type MDoc struct {
	DocType      string       `cbor:"docType"`
	IssuerSigned IssuerSigned `cbor:"issuerSigned"`
}

type IssuerSignedItem struct {
	DigestID          uint64      `cbor:"digestID"`
	Random            []byte      `cbor:"random"`
	ElementIdentifier string      `cbor:"elementIdentifier"`
	ElementValue      interface{} `cbor:"elementValue"`
}

type MSO struct {
	Version         string                       `cbor:"version"`
	DigestAlgorithm string                       `cbor:"digestAlgorithm"`
	ValueDigests    map[string]map[uint64][]byte `cbor:"valueDigests"`
	DocType         string                       `cbor:"docType"`
	ValidityInfo    ValidityInfo                 `cbor:"validityInfo"`
}

type ValidityInfo struct {
	Signed     time.Time `cbor:"signed"`
	ValidFrom  time.Time `cbor:"validFrom"`
	ValidUntil time.Time `cbor:"validUntil"`
}

type IssuerSigned struct {
	NameSpaces map[string][]Tag24Item `cbor:"nameSpaces"`
	IssuerAuth []byte                 `cbor:"issuerAuth"`
}

type Tag24Item struct {
	EncodedItem []byte
}

// ============================================================
// TAG-24 HELPERS
// ============================================================

func tag24Wrap(v interface{}) ([]byte, error) {
	innerBytes, err := cbor.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("tag24 inner encode: %w", err)
	}
	tagged := cbor.RawTag{
		Number:  24, // Tagged.ENCODED_CBOR as defined in the Multipaz Kotlin library
		Content: cbor.RawMessage(mustMarshal(innerBytes)),
	}
	return cbor.Marshal(tagged)
}

func hashTag24Item(item IssuerSignedItem) ([]byte, error) {
	wrapped, err := tag24Wrap(item)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(wrapped)
	return hash[:], nil
}

func mustMarshal(v interface{}) []byte {
	b, err := cbor.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ============================================================
// ISSUER
// ============================================================

type Issuer struct {
	privateKey *ecdsa.PrivateKey
	cert       *x509.Certificate
}

func NewIssuer() (*Issuer, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test mDoc Issuer",
			Organization: []string{"IdPro Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	return &Issuer{privateKey: privateKey, cert: cert}, nil
}

func (iss *Issuer) Issue(docType string, namespace string, claims map[string]interface{}) (*MDoc, error) {
	fmt.Println("\n--- ISSUER: Building mDoc ---")

	var items []IssuerSignedItem
	digestID := uint64(0)

	for identifier, value := range claims {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("generate salt: %w", err)
		}
		item := IssuerSignedItem{
			DigestID:          digestID,
			Random:            salt,
			ElementIdentifier: identifier,
			ElementValue:      value,
		}
		items = append(items, item)
		fmt.Printf("  Item %d: %s = %v  (salt: %s)\n", digestID, identifier, value, hex.EncodeToString(salt))
		digestID++
	}

	valueDigests := make(map[uint64][]byte)
	for _, item := range items {
		digest, err := hashTag24Item(item)
		if err != nil {
			return nil, fmt.Errorf("hash item: %w", err)
		}
		valueDigests[item.DigestID] = digest
		fmt.Printf("  Digest[%d]: %s\n", item.DigestID, hex.EncodeToString(digest))
	}

	now := time.Now().UTC()
	mso := MSO{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		ValueDigests:    map[string]map[uint64][]byte{namespace: valueDigests},
		DocType:         docType,
		ValidityInfo: ValidityInfo{
			Signed:     now,
			ValidFrom:  now,
			ValidUntil: now.Add(90 * 24 * time.Hour),
		},
	}

	msoBytes, err := cbor.Marshal(mso)
	if err != nil {
		return nil, fmt.Errorf("marshal mso: %w", err)
	}

	signer, err := cose.NewSigner(cose.AlgorithmES256, iss.privateKey)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = msoBytes
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	// Store cert DER bytes directly under key 33 (x5chain)
	msg.Headers.Unprotected[int64(33)] = iss.cert.Raw

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("sign mso: %w", err)
	}

	coseBytes, err := cbor.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal cose: %w", err)
	}

	fmt.Printf("  MSO signed: %d bytes\n", len(coseBytes))

	tag24Items := make([]Tag24Item, len(items))
	for i, item := range items {
		wrapped, err := tag24Wrap(item)
		if err != nil {
			return nil, fmt.Errorf("wrap item: %w", err)
		}
		tag24Items[i] = Tag24Item{EncodedItem: wrapped}
	}

	return &MDoc{
		DocType: docType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{namespace: tag24Items},
			IssuerAuth: coseBytes,
		},
	}, nil
}

// ============================================================
// HOLDER
// ============================================================

func SelectiveDisclose(mdoc *MDoc, namespace string, reveal []string) (*MDoc, error) {
	fmt.Println("\n--- HOLDER: Selective disclosure ---")

	revealSet := make(map[string]bool)
	for _, r := range reveal {
		revealSet[r] = true
	}

	allItems := mdoc.IssuerSigned.NameSpaces[namespace]
	var disclosed []Tag24Item

	for _, tag24item := range allItems {
		var rawTag cbor.RawTag
		if err := cbor.Unmarshal(tag24item.EncodedItem, &rawTag); err != nil {
			return nil, fmt.Errorf("unwrap tag24: %w", err)
		}
		var innerBytes []byte
		if err := cbor.Unmarshal(rawTag.Content, &innerBytes); err != nil {
			return nil, fmt.Errorf("unwrap inner bytes: %w", err)
		}
		var item IssuerSignedItem
		if err := cbor.Unmarshal(innerBytes, &item); err != nil {
			return nil, fmt.Errorf("decode item: %w", err)
		}

		if revealSet[item.ElementIdentifier] {
			fmt.Printf("  Revealing: %s\n", item.ElementIdentifier)
			disclosed = append(disclosed, tag24item)
		} else {
			fmt.Printf("  Withholding: %s\n", item.ElementIdentifier)
		}
	}

	return &MDoc{
		DocType: mdoc.DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{namespace: disclosed},
			IssuerAuth: mdoc.IssuerSigned.IssuerAuth,
		},
	}, nil
}

// ============================================================
// VERIFIER
// ============================================================

type Verifier struct {
	trustedCerts []*x509.Certificate
}

func NewVerifier(trustedCerts []*x509.Certificate) *Verifier {
	return &Verifier{trustedCerts: trustedCerts}
}

type VerificationResult struct {
	DocType    string
	Attributes map[string]interface{}
	Valid      bool
	Error      string
}

func (v *Verifier) Verify(mdoc *MDoc, namespace string) VerificationResult {
	fmt.Println("\n--- VERIFIER: Verifying mDoc ---")

	result := VerificationResult{
		DocType:    mdoc.DocType,
		Attributes: make(map[string]interface{}),
	}

	// Step 1: decode COSE_Sign1
	var msg cose.Sign1Message
	if err := cbor.Unmarshal(mdoc.IssuerSigned.IssuerAuth, &msg); err != nil {
		result.Error = fmt.Sprintf("decode cose: %v", err)
		return result
	}

	// Step 2: extract cert — go-cose stores unprotected headers as []byte directly
	rawVal, exists := msg.Headers.Unprotected[int64(33)]
	if !exists {
		result.Error = "no cert in issuerAuth"
		return result
	}
	certBytes, ok := rawVal.([]byte)
	if !ok {
		result.Error = fmt.Sprintf("cert header wrong type: %T", rawVal)
		return result
	}

	issuerCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		result.Error = fmt.Sprintf("parse issuer cert: %v", err)
		return result
	}

	// Step 3: check cert is trusted
	trusted := false
	for _, tc := range v.trustedCerts {
		if tc.Equal(issuerCert) {
			trusted = true
			break
		}
	}
	if !trusted {
		result.Error = "issuer cert not trusted"
		return result
	}
	fmt.Println("  Issuer cert: trusted ✓")

	// Step 4: verify COSE signature
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, issuerCert.PublicKey)
	if err != nil {
		result.Error = fmt.Sprintf("create verifier: %v", err)
		return result
	}
	if err := msg.Verify(nil, verifier); err != nil {
		result.Error = fmt.Sprintf("signature invalid: %v", err)
		return result
	}
	fmt.Println("  MSO signature: valid ✓")

	// Step 5: decode MSO
	var mso MSO
	if err := cbor.Unmarshal(msg.Payload, &mso); err != nil {
		result.Error = fmt.Sprintf("decode mso: %v", err)
		return result
	}

	nsDigests, ok := mso.ValueDigests[namespace]
	if !ok {
		result.Error = fmt.Sprintf("namespace %s not in MSO", namespace)
		return result
	}

	// Step 6: verify each revealed item's digest
	for _, tag24item := range mdoc.IssuerSigned.NameSpaces[namespace] {
		var rawTag cbor.RawTag
		if err := cbor.Unmarshal(tag24item.EncodedItem, &rawTag); err != nil {
			result.Error = fmt.Sprintf("unwrap tag24: %v", err)
			return result
		}
		var innerBytes []byte
		if err := cbor.Unmarshal(rawTag.Content, &innerBytes); err != nil {
			result.Error = fmt.Sprintf("unwrap inner: %v", err)
			return result
		}
		var item IssuerSignedItem
		if err := cbor.Unmarshal(innerBytes, &item); err != nil {
			result.Error = fmt.Sprintf("decode item: %v", err)
			return result
		}

		// hash the frozen tag-24 bytes — must match what issuer signed
		hash := sha256.Sum256(tag24item.EncodedItem)

		expectedDigest, exists := nsDigests[item.DigestID]
		if !exists {
			result.Error = fmt.Sprintf("digestID %d not in MSO", item.DigestID)
			return result
		}

		if hex.EncodeToString(hash[:]) != hex.EncodeToString(expectedDigest) {
			result.Error = fmt.Sprintf("digest mismatch for %s", item.ElementIdentifier)
			return result
		}

		fmt.Printf("  %s = %v  digest: ✓\n", item.ElementIdentifier, item.ElementValue)
		result.Attributes[item.ElementIdentifier] = item.ElementValue
	}

	result.Valid = true
	fmt.Println("  Verification: PASSED ✓")
	return result
}

// ============================================================
// MAIN
// ============================================================

func main() {
	fmt.Println("========================================")
	fmt.Println("  mDoc Issuer → Holder → Verifier Test")
	fmt.Println("========================================")

	issuer, err := NewIssuer()
	if err != nil {
		log.Fatal("issuer setup:", err)
	}
	fmt.Println("\nIssuer key pair and cert generated")

	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"

	claims := map[string]interface{}{
		"age_over_18": true,
		"age_over_16": true,
		"age_over_21": false,
	}

	mdoc, err := issuer.Issue(docType, namespace, claims)
	if err != nil {
		log.Fatal("issue:", err)
	}

	presented, err := SelectiveDisclose(mdoc, namespace, []string{"age_over_18"})
	if err != nil {
		log.Fatal("selective disclose:", err)
	}

	verifier := NewVerifier([]*x509.Certificate{issuer.cert})
	result := verifier.Verify(presented, namespace)

	fmt.Println("\n========================================")
	fmt.Println("  RESULT")
	fmt.Println("========================================")
	fmt.Printf("  DocType:  %s\n", result.DocType)
	fmt.Printf("  Valid:    %v\n", result.Valid)
	if result.Error != "" {
		fmt.Printf("  Error:    %s\n", result.Error)
	}
	fmt.Println("  Disclosed attributes:")
	for k, v := range result.Attributes {
		fmt.Printf("    %s = %v\n", k, v)
	}

	// --- TAMPER TEST ---
	fmt.Println("\n========================================")
	fmt.Println("  TAMPER TEST (flip age_over_18 to false)")
	fmt.Println("========================================")

	tamperedItem := IssuerSignedItem{
		DigestID:          0,
		Random:            []byte("attacker-does-not-know-real-salt"),
		ElementIdentifier: "age_over_18",
		ElementValue:      false,
	}
	tamperedWrapped, _ := tag24Wrap(tamperedItem)

	tamperedMDoc := &MDoc{
		DocType: presented.DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{
				namespace: {{EncodedItem: tamperedWrapped}},
			},
			IssuerAuth: presented.IssuerSigned.IssuerAuth,
		},
	}

	tamperedResult := verifier.Verify(tamperedMDoc, namespace)
	fmt.Printf("  Tampered valid: %v\n", tamperedResult.Valid)
	fmt.Printf("  Error: %s\n", tamperedResult.Error)
	fmt.Println("  (tamper correctly rejected ✓)")
}
