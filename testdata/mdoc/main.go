package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
		Number:  24,
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
	iacakey  *ecdsa.PrivateKey
	iacacert *x509.Certificate

	dskey  *ecdsa.PrivateKey
	dscert *x509.Certificate
}

func NewIssuer() (*Issuer, error) {
	// ── Step 1: IACA root CA (self-signed, kept offline in production) ──
	iacaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate IACA key: %w", err)
	}

	iacaSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	iacaTemplate := &x509.Certificate{
		SerialNumber: iacaSerial,
		Subject: pkix.Name{
			CommonName:   "Test Age Verification IACA Root CA",
			Organization: []string{"Yivi Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// self-signed: parent == template
	iacaDER, err := x509.CreateCertificate(rand.Reader, iacaTemplate, iacaTemplate, &iacaKey.PublicKey, iacaKey)
	if err != nil {
		return nil, fmt.Errorf("create IACA cert: %w", err)
	}

	iacaCert, err := x509.ParseCertificate(iacaDER)
	if err != nil {
		return nil, fmt.Errorf("parse IACA cert: %w", err)
	}

	// ── Step 2: DS cert (signed by IACA root, used online to sign MSOs) ──
	dsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate DS key: %w", err)
	}

	dsSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	dsTemplate := &x509.Certificate{
		SerialNumber: dsSerial,
		Subject: pkix.Name{
			CommonName:   "Test Age Verification DS - 001",
			Organization: []string{"Yivi Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// parent = iacaCert (parsed cert), signed with iacaKey
	dsDER, err := x509.CreateCertificate(rand.Reader, dsTemplate, iacaCert, &dsKey.PublicKey, iacaKey)
	if err != nil {
		return nil, fmt.Errorf("create DS cert: %w", err)
	}

	dsCert, err := x509.ParseCertificate(dsDER)
	if err != nil {
		return nil, fmt.Errorf("parse DS cert: %w", err)
	}

	return &Issuer{
		iacakey:  iacaKey,
		iacacert: iacaCert,
		dskey:    dsKey,
		dscert:   dsCert,
	}, nil
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

	// sign with dskey (NOT the IACA key)
	signer, err := cose.NewSigner(cose.AlgorithmES256, iss.dskey)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = msoBytes
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)

	// x5chain header 33: [DS cert, IACA cert]
	// EU root NOT included — verifier has it pre-installed
	chain := [][]byte{
		iss.dscert.Raw,   // leaf — verifier uses this pubkey to verify MSO
		iss.iacacert.Raw, // intermediate — verifier uses this to verify DS cert
	}
	msg.Headers.Unprotected[int64(33)] = chain

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("sign mso: %w", err)
	}

	coseBytes, err := cbor.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal cose: %w", err)
	}

	fmt.Printf("  MSO signed by DS cert ✓  (%d bytes)\n", len(coseBytes))
	fmt.Printf("  x5chain: DS cert + IACA cert\n")

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
	// trustedRoots: IACA root cert(s) pre-installed on the verifier
	// Phase 1: test self-signed IACA root
	// Phase 2: Yivi's own IACA root, manually configured
	// Phase 3: EU AV Blueprint root CA cert
	trustedRoots *x509.CertPool
}

func NewVerifier(rootCerts []*x509.Certificate) *Verifier {
	pool := x509.NewCertPool()
	for _, c := range rootCerts {
		pool.AddCert(c)
	}
	return &Verifier{trustedRoots: pool}
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

	// Step 2: extract x5chain from unprotected header 33
	// x5chain = [DS cert DER, IACA cert DER]
	rawVal, exists := msg.Headers.Unprotected[int64(33)]
	if !exists {
		result.Error = "no x5chain in issuerAuth header 33"
		return result
	}

	// go-cose decodes [][]byte as []interface{} where each element is []byte
	chainRaw, ok := rawVal.([]interface{})
	if !ok {
		// fallback: single cert (old self-signed style)
		single, ok2 := rawVal.([]byte)
		if !ok2 {
			result.Error = fmt.Sprintf("x5chain wrong type: %T", rawVal)
			return result
		}
		chainRaw = []interface{}{single}
	}

	if len(chainRaw) == 0 {
		result.Error = "x5chain is empty"
		return result
	}

	// parse all certs in the chain
	certs := make([]*x509.Certificate, 0, len(chainRaw))
	for i, raw := range chainRaw {
		b, ok := raw.([]byte)
		if !ok {
			result.Error = fmt.Sprintf("x5chain[%d] wrong type: %T", i, raw)
			return result
		}
		c, err := x509.ParseCertificate(b)
		if err != nil {
			result.Error = fmt.Sprintf("parse x5chain[%d]: %v", i, err)
			return result
		}
		certs = append(certs, c)
	}

	// certs[0] = DS cert (leaf), certs[1..] = intermediates (IACA cert)
	dsCert := certs[0]

	// build intermediate pool from certs[1..n]
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	// Step 3: verify full chain — DS cert → IACA cert → trusted root
	// x509.Verify walks the chain automatically
	_, err := dsCert.Verify(x509.VerifyOptions{
		Roots:         v.trustedRoots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   time.Now(),
	})
	if err != nil {
		result.Error = fmt.Sprintf("chain verification failed: %v", err)
		return result
	}
	fmt.Printf("  Certificate chain: valid ✓  (depth %d: %s → %s)\n",
		len(certs),
		dsCert.Subject.CommonName,
		certs[len(certs)-1].Subject.CommonName,
	)

	// Step 4: verify COSE_Sign1 signature using DS cert's public key
	coseverifier, err := cose.NewVerifier(cose.AlgorithmES256, dsCert.PublicKey)
	if err != nil {
		result.Error = fmt.Sprintf("create verifier: %v", err)
		return result
	}
	if err := msg.Verify(nil, coseverifier); err != nil {
		result.Error = fmt.Sprintf("MSO signature invalid: %v", err)
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

		hash := sha256.Sum256(tag24item.EncodedItem)
		expectedDigest, exists := nsDigests[item.DigestID]
		if !exists {
			result.Error = fmt.Sprintf("digestID %d not in MSO", item.DigestID)
			return result
		}
		if subtle.ConstantTimeCompare(hash[:], expectedDigest) != 1 {
			// Constant-Time comparison — prevents timing side channel
			// where early exit on first mismatch would leak digest bytes
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
	fmt.Println("  with two-level certificate chain")
	fmt.Println("========================================")

	issuer, err := NewIssuer()
	if err != nil {
		log.Fatal("issuer setup:", err)
	}
	fmt.Println("\nIACA root CA generated (self-signed, offline in production)")
	fmt.Printf("  Subject: %s\n", issuer.iacacert.Subject.CommonName)
	fmt.Println("DS cert generated (signed by IACA root)")
	fmt.Printf("  Subject: %s\n", issuer.dscert.Subject.CommonName)
	fmt.Printf("  Issuer:  %s\n", issuer.dscert.Issuer.CommonName)

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

	// verifier trusts ONLY the IACA root — receives DS cert via x5chain at verification time
	verifier := NewVerifier([]*x509.Certificate{issuer.iacacert})
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

	// ── CHAIN ATTACK TEST ──────────────────────────────────────
	// Attacker generates their own valid IACA + DS pair and issues
	// a correctly signed mDoc — but their IACA root is not in the
	// verifier's trusted pool, so chain verification fails before
	// signature or digest checks are even reached.

	fmt.Println("\n========================================")
	fmt.Println("  CHAIN ATTACK TEST (attacker's own cert chain)")
	fmt.Println("========================================")

	attackerIssuer, _ := NewIssuer()
	// attacker has their own valid IACA+DS chain — but their root is unknown to the verifier
	attackerMDoc, _ := attackerIssuer.Issue(docType, namespace, map[string]interface{}{"age_over_18": true})
	attackerPresented, _ := SelectiveDisclose(attackerMDoc, namespace, []string{"age_over_18"})

	attackResult := verifier.Verify(attackerPresented, namespace)
	fmt.Printf("  Attacker's mDoc valid: %v\n", attackResult.Valid)
	fmt.Printf("  Error: %s\n", attackResult.Error)
	fmt.Println("  (correctly rejected — attacker's root not trusted ✓)")

	// ── TAMPER TEST ────────────────────────────────────────────
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
