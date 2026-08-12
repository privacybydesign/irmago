package eudicli

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/stretchr/testify/require"
)

// An independent check on the signature layer.
//
// Every other test here signs with lestrrat-go/jwx and verifies with the same
// library, so a jwx bug that both produced and accepted a malformed JWS would go
// unseen — and that is precisely the layer `testdata/lote-publisher/publish.py`
// was built to guard: "how a foreign toolchain emits the `x5c` chain, orders the
// protected header, or encodes an ECDSA signature". The production publisher
// shares the wallet's library, so that guard had to be replaced rather than
// inherited.
//
// This is the replacement. Nothing here asks jwx what it signed: the compact
// serialization is split on the wire, the protected header is parsed as plain
// JSON, the certificate is decoded out of `x5c` as standard base64, and the
// signature is checked by **openssl** — a toolchain with no shared code with the
// signer. It is the exact inverse of publish.py's der_sig_to_raw.
//
// The ETSI schema covers the document layer (see eudi/trust/lote/validate_test.go);
// between them the two layers a published LoTE consists of are each checked
// against something that did not produce them.
func TestSignature_VerifiesUnderAForeignToolchain(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}

	list, err := loadSource(exampleSource(t), issuedAt)
	require.NoError(t, err)

	signer := newTestSigner(t, "NL", "Yivi Example")
	alg, err := signatureAlgorithm(signer.key)
	require.NoError(t, err)
	signed, err := signDocument(lote.Document{LoTE: list}, []*x509.Certificate{signer.leaf}, signer.key, alg)
	require.NoError(t, err)

	// --- take the document apart on the wire, not through the library ---------
	parts := strings.Split(string(signed), ".")
	require.Len(t, parts, 3, "a compact JWS has exactly three parts")
	signingInput := parts[0] + "." + parts[1]

	protected, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err, "the protected header must be base64url without padding")

	var header struct {
		Typ string   `json:"typ"`
		Alg string   `json:"alg"`
		X5c []string `json:"x5c"`
	}
	require.NoError(t, json.Unmarshal(protected, &header))
	require.Equal(t, lote.LoteTyp, header.Typ, "the typ guard is what says this JWS is a trusted list")
	require.Equal(t, "ES256", header.Alg)
	require.Len(t, header.X5c, 1)

	// RFC 7515 requires x5c entries to be *standard* base64, unlike everything
	// else in a JWS. Decoding it strictly is the assertion.
	leafDer, err := base64.StdEncoding.DecodeString(header.X5c[0])
	require.NoError(t, err, "x5c must be standard base64, not base64url")
	require.Equal(t, signer.leaf.Raw, leafDer)

	// --- ES256 is raw r||s; openssl wants DER ---------------------------------
	rawSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.Len(t, rawSignature, 64, "ES256 is a fixed 32-byte r followed by a fixed 32-byte s")

	derSignature, err := asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(rawSignature[:32]),
		S: new(big.Int).SetBytes(rawSignature[32:]),
	})
	require.NoError(t, err)

	// --- and let openssl be the judge ----------------------------------------
	dir := t.TempDir()
	publicKeyPath := filepath.Join(dir, "signer.pub.pem")
	publicKeyDer, err := x509.MarshalPKIXPublicKey(signer.leaf.PublicKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(publicKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDer}), 0o600))

	signaturePath := filepath.Join(dir, "signature.der")
	require.NoError(t, os.WriteFile(signaturePath, derSignature, 0o600))

	command := exec.Command(openssl, "dgst", "-sha256", "-verify", publicKeyPath, "-signature", signaturePath)
	command.Stdin = strings.NewReader(signingInput)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "openssl rejected a signature jwx produced: %s", output)
	require.Contains(t, string(output), "Verified OK")
}

// The same check, run against a document whose payload was altered after signing:
// if openssl accepted this too, the test above would be proving nothing.
func TestSignature_AForeignToolchainRejectsATamperedPayload(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}

	list, err := loadSource(exampleSource(t), issuedAt)
	require.NoError(t, err)
	signer := newTestSigner(t, "NL", "Yivi Example")
	alg, err := signatureAlgorithm(signer.key)
	require.NoError(t, err)
	signed, err := signDocument(lote.Document{LoTE: list}, []*x509.Certificate{signer.leaf}, signer.key, alg)
	require.NoError(t, err)

	parts := strings.Split(string(signed), ".")
	require.Len(t, parts, 3)

	// Re-issue the payload with a bumped sequence number, leaving the signature
	// as it was — the substitution the signature exists to prevent.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var document lote.Document
	require.NoError(t, json.Unmarshal(payload, &document))
	document.LoTE.SchemeInformation.SequenceNumber = 99
	tampered, err := json.Marshal(document)
	require.NoError(t, err)

	signingInput := parts[0] + "." + base64.RawURLEncoding.EncodeToString(tampered)

	rawSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	derSignature, err := asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(rawSignature[:32]),
		S: new(big.Int).SetBytes(rawSignature[32:]),
	})
	require.NoError(t, err)

	dir := t.TempDir()
	publicKeyPath := filepath.Join(dir, "signer.pub.pem")
	publicKeyDer, err := x509.MarshalPKIXPublicKey(signer.leaf.PublicKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(publicKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDer}), 0o600))
	signaturePath := filepath.Join(dir, "signature.der")
	require.NoError(t, os.WriteFile(signaturePath, derSignature, 0o600))

	command := exec.Command(openssl, "dgst", "-sha256", "-verify", publicKeyPath, "-signature", signaturePath)
	command.Stdin = strings.NewReader(signingInput)
	output, err := command.CombinedOutput()
	require.Error(t, err, "openssl accepted a tampered payload: %s", output)
}
