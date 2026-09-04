package services

import (
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

func newTestMdocCredentialResponseString(t *testing.T) (raw string, iacaCert *x509.Certificate) {
	t.Helper()

	issuer, err := mdoc.NewIssuer()
	require.NoError(t, err)
	holder, err := mdoc.NewHolder()
	require.NoError(t, err)

	issued, err := issuer.Issue(
		"eu.europa.ec.av.1",
		"eu.europa.ec.av.1",
		map[string]any{"age_over_18": true},
		holder.PublicKey(),
	)
	require.NoError(t, err)

	encoded, err := cbor.Marshal(issued)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(encoded), issuer.IACACert()
}

func TestMdocCredentialFormatParser_ParseAndVerify(t *testing.T) {
	raw, iacaCert := newTestMdocCredentialResponseString(t)
	verifier := mdoc.NewVerifier([]*x509.Certificate{iacaCert})
	parser := NewMdocCredentialFormatParser(verifier)

	parsed, err := parser.ParseAndVerify(raw, "https://test-issuer.example.com", true)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	require.Equal(t, models.CredentialFormatMsoMdoc, parsed.Format)
	require.Equal(t, "eu.europa.ec.av.1", parsed.VerifiableCredentialType)
	require.Equal(t, "https://test-issuer.example.com", parsed.IssuerIdentifier)
	require.NotNil(t, parsed.Mdoc)
	require.NotEmpty(t, parsed.Mdoc.Namespaces)
	require.Equal(t, "eu.europa.ec.av.1", parsed.Mdoc.DocType)
	require.NotEmpty(t, parsed.RawCredentialBytes)
	require.NotNil(t, parsed.IssuedAt)
	require.NotNil(t, parsed.ExpiresAt)
	require.NotNil(t, parsed.NotBefore)
	require.NotEmpty(t, parsed.Mdoc.DeviceKeyThumbprint)
	require.NotNil(t, parsed.Mdoc.DeviceKey)
	require.Nil(t, parsed.SdJwtVc)
}

func TestMdocCredentialFormatParser_ParseAndVerify_UntrustedRootRejected(t *testing.T) {
	raw, _ := newTestMdocCredentialResponseString(t)
	otherIssuer, err := mdoc.NewIssuer()
	require.NoError(t, err)
	verifier := mdoc.NewVerifier([]*x509.Certificate{otherIssuer.IACACert()})
	parser := NewMdocCredentialFormatParser(verifier)

	_, err = parser.ParseAndVerify(raw, "https://test-issuer.example.com", false)
	require.Error(t, err)
}

func TestMdocCredentialFormatParser_ParseAndVerify_InvalidBase64(t *testing.T) {
	verifier := mdoc.NewVerifier(nil)
	parser := NewMdocCredentialFormatParser(verifier)

	_, err := parser.ParseAndVerify("not-valid-base64url!!!", "https://test-issuer.example.com", false)
	require.Error(t, err)
}

// TestDecodeIssuedMdoc covers every wire shape decodeIssuedMdoc accepts and
// every way it refuses one.
//
// The shapes are not hypothetical: OpenID4VCI's mso_mdoc profile specifies a bare
// IssuerSigned, a Document is what travels when the docType has to come with it,
// and the EUDI reference issuer returns a whole DeviceResponse envelope. Which one
// arrives is the issuer's choice, so all three have to decode — and anything else
// has to be refused rather than decoded into a zero-valued struct, which is the
// bug this function was written to fix (it surfaced as "empty COSE_Sign1", blaming
// the issuer's signature for what was a container mismatch).
//
// CBOR unmarshalling is what makes the refusals worth pinning: decoding an
// arbitrary map into MDoc succeeds and yields empty fields, so every branch's
// guard — not its Unmarshal call — is what actually rejects the wrong shape.
func TestDecodeIssuedMdoc(t *testing.T) {
	const docType = "eu.europa.ec.av.1"

	issued := newIssuedMdocDocument(t, docType)

	// A device response whose document omits issuerAuth entirely, for the guard
	// that must refuse it rather than pass an empty COSE_Sign1 on to verification.
	//
	// Built as a raw map rather than from mdoc types on purpose: marshalling a
	// zero-valued IssuerSigned emits `issuerAuth: null`, which decodes back as a
	// one-byte RawMessage and therefore satisfies a length check. Only an absent
	// key reaches this branch — see
	// TestDecodeIssuedMdocLeavesNullIssuerAuthToVerification for where the null
	// spelling is caught instead.
	responseWithoutIssuerAuth := map[string]any{
		"version": "1.0",
		"documents": []any{map[string]any{
			"docType":      docType,
			"issuerSigned": map[string]any{},
		}},
		"status": uint64(0),
	}

	tests := []struct {
		name string
		// encoded is the credential bytes as they arrive, after base64url decoding.
		encoded []byte
		// expectDocType is the docType decodeIssuedMdoc must report on success.
		expectDocType string
		// expectErr, when set, is a substring of the error it must return instead.
		expectErr string
	}{
		{
			name:          "a document carrying docType and issuerSigned",
			encoded:       mustCborMarshal(t, issued),
			expectDocType: docType,
		},
		{
			name:          "a device response wrapping one document",
			encoded:       mustCborMarshal(t, mdoc.NewDeviceResponse(*issued)),
			expectDocType: docType,
		},
		{
			// Which document would be the credential is unanswerable, so this is
			// refused rather than resolved by taking the first.
			name:      "a device response wrapping two documents",
			encoded:   mustCborMarshal(t, mdoc.NewDeviceResponse(*issued, *issued)),
			expectErr: "holds 2 documents",
		},
		{
			name:      "a device response whose document carries no issuerAuth",
			encoded:   mustCborMarshal(t, responseWithoutIssuerAuth),
			expectErr: "carries no issuerAuth",
		},
		{
			// No envelope docType exists here, so the only place left to read it is
			// the MSO the issuer signed. Reporting it empty would fail the verifier's
			// docType check against a value the issuer never sent, so the recovered
			// value is the whole point of this branch.
			name:          "a bare issuerSigned, whose docType comes from the signed MSO",
			encoded:       mustCborMarshal(t, issued.IssuerSigned),
			expectDocType: docType,
		},
		{
			// Reaches the bare-IssuerSigned branch, where the docType has to be read
			// from issuerAuth and there is nothing readable there. Distinct from the
			// case below: the container is recognised, its contents are not.
			name: "a bare issuerSigned whose issuerAuth is not a COSE_Sign1",
			encoded: mustCborMarshal(t, map[string]any{
				"nameSpaces": map[string]any{},
				"issuerAuth": []byte{0x01, 0x02},
			}),
			expectErr: "failed to read docType from issuerAuth",
		},
		{
			name:      "cbor that is none of the three",
			encoded:   mustCborMarshal(t, map[string]any{"credential": "not an mdoc"}),
			expectErr: "neither a Document, a DeviceResponse nor an IssuerSigned",
		},
		{
			name:      "no bytes at all",
			encoded:   nil,
			expectErr: "neither a Document, a DeviceResponse nor an IssuerSigned",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoded, err := decodeIssuedMdoc(test.encoded)

			if test.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectErr)
				require.Nil(t, decoded)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, decoded)
			require.Equal(t, test.expectDocType, decoded.DocType)
			require.NotEmpty(t, decoded.IssuerSigned.IssuerAuth,
				"the decoded credential must carry the issuerAuth verification needs")
			require.Equal(t, issued.IssuerSigned.NameSpaces, decoded.IssuerSigned.NameSpaces,
				"the issuer's namespace bytes must survive decoding unchanged, or their digests stop matching")
		})
	}
}

// TestDecodeIssuedMdocLeavesNullIssuerAuthToVerification pins where a document
// spelling its missing signature as `issuerAuth: null` is caught.
//
// It is not caught at decode: null is one CBOR byte, so it passes a length check
// the way absent bytes do not. That is fine but only because something downstream
// refuses it — so this asserts that ParseAndVerify does, rather than leaving the
// layering to be assumed.
func TestDecodeIssuedMdocLeavesNullIssuerAuthToVerification(t *testing.T) {
	const docType = "eu.europa.ec.av.1"

	encoded := mustCborMarshal(t, mdoc.NewDeviceResponse(mdoc.MDoc{
		DocType:      docType,
		IssuerSigned: mdoc.IssuerSigned{},
	}))

	decoded, err := decodeIssuedMdoc(encoded)
	require.NoError(t, err, "a null issuerAuth is one byte, so decode's length guard does not fire")
	require.Equal(t, docType, decoded.DocType)

	parser := NewMdocCredentialFormatParser(mdoc.NewVerifier(nil))
	_, err = parser.ParseAndVerify(base64.RawURLEncoding.EncodeToString(encoded),
		"https://test-issuer.example.com", false)
	require.Error(t, err, "verification must refuse what decode let through")
}

// TestDecodeIssuedMdocAcceptsEveryShapeTheVerifierThenAccepts checks the three
// valid shapes all the way through verification, so the decode branches are not
// only shown to produce a struct but to produce one that verifies.
//
// A branch could return a technically-populated MDoc that the verifier then
// rejects — a wrong docType from the MSO being the obvious way — and the table
// above, asserting only on the decoded fields, would not notice.
func TestDecodeIssuedMdocAcceptsEveryShapeTheVerifierThenAccepts(t *testing.T) {
	const docType = "eu.europa.ec.av.1"

	issuer, err := mdoc.NewIssuer()
	require.NoError(t, err)
	holder, err := mdoc.NewHolder()
	require.NoError(t, err)

	issued, err := issuer.Issue(docType, docType, map[string]any{"age_over_18": true}, holder.PublicKey())
	require.NoError(t, err)

	verifier := mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})
	parser := NewMdocCredentialFormatParser(verifier)

	shapes := map[string]any{
		"document":        issued,
		"device response": mdoc.NewDeviceResponse(*issued),
		"issuer signed":   issued.IssuerSigned,
	}

	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			raw := base64.RawURLEncoding.EncodeToString(mustCborMarshal(t, shape))

			parsed, err := parser.ParseAndVerify(raw, "https://test-issuer.example.com", true)
			require.NoError(t, err)
			require.Equal(t, docType, parsed.VerifiableCredentialType)
			require.Equal(t, models.CredentialFormatMsoMdoc, parsed.Format)
		})
	}
}

// newIssuedMdocDocument issues one real mdoc, so the fixtures below are built
// from bytes an issuer actually signed rather than hand-assembled ones: the
// namespace items must stay byte-identical for their digests to match, which a
// re-encoded fixture would not guarantee.
func newIssuedMdocDocument(t *testing.T, docType string) *mdoc.MDoc {
	t.Helper()

	issuer, err := mdoc.NewIssuer()
	require.NoError(t, err)
	holder, err := mdoc.NewHolder()
	require.NoError(t, err)

	issued, err := issuer.Issue(docType, docType, map[string]any{"age_over_18": true}, holder.PublicKey())
	require.NoError(t, err)
	return issued
}

func mustCborMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := cbor.Marshal(value)
	require.NoError(t, err)
	return encoded
}

func TestMdocCredentialFormatParser_CheckBatchUniqueness(t *testing.T) {
	parser := NewMdocCredentialFormatParser(nil)

	thumbprint := "same-thumbprint"
	err := parser.CheckBatchUniqueness([]*ParsedCredential{
		{Mdoc: &ParsedMdoc{DeviceKeyThumbprint: thumbprint}},
		{Mdoc: &ParsedMdoc{DeviceKeyThumbprint: thumbprint}},
	})
	require.Error(t, err)

	other := "different-thumbprint"
	err = parser.CheckBatchUniqueness([]*ParsedCredential{
		{Mdoc: &ParsedMdoc{DeviceKeyThumbprint: thumbprint}},
		{Mdoc: &ParsedMdoc{DeviceKeyThumbprint: other}},
	})
	require.NoError(t, err)
}

// A parsed mdoc's element values have the shapes they will have when read back
// from the database, so the offer screen and the credential list agree. A CBOR
// integer decodes as uint64, which clientmodels.NewAttributeValue does not know
// and rendered as text on the offer screen; after the JSON shaping it is the
// float64 the list also sees.
func TestMdocCredentialFormatParser_NamespacesAreJSONShaped(t *testing.T) {
	issuer, err := mdoc.NewIssuer()
	require.NoError(t, err)
	holder, err := mdoc.NewHolder()
	require.NoError(t, err)
	issued, err := issuer.Issue("eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.pid.1", map[string]any{
		"sex":            1,
		"nationality":    []any{"NL", "BE"},
		"place_of_birth": map[string]any{"country": "NL"},
	}, holder.PublicKey())
	require.NoError(t, err)
	encoded, err := cbor.Marshal(issued)
	require.NoError(t, err)

	parser := NewMdocCredentialFormatParser(mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()}))
	parsed, err := parser.ParseAndVerify(base64.RawURLEncoding.EncodeToString(encoded), "https://issuer.example", true)
	require.NoError(t, err)

	elements := parsed.Mdoc.Namespaces["eu.europa.ec.eudi.pid.1"]
	require.Equal(t, float64(1), elements["sex"], "a CBOR integer is the float64 JSON yields")
	require.Equal(t, []any{"NL", "BE"}, elements["nationality"])
	require.Equal(t, map[string]any{"country": "NL"}, elements["place_of_birth"])

	value := clientmodels.NewAttributeValue(elements["sex"])
	require.Equal(t, clientmodels.AttributeType_Int, value.Type, "the offer screen shows it as a number")
}
