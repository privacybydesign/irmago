// mdoc-demo walks one age-verification credential through its whole life —
// issued with two claims, presented with one, verified by a party that trusts
// only the issuer's root — printing what each side can see at every step.
//
// It exists to make selective disclosure observable. The integration tests
// assert the same properties (see internal/sessiontest/eudi_pid_python_issuer_mdoc_test.go),
// but an assertion that a map has one key does not show *why* withholding a
// claim is safe for the verifier and private for the holder. Here the MSO's
// digests are printed next to the disclosed items, so the asymmetry is visible:
// the issuer signed both claims, the holder revealed one, and the verifier can
// still check what it received without learning what it did not.
//
// Everything runs in-process against eudi/credentials/mdoc. No containers, no
// wallet storage, no network — the OpenID4VCI and OpenID4VP plumbing around
// this is what the integration tests cover.
//
// Usage, from the repository root:
//
//	go run ./yivi/cli/eudicli/mdoc-demo
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/yivi/cli/eudicli/internal/mdocdecode"
)

const (
	docType   = "eu.europa.ec.av.1"
	namespace = docType

	// The verifier's OpenID4VP session parameters. deviceAuth signs over these,
	// which is what stops a captured presentation being replayed at another
	// verifier or in another session.
	clientID    = "x509_san_dns:verifier.example.com"
	nonce       = "9f8c1e4b2a7d"
	responseURI = "https://verifier.example.com/response"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nFAILED: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// ── 1. The parties ──────────────────────────────────────────────────
	section("1. Setup")

	issuer, err := mdoc.NewIssuer()
	if err != nil {
		return fmt.Errorf("create issuer: %w", err)
	}
	fmt.Printf("  issuer IACA root : %s\n", issuer.IACACert().Subject.CommonName)
	fmt.Printf("  document signer  : %s\n", issuer.DSCert().Subject.CommonName)

	holder, err := mdoc.NewHolder()
	if err != nil {
		return fmt.Errorf("create holder: %w", err)
	}
	fmt.Printf("  holder device key: generated on the holder's side; the private half never leaves it\n")

	// ── 2. Issuance ─────────────────────────────────────────────────────
	section("2. Issuance — the issuer certifies two claims")

	claims := map[string]any{"age_over_18": true, "age_over_21": true}
	fmt.Printf("  docType   : %s\n", docType)
	fmt.Printf("  namespace : %s\n", namespace)
	fmt.Printf("  claims    : age_over_18=true, age_over_21=true\n")

	credential, err := issuer.Issue(docType, namespace, claims, holder.PublicKey())
	if err != nil {
		return fmt.Errorf("issue: %w", err)
	}

	digests, err := valueDigests(credential)
	if err != nil {
		return fmt.Errorf("read MSO digests: %w", err)
	}
	fmt.Printf("\n  The issuer signs one MSO covering a digest per claim:\n")
	for _, id := range sortedIDs(digests) {
		fmt.Printf("    digestID %d -> %x…\n", id, digests[id][:8])
	}
	fmt.Printf("  %d digests, both inside the signature. Digest IDs are shuffled at issuance,\n", len(digests))
	fmt.Printf("  so their order tells a verifier nothing about which claim is which.\n")
	fmt.Printf("  The credential itself carries %d items, one per claim.\n", len(credential.IssuerSigned.NameSpaces[namespace]))

	// ── 3. The request ──────────────────────────────────────────────────
	section("3. The verifier asks for one claim only")

	fmt.Printf("  requested: age_over_18\n")
	fmt.Printf("  withheld : age_over_21 (the holder has it, the verifier did not ask)\n")

	// ── 4. Selective disclosure ─────────────────────────────────────────
	section("4. The holder discloses exactly what was asked")

	disclosed, err := mdoc.SelectiveDisclose(credential, namespace, []string{"age_over_18"})
	if err != nil {
		return fmt.Errorf("selective disclose: %w", err)
	}
	fmt.Printf("  items on the wire: %d (was %d)\n",
		len(disclosed.IssuerSigned.NameSpaces[namespace]),
		len(credential.IssuerSigned.NameSpaces[namespace]))
	fmt.Printf("  issuerAuth       : reused byte-for-byte — the issuer is not asked to re-sign,\n")
	fmt.Printf("                     and could not be: it is offline by the time this happens.\n")

	// ── 5. Device binding ───────────────────────────────────────────────
	section("5. The holder proves the credential is theirs, for this session")

	transcript := openID4VPTranscript(clientID, nonce, responseURI)
	deviceAuth, err := holder.SignDeviceAuth(docType, transcript)
	if err != nil {
		return fmt.Errorf("sign deviceAuth: %w", err)
	}
	presented, err := mdoc.AttachDeviceSigned(disclosed, deviceAuth)
	if err != nil {
		return fmt.Errorf("attach deviceSigned: %w", err)
	}
	response := mdoc.NewDeviceResponse(*presented)
	fmt.Printf("  deviceAuth signs over: [clientId, nonce, null, responseUri] for this session\n")
	fmt.Printf("    clientId    : %s\n", clientID)
	fmt.Printf("    nonce       : %s\n", nonce)
	fmt.Printf("    responseUri : %s\n", responseURI)

	// ── 6. Verification ─────────────────────────────────────────────────
	section("6. The verifier checks what arrived")

	verifier := mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})
	results, err := verifier.VerifyDeviceResponse(response, namespace, docType, transcript)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	result := results[0]
	if !result.Valid {
		return fmt.Errorf("presentation rejected: %s", result.Error)
	}
	fmt.Printf("  valid            : %t\n", result.Valid)
	fmt.Printf("  deviceAuth valid : %t\n", result.DeviceAuthValid)
	fmt.Printf("  docType          : %s (read from the signed MSO, not the envelope)\n", result.DocType)
	fmt.Printf("  claims received  : %v\n", result.Attributes)

	if err := result.RequireElements("age_over_18"); err != nil {
		return fmt.Errorf("the requested claim is missing: %w", err)
	}
	fmt.Printf("  RequireElements(\"age_over_18\") -> ok\n")

	if err := result.RequireElements("age_over_21"); err == nil {
		return fmt.Errorf("age_over_21 was disclosed but should not have been")
	} else {
		fmt.Printf("  RequireElements(\"age_over_21\") -> %v\n", err)
	}

	fmt.Printf("\n  So the verifier learned age_over_18=true and nothing else. It still holds a\n")
	fmt.Printf("  signed digest of age_over_21 — but a digest over a 16-byte random salt plus the\n")
	fmt.Printf("  value, so guessing \"true\" and hashing it does not confirm anything.\n")

	// ── 7. The bytes themselves ─────────────────────────────────────────
	section("7. What actually went over the wire")

	responseBytes, err := cbor.Marshal(response)
	if err != nil {
		return fmt.Errorf("encode DeviceResponse: %w", err)
	}
	fmt.Printf("  DeviceResponse: %d bytes of CBOR\n", len(responseBytes))
	fmt.Printf("  Inspect any of these yourself with:\n")
	fmt.Printf("    go run ./yivi/cli/eudicli/mdoc-decode.go <hex>\n")

	subsection("issuerAuth — the COSE_Sign1 the issuer produced")
	mdocdecode.Dump(presented.IssuerSigned.IssuerAuth)

	subsection("the disclosed item — Tag-24 wrapped, exactly as hashed")
	// One item survived step 4; its bytes are frozen at issuance, which is why
	// its digest still matches after travelling through the holder untouched.
	mdocdecode.Dump(presented.IssuerSigned.NameSpaces[namespace][0].EncodedItem)

	// ── 8. What the checks actually stop ────────────────────────────────
	section("8. The same response, three ways it can fail")

	if err := showTamperedValueRejected(verifier, issuer, holder); err != nil {
		return err
	}
	if err := showReplayRejected(verifier, presented); err != nil {
		return err
	}
	if err := showUntrustedIssuerRejected(presented, transcript); err != nil {
		return err
	}

	// ── 9. Why one credential is not enough ─────────────────────────────
	if err := showBatchIssuance(issuer); err != nil {
		return err
	}

	section("Done")
	fmt.Printf("  Issued 2 claims, disclosed 1, verified against the issuer's root, rejected a\n")
	fmt.Printf("  tampered value, a replayed session and an untrusted issuer, and showed why the\n")
	fmt.Printf("  same claim is issued many times over.\n")
	return nil
}

// showBatchIssuance issues a batch the way an attestation provider does, and
// shows what makes the batch worth the trouble.
//
// An mdoc is a fixed signed blob, so presenting one twice hands two relying
// parties the same bytes to correlate — the credential is its own tracking
// cookie. The AV profile's answer is one attestation per presentation, which
// only works if the wallet holds a stockpile: Annex A recommends thirty per
// batch. Three are enough to see the shape of it.
func showBatchIssuance(issuer *mdoc.Issuer) error {
	section("9. Why the wallet holds a batch, not one credential")

	const batchSize = 3
	fmt.Printf("  Issuing %d attestations of the same claim (the AV profile recommends 30):\n\n", batchSize)

	type instance struct {
		holder     *mdoc.Holder
		credential *mdoc.MDoc
	}
	batch := make([]instance, 0, batchSize)

	fmt.Printf("    %-4s  %-18s  %-18s  %s\n", "#", "device key", "issuerAuth", "validUntil")
	for i := range batchSize {
		holder, err := mdoc.NewHolder()
		if err != nil {
			return fmt.Errorf("create holder %d: %w", i, err)
		}
		credential, err := issuer.Issue(docType, namespace,
			map[string]any{"age_over_18": true}, holder.PublicKey())
		if err != nil {
			return fmt.Errorf("issue %d: %w", i, err)
		}
		batch = append(batch, instance{holder: holder, credential: credential})

		deviceKeyDER, err := x509.MarshalPKIXPublicKey(holder.PublicKey())
		if err != nil {
			return fmt.Errorf("encode device key %d: %w", i, err)
		}
		validity, err := validUntil(credential)
		if err != nil {
			return fmt.Errorf("read validity %d: %w", i, err)
		}
		fmt.Printf("    %-4d  %-18s  %-18s  %s\n", i,
			fingerprint(deviceKeyDER), fingerprint(credential.IssuerSigned.IssuerAuth), validity)
	}

	fmt.Printf("\n  Every row is a different device key and a different signature, so no two\n")
	fmt.Printf("  presentations share bytes — but validUntil is identical across the batch.\n")
	fmt.Printf("  That is deliberate: at second precision the timestamp would itself be a\n")
	fmt.Printf("  correlator, so the issuer coarsens it to midnight UTC (AV profile, Annex A).\n")

	// Two relying parties, one after the other, each getting a fresh instance.
	subsection("the same holder, two verifiers, two instances")

	verifier := mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})
	for i, party := range []struct{ name, nonce, uri string }{
		{"bar.example.com", "11111111", "https://bar.example.com/response"},
		{"shop.example.net", "22222222", "https://shop.example.net/response"},
	} {
		inst := batch[i]
		disclosed, err := mdoc.SelectiveDisclose(inst.credential, namespace, []string{"age_over_18"})
		if err != nil {
			return fmt.Errorf("disclose to %s: %w", party.name, err)
		}
		transcript := openID4VPTranscript("x509_san_dns:"+party.name, party.nonce, party.uri)
		deviceAuth, err := inst.holder.SignDeviceAuth(docType, transcript)
		if err != nil {
			return fmt.Errorf("sign for %s: %w", party.name, err)
		}
		presented, err := mdoc.AttachDeviceSigned(disclosed, deviceAuth)
		if err != nil {
			return fmt.Errorf("attach for %s: %w", party.name, err)
		}
		results, err := verifier.VerifyDeviceResponse(
			mdoc.NewDeviceResponse(*presented), namespace, docType, transcript)
		if err != nil {
			return fmt.Errorf("verify for %s: %w", party.name, err)
		}
		if !results[0].Valid {
			return fmt.Errorf("%s rejected instance %d: %s", party.name, i, results[0].Error)
		}
		fmt.Printf("    %-17s instance %d  valid=%t  claims=%v  issuerAuth=%s\n",
			party.name, i, results[0].Valid, results[0].Attributes,
			fingerprint(presented.IssuerSigned.IssuerAuth))
	}

	fmt.Printf("\n  Both verifiers are satisfied, and comparing notes tells them nothing: different\n")
	fmt.Printf("  signatures, different device keys, different salts. Reusing one instance would\n")
	fmt.Printf("  have handed them identical bytes — which is why the wallet marks an instance\n")
	fmt.Printf("  used and refuses to spend it twice.\n")
	return nil
}

// validUntil reads the MSO's expiry, to show it is the same across a batch.
func validUntil(credential *mdoc.MDoc) (string, error) {
	mso, err := decodeMSO(credential)
	if err != nil {
		return "", err
	}
	return mso.ValidityInfo.ValidUntil.UTC().Format(time.RFC3339), nil
}

// fingerprint shortens a blob to something eyeballable — enough to see that two
// values differ, not enough to clutter the table.
func fingerprint(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:8])
}

// showTamperedValueRejected re-issues, flips a disclosed value, and shows the
// digest check catching it. The signature still verifies — only the digest of
// the changed item stops matching — which is the point: the issuer signs
// digests, so tampering is caught per claim rather than per document.
func showTamperedValueRejected(verifier *mdoc.Verifier, issuer *mdoc.Issuer, holder *mdoc.Holder) error {
	credential, err := issuer.Issue(docType, namespace, map[string]any{"age_over_18": false}, holder.PublicKey())
	if err != nil {
		return fmt.Errorf("issue for tamper case: %w", err)
	}
	// Swap in an item claiming true, keeping the issuer's own signature.
	forged, err := issuer.Issue(docType, namespace, map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		return fmt.Errorf("issue forged item: %w", err)
	}
	credential.IssuerSigned.NameSpaces[namespace] = forged.IssuerSigned.NameSpaces[namespace]

	result := verifier.Verify(credential, namespace)
	fmt.Printf("  tampered value   : valid=%t  (%s)\n", result.Valid, firstLine(result.Error))
	if result.Valid {
		return fmt.Errorf("a swapped claim value was accepted")
	}
	return nil
}

// showReplayRejected presents an untouched, genuinely signed response against a
// different session's transcript — what an eavesdropper replaying a captured
// presentation would have.
func showReplayRejected(verifier *mdoc.Verifier, presented *mdoc.MDoc) error {
	otherSession := openID4VPTranscript(clientID, "a-different-nonce", responseURI)
	results, err := verifier.VerifyDeviceResponse(mdoc.NewDeviceResponse(*presented), namespace, docType, otherSession)
	if err != nil {
		return fmt.Errorf("verify replay: %w", err)
	}
	fmt.Printf("  replayed session : valid=%t  (%s)\n", results[0].Valid, firstLine(results[0].Error))
	if results[0].Valid {
		return fmt.Errorf("a presentation from another session was accepted")
	}
	return nil
}

// showUntrustedIssuerRejected verifies the same response against a verifier that
// trusts a different root — the chain check runs before any signature or digest
// check, so this fails first and for the right reason.
func showUntrustedIssuerRejected(presented *mdoc.MDoc, transcript mdoc.SessionTranscript) error {
	stranger, err := mdoc.NewIssuer()
	if err != nil {
		return fmt.Errorf("create unrelated issuer: %w", err)
	}
	verifier := mdoc.NewVerifier([]*x509.Certificate{stranger.IACACert()})
	results, err := verifier.VerifyDeviceResponse(mdoc.NewDeviceResponse(*presented), namespace, docType, transcript)
	if err != nil {
		return fmt.Errorf("verify untrusted: %w", err)
	}
	fmt.Printf("  untrusted issuer : valid=%t  (%s)\n", results[0].Valid, firstLine(results[0].Error))
	if results[0].Valid {
		return fmt.Errorf("a credential from an untrusted issuer was accepted")
	}
	return nil
}

// openID4VPTranscript rebuilds the handover an OpenID4VP session produces. The
// wallet's own copy lives unexported in eudi/openid4vp/mdoc_dcql; this mirrors
// it so the demo needs nothing but the mdoc package.
func openID4VPTranscript(clientID, nonce, responseURI string) mdoc.SessionTranscript {
	// The third element is the response encryption key's thumbprint, null here
	// because this demo's response travels unencrypted.
	handoverInfo, err := cbor.Marshal([]any{clientID, nonce, nil, responseURI})
	if err != nil {
		panic(err) // marshalling four strings cannot fail
	}
	digest := sha256.Sum256(handoverInfo)
	return mdoc.SessionTranscript{
		Handover: []any{"OpenID4VPHandover", digest[:]},
	}
}

// mobileSecurityObject is the subset of the MSO this demo reads back. The mdoc
// package has the full type, but not exported, and decoding the couple of fields
// we display keeps the demo honest about where they come from: straight out of
// the signed bytes, with no help from the library that produced them.
type mobileSecurityObject struct {
	ValueDigests map[string]map[uint64][]byte `cbor:"valueDigests"`
	ValidityInfo struct {
		Signed     time.Time `cbor:"signed"`
		ValidFrom  time.Time `cbor:"validFrom"`
		ValidUntil time.Time `cbor:"validUntil"`
	} `cbor:"validityInfo"`
}

// decodeMSO unwraps issuerAuth down to the MSO. It decodes rather than verifies:
// the point is to show what the issuer committed to, and the verification itself
// happens in step 6.
func decodeMSO(credential *mdoc.MDoc) (*mobileSecurityObject, error) {
	// issuerAuth is a COSE_Sign1: [protected, unprotected, payload, signature].
	var coseSign1 []cbor.RawMessage
	if err := cbor.Unmarshal(credential.IssuerSigned.IssuerAuth, &coseSign1); err != nil {
		return nil, fmt.Errorf("decode COSE_Sign1: %w", err)
	}
	if len(coseSign1) != 4 {
		return nil, fmt.Errorf("expected a 4-element COSE_Sign1, got %d", len(coseSign1))
	}

	var payload []byte
	if err := cbor.Unmarshal(coseSign1[2], &payload); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	// The payload is MobileSecurityObjectBytes = #6.24(bstr .cbor MSO).
	var tagged cbor.RawTag
	if err := cbor.Unmarshal(payload, &tagged); err != nil {
		return nil, fmt.Errorf("decode tag-24 wrapper: %w", err)
	}
	var msoBytes []byte
	if err := cbor.Unmarshal(tagged.Content, &msoBytes); err != nil {
		return nil, fmt.Errorf("unwrap tag-24: %w", err)
	}

	var mso mobileSecurityObject
	if err := cbor.Unmarshal(msoBytes, &mso); err != nil {
		return nil, fmt.Errorf("decode MSO: %w", err)
	}
	return &mso, nil
}

// valueDigests pulls the MSO's per-claim digests out of issuerAuth.
func valueDigests(credential *mdoc.MDoc) (map[uint64][]byte, error) {
	mso, err := decodeMSO(credential)
	if err != nil {
		return nil, err
	}
	return mso.ValueDigests[namespace], nil
}

func sortedIDs(digests map[uint64][]byte) []uint64 {
	ids := make([]uint64, 0, len(digests))
	for id := range digests {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func subsection(title string) {
	fmt.Printf("\n  %s\n  %s\n\n", title, strings.Repeat("-", len(title)))
}

func section(title string) {
	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("─", len(title)))
}

func firstLine(s string) string {
	if before, _, ok := strings.Cut(s, "\n"); ok {
		return before
	}
	return s
}
