package mdoc

import (
	"crypto/x509"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// ============================================================
// RANDOMIZED DIGEST ORDERING
// ============================================================

// TestClaimOrderingIsRandomized issues the same claim set many times and
// checks two things: every claim is still reachable via its digestID
// regardless of order (shuffling must never lose or duplicate an item),
// and the order actually varies across issuances. The latter is a
// regression guard against silently reverting to a deterministic (e.g.
// alphabetical) order — see the comment on the shuffle in Issue() for why
// a predictable order leaks which undisclosed claims exist relative to a
// disclosed one, for a small/guessable vocabulary like this profile's
// age_over_NN thresholds.
func TestClaimOrderingIsRandomized(t *testing.T) {
	issuer, err := NewTestIssuer()
	require.NoError(t, err, "NewTestIssuer: %v", err)
	holder, _ := NewHolder()

	claims := map[string]any{
		"age_over_18": true,
		"age_over_16": true,
		"age_over_21": false,
		"age_over_65": false,
	}
	namespace := "eu.europa.ec.av.1"
	want := []string{"age_over_16", "age_over_18", "age_over_21", "age_over_65"}

	extractOrder := func(mdoc *MDoc) []string {
		items := mdoc.IssuerSigned.NameSpaces[namespace]
		order := make([]string, len(items))
		for _, tag24item := range items {
			var rawTag cbor.RawTag
			err := cbor.Unmarshal(tag24item.EncodedItem, &rawTag)
			require.NoError(t, err, "unwrap tag24: %v", err)
			var innerBytes []byte
			err = cbor.Unmarshal(rawTag.Content, &innerBytes)
			require.NoError(t, err, "unwrap inner: %v", err)
			var item IssuerSignedItem
			err = cbor.Unmarshal(innerBytes, &item)
			require.NoError(t, err, "decode item: %v", err)
			order[item.DigestID] = item.ElementIdentifier
		}
		return order
	}

	const runs = 30
	seenOrders := make(map[string]bool)
	for i := range runs {
		mdoc, err := issuer.Issue("eu.europa.ec.av.1", namespace, claims, holder.PublicKey())
		require.NoError(t, err, "Issue #%d: %v", i, err)
		order := extractOrder(mdoc)

		// Round-trip correctness: same set of identifiers, regardless of order.
		gotSet := slices.Clone(order)
		slices.Sort(gotSet)
		wantSet := slices.Clone(want)
		slices.Sort(wantSet)
		require.Equal(t, wantSet, gotSet, "run %d: digestID assignment lost/duplicated a claim: got %v, want set %v", i, order, wantSet)

		seenOrders[strings.Join(order, ",")] = true
	}

	// With 4 claims there are 4! = 24 possible orderings; seeing only one
	// order across 30 random issuances would mean the shuffle isn't
	// actually randomizing anything.
	require.GreaterOrEqual(t, len(seenOrders), 2,
		"expected digestID order to vary across issuances (randomized shuffle), but saw only %d distinct order(s) across %d issuances — looks deterministic", len(seenOrders), runs)
}

// ============================================================
// DOC-TYPE-AGNOSTIC ISSUANCE
// ============================================================
//
// Issue() itself enforces no profile-specific claim schema — any
// docType/namespace/claims combination is signed as given. That is
// deliberate: a passport, a driving licence, or an email credential each
// have their own claim shape that Issue() has no business knowing about,
// so profile rules belong above this layer.
//
// Note that the AV profile's attribute restriction (age_over_18 mandatory,
// age_over_NN optional, boolean values — see the Data model section of this
// package's README for what is and is not actually attributable to the
// Blueprint) is currently enforced nowhere in this repo. Earlier revisions asserted it here, in
// tests this one replaced, back when the package carried its own issuance
// path. Nothing regressed by dropping them: irmago ships no production
// mdoc issuer — TestIssuer exists for tests and the AV issuer is external — so
// there is no code path the restriction would guard. If irmago ever issues
// mdocs itself, it belongs in that issuance path, not in Issue().

func TestIssueAcceptsArbitraryDocTypeAndClaims(t *testing.T) {
	issuer, err := NewTestIssuer()
	require.NoError(t, err, "NewTestIssuer: %v", err)
	holder, _ := NewHolder()

	cases := []struct {
		name      string
		docType   string
		namespace string
		claims    map[string]any
	}{
		{
			name:      "age verification",
			docType:   "eu.europa.ec.av.1",
			namespace: "eu.europa.ec.av.1",
			claims:    map[string]any{"age_over_18": true, "age_over_16": true, "age_over_65": false},
		},
		{
			name:      "passport",
			docType:   "eu.europa.ec.pid.1",
			namespace: "eu.europa.ec.pid.1",
			claims:    map[string]any{"family_name": "Smith", "given_name": "Alice", "birth_date": "1990-01-01"},
		},
		{
			name:      "driving licence",
			docType:   "org.iso.18013.5.1.mDL",
			namespace: "org.iso.18013.5.1",
			claims:    map[string]any{"family_name": "Jansen", "driving_privileges": "B"},
		},
		{
			name:      "email",
			docType:   "eu.europa.ec.email.1",
			namespace: "eu.europa.ec.email.1",
			claims:    map[string]any{"email_address": "alice@example.com"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mdoc, err := issuer.Issue(tc.docType, tc.namespace, tc.claims, holder.PublicKey())
			require.NoError(t, err, "Issue: %v", err)
			require.Equal(t, tc.docType, mdoc.DocType, "expected docType %q, got %q", tc.docType, mdoc.DocType)
			require.Len(t, mdoc.IssuerSigned.NameSpaces[tc.namespace], len(tc.claims),
				"expected %d claims in namespace %q, got %d", len(tc.claims), tc.namespace, len(mdoc.IssuerSigned.NameSpaces[tc.namespace]))
		})
	}
}

// TestIssuedValidityTimestampsAreCoarsened pins the AV profile's unlinkability
// requirement on the issuer side: attestations are single-use and issued in
// batches so a holder cannot be followed between relying parties, which a
// per-second validityInfo would undo — each attestation would carry a distinct
// validUntil, correlating exactly what the batch exists to hide. Annex A has the
// provider set hh, mm and ss to the same value on every attestation.
func TestIssuedValidityTimestampsAreCoarsened(t *testing.T) {
	issuer, err := NewTestIssuer()
	require.NoError(t, err, "NewTestIssuer: %v", err)

	// Two attestations of the same batch, issued to different device keys.
	var issued []*MDoc
	for range 2 {
		holder, err := NewHolder()
		require.NoError(t, err, "NewHolder: %v", err)
		doc, err := issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1",
			map[string]any{"age_over_18": true}, holder.PublicKey())
		require.NoError(t, err, "Issue: %v", err)
		issued = append(issued, doc)
	}

	verifier := NewVerifier([]*x509.Certificate{issuer.IACACert()})
	var infos []ValidityInfo
	for _, doc := range issued {
		_, result := verifier.VerifyAllDisclosedNamespaces(doc)
		require.True(t, result.Valid, "verify: %s", result.Error)
		infos = append(infos, result.ValidityInfo)
	}

	for _, info := range infos {
		for name, ts := range map[string]time.Time{
			"signed": info.Signed, "validFrom": info.ValidFrom, "validUntil": info.ValidUntil,
		} {
			h, m, s := ts.UTC().Clock()
			require.True(t, h == 0 && m == 0 && s == 0,
				"%s is %s: hh:mm:ss must be coarsened away, not the issuing wallclock", name, ts.UTC().Format(time.RFC3339))
		}
	}

	// The point of coarsening: two attestations of one batch must be
	// indistinguishable by their timestamps.
	require.True(t, infos[0].Signed.Equal(infos[1].Signed) && infos[0].ValidUntil.Equal(infos[1].ValidUntil),
		"two attestations carry different validity timestamps (%s/%s vs %s/%s); they are linkable",
		infos[0].Signed, infos[0].ValidUntil, infos[1].Signed, infos[1].ValidUntil)
}

// TestIssuedSaltsMeetTheIsoMinimum pins the size and freshness of the per-item
// random value.
//
// The salt is what stops a verifier brute-forcing an undisclosed claim: it holds
// the digest of every element, disclosed or not, and this profile's values are
// booleans, so without a salt hashing "true" and "false" would reveal which one
// the issuer signed. ISO/IEC 18013-5 therefore requires at least 16 bytes.
//
// Nothing downstream would notice a shortened or reused salt — every signature
// and digest would still verify — so it is worth asserting directly.
func TestIssuedSaltsMeetTheIsoMinimum(t *testing.T) {
	issuer, err := NewTestIssuer()
	require.NoError(t, err, "NewTestIssuer: %v", err)
	holder, err := NewHolder()
	require.NoError(t, err, "NewHolder: %v", err)

	const docType = "eu.europa.ec.av.1"
	credential, err := issuer.Issue(docType, docType,
		map[string]any{"age_over_18": true, "age_over_21": true}, holder.PublicKey())
	require.NoError(t, err, "Issue: %v", err)

	items := credential.IssuerSigned.NameSpaces[docType]
	require.Len(t, items, 2, "expected 2 issuer-signed items, got %d", len(items))

	seen := map[string]string{}
	for _, wrapped := range items {
		item, err := decodeTag24Item(wrapped)
		require.NoError(t, err, "decode item: %v", err)
		require.GreaterOrEqual(t, len(item.Random), minSaltLength,
			"%s carries a %d-byte salt; ISO/IEC 18013-5 requires at least %d",
			item.ElementIdentifier, len(item.Random), minSaltLength)
		key := string(item.Random)
		other, reused := seen[key]
		require.False(t, reused, "%s and %s share a salt, so their digests leak whether their values are equal",
			other, item.ElementIdentifier)
		seen[key] = item.ElementIdentifier
	}
}

// decodeTag24Item unwraps one Tag-24 issuer-signed item.
func decodeTag24Item(wrapped Tag24Item) (*IssuerSignedItem, error) {
	var tagged cbor.RawTag
	if err := cbor.Unmarshal(wrapped.EncodedItem, &tagged); err != nil {
		return nil, err
	}
	var inner []byte
	if err := cbor.Unmarshal(tagged.Content, &inner); err != nil {
		return nil, err
	}
	var item IssuerSignedItem
	if err := cbor.Unmarshal(inner, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

// ============================================================
// VALIDITY TIMESTAMPS
// ============================================================

// TestIssuedValidityInfoIsCoarsened pins the timestamp policy: one rule for
// every docType, and the test that fails first if anyone changes the coarsening
// without reading why 9.3.1 step 5 depends on it.
func TestIssuedValidityInfoIsCoarsened(t *testing.T) {
	// A wallclock instant well past midnight, so coarsening is observable rather
	// than coincidental.
	issuedAt, err := time.Parse(time.RFC3339, "2026-09-02T10:03:53Z")
	require.NoError(t, err, "parse issuedAt: %v", err)

	info := issuedValidityInfo(issuedAt)

	got := info.Signed.Format("15:04:05")
	require.Equal(t, "00:00:00", got, "signed should be coarsened to midnight UTC, got %s", got)
	require.True(t, info.ValidFrom.Equal(info.Signed), "validFrom %s should equal signed %s", info.ValidFrom, info.Signed)
	require.True(t, info.ValidUntil.After(info.ValidFrom), "validUntil %s must be later than validFrom %s", info.ValidUntil, info.ValidFrom)
	require.LessOrEqual(t, credentialValidityPeriod, 90*24*time.Hour,
		"validity period %s exceeds the three-month maximum the AV Blueprint recommends", credentialValidityPeriod)
}
