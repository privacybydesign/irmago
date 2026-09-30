package credman

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/eudi/isomdoc"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

// The matcher parses this database in WebAssembly, inside the platform's
// process, with no way to report a parse failure to anyone. So the tests here
// decode the bytes back into the shape CredentialDatabase.cpp reads, key by key
// and type by type, rather than comparing against a Go round trip: a round trip
// would agree with itself about a structure the matcher cannot read.

// decoded mirrors the matcher's reader: every value is taken at the CBOR type
// the C++ asserts, so a field that changed type fails here instead of on a
// phone.
type decoded struct {
	Protocols   []string `cbor:"protocols"`
	Credentials []struct {
		Title     string   `cbor:"title"`
		Subtitle  string   `cbor:"subtitle"`
		Bitmap    []byte   `cbor:"bitmap"`
		Protocols []string `cbor:"protocols"`
		Mdoc      *struct {
			DocumentId string                          `cbor:"documentId"`
			DocType    string                          `cbor:"docType"`
			Namespaces map[string]map[string][3]string `cbor:"namespaces"`
		} `cbor:"mdoc"`
	} `cbor:"credentials"`
}

func decode(t *testing.T, encoded []byte) decoded {
	t.Helper()
	var db decoded
	require.NoError(t, cbor.Unmarshal(encoded, &db))
	return db
}

// batch builds a stored mdoc with the given hash and elements, labelling each
// declared claim in English so display resolution has something to resolve.
func batch(hash string, elements map[string]any, labelled ...string) *models.MdocBatch {
	cm := metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{{Name: "Proof of Age", Locale: new("en")}},
	}
	for _, element := range labelled {
		cm.Claims = append(cm.Claims, metadata.ClaimsDescription{
			Path:    metadata.ClaimsPathPointer([]any{"eu.europa.ec.av.1", element}),
			Display: []metadata.Display{{Name: "Over " + strings.TrimPrefix(element, "age_over_"), Locale: new("en")}},
		})
	}
	encoded, _ := json.Marshal(cm)

	now := time.Now()
	return &models.MdocBatch{
		DocType:            "eu.europa.ec.av.1",
		CredentialIssuer:   "https://issuer.example",
		Hash:               hash,
		Namespaces:         models.MdocNamespaces{"eu.europa.ec.av.1": elements},
		IssuerDisplay:      datatypes.JSON(`[{"name":"Yivi Issuer","locale":"en"}]`),
		CredentialMetadata: datatypes.JSON(encoded),
		SignedAt:           now,
		ValidFrom:          now,
		ValidUntil:         now.Add(24 * time.Hour),
		BatchSize:          1,
		RemainingCount:     1,
	}
}

func TestBuildProducesTheStructureTheMatcherReads(t *testing.T) {
	encoded, err := Build(
		[]*models.MdocBatch{batch("abc123", map[string]any{"age_over_18": true}, "age_over_18")},
		"en",
		[]string{ProtocolIsoMdoc},
	)
	require.NoError(t, err)

	db := decode(t, encoded)
	require.Equal(t, []string{ProtocolIsoMdoc}, db.Protocols)
	require.Len(t, db.Credentials, 1)

	cred := db.Credentials[0]
	require.Equal(t, "Proof of Age", cred.Title)
	require.Equal(t, "Yivi Issuer", cred.Subtitle)
	require.Nil(t, cred.Protocols, "per-credential protocols must be absent so the top-level list applies")

	require.NotNil(t, cred.Mdoc)
	require.Equal(t, "abc123", cred.Mdoc.DocumentId)
	require.Equal(t, "eu.europa.ec.av.1", cred.Mdoc.DocType)
	require.Equal(t,
		map[string]map[string][3]string{
			"eu.europa.ec.av.1": {"age_over_18": {"Over 18", "", ""}},
		},
		cred.Mdoc.Namespaces)
}

// The matcher reads "bitmap" as a byte string without checking the lookup, so an
// omitted key or a CBOR null is a crash in the platform's WASM runtime, seen by
// the user as a wallet that never appears.
func TestBitmapIsAnEmptyByteStringAndNotNull(t *testing.T) {
	encoded, err := Build(
		[]*models.MdocBatch{batch("abc123", map[string]any{"age_over_18": true})},
		"en",
		[]string{ProtocolIsoMdoc},
	)
	require.NoError(t, err)

	// Decoding into []byte cannot tell null from empty, so assert on the bytes:
	// 0x40 is a zero-length byte string, 0xf6 is null.
	require.Contains(t, string(encoded), "bitmap")
	i := strings.Index(string(encoded), "bitmap")
	require.Equal(t, byte(0x40), encoded[i+len("bitmap")],
		"bitmap must encode as an empty byte string (0x40), not null (0xf6) or absent")

	db := decode(t, encoded)
	require.NotNil(t, db.Credentials[0].Bitmap)
	require.Empty(t, db.Credentials[0].Bitmap)
}

// The Android layer skips re-registration when the digest is unchanged. Go map
// iteration is randomised, so an encoder that did not sort would produce a new
// digest on every call and push the whole database on every credential event.
func TestSameContentsProduceIdenticalBytes(t *testing.T) {
	elements := map[string]any{"age_over_18": true, "age_over_21": true, "age_over_65": false}

	first, err := Build(
		[]*models.MdocBatch{batch("aaa", elements), batch("bbb", elements)},
		"en", []string{ProtocolIsoMdoc})
	require.NoError(t, err)

	for range 20 {
		// Rebuilt from scratch each round so the maps are new allocations with
		// their own iteration order.
		again, err := Build(
			[]*models.MdocBatch{batch("aaa", elements), batch("bbb", elements)},
			"en", []string{ProtocolIsoMdoc})
		require.NoError(t, err)
		require.Equal(t, first, again)
	}
}

func TestCredentialOrderDoesNotDependOnStoreOrder(t *testing.T) {
	elements := map[string]any{"age_over_18": true}

	ascending, err := Build(
		[]*models.MdocBatch{batch("aaa", elements), batch("bbb", elements)},
		"en", []string{ProtocolIsoMdoc})
	require.NoError(t, err)

	descending, err := Build(
		[]*models.MdocBatch{batch("bbb", elements), batch("aaa", elements)},
		"en", []string{ProtocolIsoMdoc})
	require.NoError(t, err)

	require.Equal(t, ascending, descending)

	db := decode(t, ascending)
	require.Equal(t, "aaa", db.Credentials[0].Mdoc.DocumentId)
	require.Equal(t, "bbb", db.Credentials[1].Mdoc.DocumentId)
}

// No element value is registered, and this is the property worth pinning: the
// picker draws these strings before the wallet has asked for a PIN, so a value
// here is readable by anyone holding the unlocked phone. For an age credential
// that is the whole ladder, including the thresholds answered false that this
// wallet refuses to disclose over the wire.
func TestNoElementValueIsRegistered(t *testing.T) {
	encoded, err := Build([]*models.MdocBatch{batch("abc123", map[string]any{
		"age_over_18":  true,
		"age_over_65":  false,
		"age_in_years": float64(42),
		"family_name":  "de Vries",
		"portrait":     strings.Repeat("x", 4096),
		"nested":       map[string]any{"a": 1.0},
	})}, "en", []string{ProtocolIsoMdoc})
	require.NoError(t, err)

	elements := decode(t, encoded).Credentials[0].Mdoc.Namespaces["eu.europa.ec.av.1"]
	require.Len(t, elements, 6, "every element is still listed: the picker says what is asked for")

	for name, triple := range elements {
		require.NotEmpty(t, triple[0], "%s must keep a label, or the picker draws a blank row", name)
		require.Empty(t, triple[1], "%s must not publish its value to the picker", name)
		require.Empty(t, triple[2], "%s must not publish a match value either", name)
	}

	// The false threshold specifically, because it is the one with teeth: proving
	// it is a certain statement that the holder is UNDER that age, which is why
	// isomdoc drops it from a presentation. Registering it would be the same fact
	// on a second channel.
	require.Equal(t, [3]string{"Age Over 65", "", ""}, elements["age_over_65"])

	// Labels still resolve, so the rows remain readable.
	require.Equal(t, "Age Over 18", elements["age_over_18"][0])
	require.Equal(t, "family_name", elements["family_name"][0],
		"nothing names this element, so the identifier is the label")
}

// The matcher emits "<combination> <protocol> <documentId>" as the picker entry
// id and the presentation activity splits it on spaces expecting three parts, so
// a hash with a space routes the user's choice to the wrong credential or to
// none, silently.
func TestHashWithASpaceIsRefused(t *testing.T) {
	_, err := Build(
		[]*models.MdocBatch{batch("has a space", map[string]any{"age_over_18": true})},
		"en", []string{ProtocolIsoMdoc})
	require.ErrorContains(t, err, "contains a space")
}

func TestDatabaseWithoutProtocolsIsRefused(t *testing.T) {
	_, err := Build(
		[]*models.MdocBatch{batch("abc123", map[string]any{"age_over_18": true})},
		"en", nil)
	require.ErrorContains(t, err, "at least one protocol")
}

// An empty wallet still registers: the platform has to be told the wallet holds
// nothing, or it keeps offering what the wallet held before.
func TestEmptyWalletProducesAValidDatabase(t *testing.T) {
	encoded, err := Build(nil, "en", []string{ProtocolIsoMdoc})
	require.NoError(t, err)

	db := decode(t, encoded)
	require.Equal(t, []string{ProtocolIsoMdoc}, db.Protocols)
	require.Empty(t, db.Credentials)
}

func TestTitleAndSubtitleFallBackWhenTheIssuerPublishedNoDisplayText(t *testing.T) {
	bare := &models.MdocBatch{
		DocType:          "eu.europa.ec.av.1",
		CredentialIssuer: "https://issuer.example",
		Hash:             "abc123",
		Namespaces:       models.MdocNamespaces{"eu.europa.ec.av.1": {"age_over_18": true}},
		SignedAt:         time.Now(),
		ValidFrom:        time.Now(),
		ValidUntil:       time.Now().Add(time.Hour),
		BatchSize:        1,
		RemainingCount:   1,
	}

	encoded, err := Build([]*models.MdocBatch{bare}, "en", []string{ProtocolIsoMdoc})
	require.NoError(t, err)

	cred := decode(t, encoded).Credentials[0]
	require.Equal(t, "eu.europa.ec.av.1", cred.Title)
	require.Equal(t, "https://issuer.example", cred.Subtitle)
}

// The picker is drawn by the platform with the wallet not running, so these
// strings are the only localisation the user gets.
func TestDisplayTextFollowsTheLocale(t *testing.T) {
	cm := metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{Name: "Proof of Age", Locale: new("en")},
			{Name: "Leeftijdsbewijs", Locale: new("nl")},
		},
		Claims: []metadata.ClaimsDescription{{
			Path: metadata.ClaimsPathPointer([]any{"eu.europa.ec.av.1", "age_over_18"}),
			Display: []metadata.Display{
				{Name: "Over 18", Locale: new("en")},
				{Name: "Ouder dan 18", Locale: new("nl")},
			},
		}},
	}
	encodedMetadata, _ := json.Marshal(cm)

	now := time.Now()
	b := &models.MdocBatch{
		DocType:            "eu.europa.ec.av.1",
		CredentialIssuer:   "https://issuer.example",
		Hash:               "abc123",
		Namespaces:         models.MdocNamespaces{"eu.europa.ec.av.1": {"age_over_18": true}},
		CredentialMetadata: datatypes.JSON(encodedMetadata),
		SignedAt:           now,
		ValidFrom:          now,
		ValidUntil:         now.Add(time.Hour),
		BatchSize:          1,
		RemainingCount:     1,
	}

	dutch, err := Build([]*models.MdocBatch{b}, "nl", []string{ProtocolIsoMdoc})
	require.NoError(t, err)
	cred := decode(t, dutch).Credentials[0]
	require.Equal(t, "Leeftijdsbewijs", cred.Title)
	require.Equal(t, "Ouder dan 18",
		cred.Mdoc.Namespaces["eu.europa.ec.av.1"]["age_over_18"][0])
}

// The identifier here names an Android registry entry and the one in isomdoc
// names the protocol; they are the same string for the same reason, and a
// divergence would register the wallet for a protocol it never answers.
func TestProtocolIdentifierMatchesTheSessionItRoutesTo(t *testing.T) {
	require.Equal(t, isomdoc.DcApiProtocolIsoMdoc, ProtocolIsoMdoc)
}
