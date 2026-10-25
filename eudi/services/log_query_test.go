package services

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func emailCred(hash, value string, role clientmodels.LogRole, formats ...clientmodels.CredentialFormat) LogWriteCredential {
	if len(formats) == 0 {
		formats = []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc}
	}
	return LogWriteCredential{
		LogCredential: clientmodels.LogCredential{
			CredentialId: "https://example.com/vct/email",
			Name:         "E-mail",
			Formats:      formats,
			Issuer:       clientmodels.TrustedParty{Id: "https://issuer.example.com", Name: "Issuer"},
			Attributes: []clientmodels.Attribute{{
				ClaimPath:   []any{"email"},
				DisplayName: strPtr("Email address"),
				Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr(value)},
			}},
			Hash: hash,
		},
		Role: role,
	}
}

func queryAll(t *testing.T, svc EudiLogService, f clientmodels.LogFilter, pageSize int) []clientmodels.LogInfo {
	t.Helper()
	var all []clientmodels.LogInfo
	cursor := ""
	for {
		page, err := svc.QueryLogs(clientmodels.LogQuery{Filter: f, Cursor: cursor, Limit: pageSize})
		require.NoError(t, err)
		all = append(all, page.Entries...)
		if page.NextCursor == "" {
			return all
		}
		cursor = page.NextCursor
	}
}

// Entries that share a timestamp all come back once: the cursor carries the
// id, where paging on time alone skipped those at a page boundary.
func TestQueryLogs_TiedTimestampsPageWithoutGaps(t *testing.T) {
	svc := newTestLogService(t)
	at := time.Now()
	for range 7 {
		require.NoError(t, svc.AddLog(LogWrite{Type: clientmodels.LogType_Disclosure, Time: at,
			Requestor: &clientmodels.TrustedParty{Id: "v"}}))
	}

	all := queryAll(t, svc, clientmodels.LogFilter{}, 2)
	require.Len(t, all, 7)
	seen := map[string]bool{}
	for _, e := range all {
		require.False(t, seen[e.ID])
		seen[e.ID] = true
	}
}

// The order follows the moment, not the local clock time it was written in:
// the database stores times as text with their UTC offset, which sorts
// wrong across a DST change.
func TestQueryLogs_OrdersByInstantAcrossUTCOffsets(t *testing.T) {
	svc := newTestLogService(t)
	summer := time.FixedZone("CEST", 2*3600)
	winter := time.FixedZone("CET", 3600)
	older := time.Date(2026, 10, 25, 10, 30, 0, 0, summer) // 08:30Z
	newer := time.Date(2026, 10, 25, 9, 45, 0, 0, winter)  // 08:45Z

	require.NoError(t, svc.AddLog(LogWrite{Type: clientmodels.LogType_Disclosure, Time: older, Requestor: &clientmodels.TrustedParty{Id: "older"}}))
	require.NoError(t, svc.AddLog(LogWrite{Type: clientmodels.LogType_Disclosure, Time: newer, Requestor: &clientmodels.TrustedParty{Id: "newer"}}))

	all := queryAll(t, svc, clientmodels.LogFilter{}, 10)
	require.Len(t, all, 2)
	require.Equal(t, "newer", all[0].DisclosureLog.Verifier.Id)
	require.True(t, all[0].Time.Equal(newer))
}

func TestQueryLogs_Filters(t *testing.T) {
	svc := newTestLogService(t)
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	add := func(minutes int, w LogWrite) {
		w.Time = base.Add(time.Duration(minutes) * time.Minute)
		require.NoError(t, svc.AddLog(w))
	}
	shop := &clientmodels.TrustedParty{Id: "shop", Name: "Café Noir"}
	bank := &clientmodels.TrustedParty{Id: "bank", Name: "Bank"}

	add(1, LogWrite{Type: clientmodels.LogType_Issuance, Protocol: clientmodels.Protocol_OpenID4VCI, Requestor: bank,
		Credentials: []LogWriteCredential{emailCred("card-a", "a@example.com", clientmodels.LogRole_Issued)}})
	add(2, LogWrite{Type: clientmodels.LogType_Disclosure, Protocol: clientmodels.Protocol_OpenID4VP, Requestor: shop,
		Credentials: []LogWriteCredential{emailCred("card-a", "a@example.com", clientmodels.LogRole_Disclosed)}})
	add(3, LogWrite{Type: clientmodels.LogType_Disclosure, Protocol: clientmodels.Protocol_Irma, Requestor: bank,
		Credentials: []LogWriteCredential{emailCred("card-b", "b@example.com", clientmodels.LogRole_Disclosed, clientmodels.Format_Idemix)}})
	add(4, LogWrite{Type: clientmodels.LogType_Signature, Protocol: clientmodels.Protocol_Irma, Requestor: shop, SignedMessage: "I agree to the terms",
		Credentials: []LogWriteCredential{emailCred("card-b", "b@example.com", clientmodels.LogRole_Disclosed, clientmodels.Format_Idemix)}})
	add(5, LogWrite{Type: clientmodels.LogType_Issuance, Protocol: clientmodels.Protocol_Irma, Requestor: bank, Hidden: true,
		Credentials: []LogWriteCredential{emailCred("keyshare", "k", clientmodels.LogRole_Issued)}})
	add(6, LogWrite{Type: clientmodels.LogType_CredentialRemoval,
		Credentials: []LogWriteCredential{emailCred("card-a", "a@example.com", clientmodels.LogRole_Removed)}})

	ids := func(f clientmodels.LogFilter) []clientmodels.LogType {
		var types []clientmodels.LogType
		for _, e := range queryAll(t, svc, f, 2) {
			types = append(types, e.Type)
		}
		return types
	}

	// Hidden entries only on request.
	require.Len(t, ids(clientmodels.LogFilter{}), 5)
	require.Len(t, ids(clientmodels.LogFilter{IncludeHidden: true}), 6)

	// One card's activity, newest first.
	require.Equal(t, []clientmodels.LogType{clientmodels.LogType_CredentialRemoval, clientmodels.LogType_Disclosure, clientmodels.LogType_Issuance},
		ids(clientmodels.LogFilter{CredentialHash: "card-a"}))
	require.Equal(t, []clientmodels.LogType{clientmodels.LogType_Disclosure},
		ids(clientmodels.LogFilter{CredentialHash: "card-a", Roles: []clientmodels.LogRole{clientmodels.LogRole_Disclosed}}))

	require.Len(t, ids(clientmodels.LogFilter{Types: []clientmodels.LogType{clientmodels.LogType_Disclosure, clientmodels.LogType_Signature}}), 3)
	require.Len(t, ids(clientmodels.LogFilter{Protocols: []clientmodels.Protocol{clientmodels.Protocol_Irma}}), 2)
	require.Len(t, ids(clientmodels.LogFilter{Formats: []clientmodels.CredentialFormat{clientmodels.Format_Idemix}}), 2)
	require.Len(t, ids(clientmodels.LogFilter{PartyKey: "shop"}), 2)
	require.Len(t, ids(clientmodels.LogFilter{CredentialId: "https://example.com/vct/email", ClaimPath: []any{"email"}}), 5)
	require.Empty(t, ids(clientmodels.LogFilter{CredentialId: "https://example.com/vct/email", ClaimPath: []any{"phone"}}))

	from, to := base.Add(2*time.Minute), base.Add(4*time.Minute)
	require.Len(t, ids(clientmodels.LogFilter{From: &from, To: &to}), 2)

	// Search ignores case and accents, matches values and signed messages,
	// and needs every word.
	require.Len(t, ids(clientmodels.LogFilter{Text: "cafe"}), 2)
	require.Len(t, ids(clientmodels.LogFilter{Text: "B@EXAMPLE"}), 2)
	require.Len(t, ids(clientmodels.LogFilter{Text: "terms agree"}), 1)
	require.Empty(t, ids(clientmodels.LogFilter{Text: "cafe bank"}))
	// What the app matched in its own type labels widens the search.
	require.Len(t, ids(clientmodels.LogFilter{Text: "terms", TextOrTypes: []clientmodels.LogType{clientmodels.LogType_CredentialRemoval}}), 2)
}

func TestQueryLogs_CountsIgnoreTheTypeFilter(t *testing.T) {
	svc := newTestLogService(t)
	for _, typ := range []clientmodels.LogType{clientmodels.LogType_Disclosure, clientmodels.LogType_Disclosure, clientmodels.LogType_Issuance} {
		require.NoError(t, svc.AddLog(LogWrite{Type: typ, Requestor: &clientmodels.TrustedParty{Id: "p"}}))
	}
	page, err := svc.QueryLogs(clientmodels.LogQuery{
		Filter:     clientmodels.LogFilter{Types: []clientmodels.LogType{clientmodels.LogType_Issuance}},
		WithCounts: true,
	})
	require.NoError(t, err)
	require.Len(t, page.Entries, 1)
	require.Equal(t, 1, page.Counts.Total)
	require.Equal(t, 2, page.Counts.ByType[clientmodels.LogType_Disclosure])
	require.Equal(t, 1, page.Counts.ByType[clientmodels.LogType_Issuance])
}

func TestCredentialActivityAndParties(t *testing.T) {
	svc := newTestLogService(t)
	shop := &clientmodels.TrustedParty{Id: "shop", Name: "Shop"}
	t0 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	require.NoError(t, svc.AddLog(LogWrite{Type: clientmodels.LogType_Issuance, Time: t0, Requestor: &clientmodels.TrustedParty{Id: "issuer"},
		Credentials: []LogWriteCredential{emailCred("card", "a@example.com", clientmodels.LogRole_Issued)}}))
	require.NoError(t, svc.AddLog(LogWrite{Type: clientmodels.LogType_Disclosure, Time: t0.Add(time.Hour), Requestor: shop,
		Credentials: []LogWriteCredential{emailCred("card", "a@example.com", clientmodels.LogRole_Disclosed)}}))
	inferred := emailCred("card", "a@example.com", clientmodels.LogRole_Disclosed)
	inferred.HashConfidence = clientmodels.HashConfidence_Inferred
	require.NoError(t, svc.AddLog(LogWrite{Type: clientmodels.LogType_Disclosure, Time: t0.Add(2 * time.Hour), Requestor: shop,
		Credentials: []LogWriteCredential{inferred}}))

	activity, err := svc.CredentialActivity([]string{"card", "unused"})
	require.NoError(t, err)
	a := activity["card"]
	require.Equal(t, 3, a.EventCount)
	require.Equal(t, 1, a.ShareCount)
	require.Equal(t, 1, a.InferredShareCount)
	require.True(t, a.LastUsed.Equal(t0.Add(2*time.Hour)))
	require.True(t, a.LastReceived.Equal(t0))
	require.Equal(t, clientmodels.CredentialActivity{Hash: "unused"}, activity["unused"])

	parties, err := svc.ListParties(clientmodels.LogFilter{}, 0)
	require.NoError(t, err)
	require.Len(t, parties, 2)
	require.Equal(t, "shop", parties[0].Key)
	require.Equal(t, "Shop", parties[0].Party.Name)
	require.Equal(t, 2, parties[0].Count)
	require.Equal(t, 2, parties[0].ByType[clientmodels.LogType_Disclosure])

	limited, err := svc.ListParties(clientmodels.LogFilter{}, 1)
	require.NoError(t, err)
	require.Len(t, limited, 1)
}

// Multi-language texts are stored as maps: the entry follows the locale and
// is found in every language.
func TestAddLog_StoresTranslationsAndRoles(t *testing.T) {
	svc := newTestLogServiceWithLocale(t, "nl")
	disclosed := emailCred("", "a@example.com", clientmodels.LogRole_Disclosed)
	disclosed.Texts = &LogCredentialTexts{
		Name: clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
		Attributes: map[string]LogAttributeTexts{
			clientmodels.ClaimPathKey([]any{"email"}): {Name: clientmodels.TranslatedString{"en": "Address", "nl": "Adres"}},
		},
	}
	require.NoError(t, svc.AddLog(LogWrite{
		Type:           clientmodels.LogType_Issuance,
		Protocol:       clientmodels.Protocol_Irma,
		Requestor:      &clientmodels.TrustedParty{Id: "r", Name: "Requestor", Verified: true, TrustSource: clientmodels.TrustSource_YiviScheme},
		RequestorNames: clientmodels.TranslatedString{"en": "Town hall", "nl": "Gemeentehuis"},
		Credentials:    []LogWriteCredential{emailCred("issued", "x@example.com", clientmodels.LogRole_Issued), disclosed},
	}))

	logs, err := newestLogs(svc, 10)
	require.NoError(t, err)
	log := logs[0].IssuanceLog
	require.Equal(t, "Gemeentehuis", log.Issuer.Name)
	require.Equal(t, clientmodels.TrustSource_YiviScheme, log.Issuer.TrustSource, "trust details survive")
	require.Len(t, log.Credentials, 1)
	require.Equal(t, "issued", log.Credentials[0].Hash)
	require.Equal(t, clientmodels.HashConfidence_Exact, log.Credentials[0].HashConfidence)
	require.Len(t, log.DisclosedCredentials, 1)
	require.Equal(t, "E-mailadres", log.DisclosedCredentials[0].Name)
	require.Equal(t, "Adres", *log.DisclosedCredentials[0].Attributes[0].DisplayName)

	found := queryAll(t, svc, clientmodels.LogFilter{Text: "town hall"}, 10)
	require.Len(t, found, 1, "the English name is searchable while the locale is Dutch")
}

// Writing an entry twice under the same id stores it once, so an
// interrupted migration can run again.
func TestAddLogs_SkipsStoredIds(t *testing.T) {
	svc := newTestLogServiceWithLocale(t, "en")
	id := datatypes.NewUUIDv4()
	w := LogWrite{ID: id, Type: clientmodels.LogType_Disclosure, Requestor: &clientmodels.TrustedParty{Id: "v"},
		Credentials: []LogWriteCredential{emailCred("", "a@example.com", clientmodels.LogRole_Disclosed)}}
	require.NoError(t, svc.AddLogs([]LogWrite{w}, ""))
	require.NoError(t, svc.AddLogs([]LogWrite{w}, "test-migration"))

	logs, err := newestLogs(svc, 10)
	require.NoError(t, err)
	require.Len(t, logs, 1)
	done, err := svc.store.MigrationDone("test-migration")
	require.NoError(t, err)
	require.True(t, done)
}

func TestInferCredentialHashes(t *testing.T) {
	svc := newTestLogServiceWithLocale(t, "en")
	signed := int64(1_700_000_000)
	other := signed + 86400
	withDate := func(c LogWriteCredential, date int64) LogWriteCredential {
		c.IssuanceDate = &date
		return c
	}
	for _, c := range []LogWriteCredential{
		emailCred("", "only@example.com", clientmodels.LogRole_Disclosed),
		withDate(emailCred("", "twice@example.com", clientmodels.LogRole_Disclosed), other),
		emailCred("", "twice@example.com", clientmodels.LogRole_Disclosed),
		emailCred("", "gone@example.com", clientmodels.LogRole_Disclosed),
	} {
		require.NoError(t, svc.AddLog(LogWrite{Type: clientmodels.LogType_Disclosure, Requestor: &clientmodels.TrustedParty{Id: "v"},
			Credentials: []LogWriteCredential{c}}))
	}

	card := func(hash, value string, date int64) *clientmodels.Credential {
		return &clientmodels.Credential{
			CredentialId: "https://example.com/vct/email",
			Hash:         hash,
			IssuanceDate: &date,
			Attributes: []clientmodels.Attribute{{ClaimPath: []any{"email"},
				Value: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr(value)}}},
		}
	}
	cards := []*clientmodels.Credential{
		card("only", "only@example.com", signed),
		card("twice-1", "twice@example.com", signed),
		card("twice-2", "twice@example.com", other),
	}
	require.NoError(t, svc.InferCredentialHashes(cards, "backfill"))

	hashOf := func(value string) []string {
		var hashes []string
		for _, e := range queryAll(t, svc, clientmodels.LogFilter{Text: value}, 10) {
			c := e.DisclosureLog.Credentials[0]
			if c.Hash != "" {
				require.Equal(t, clientmodels.HashConfidence_Inferred, c.HashConfidence)
			}
			hashes = append(hashes, c.Hash)
		}
		return hashes
	}
	require.Equal(t, []string{"only"}, hashOf("only@example.com"))
	// Two cards share the value: the issuance date tells them apart, and
	// without one the entry stays unmatched.
	require.ElementsMatch(t, []string{"twice-2", ""}, hashOf("twice@example.com"))
	require.Equal(t, []string{""}, hashOf("gone@example.com"))

	// It runs once.
	require.NoError(t, svc.AddLog(LogWrite{Type: clientmodels.LogType_Disclosure, Requestor: &clientmodels.TrustedParty{Id: "v"},
		Credentials: []LogWriteCredential{emailCred("", "only@example.com", clientmodels.LogRole_Disclosed)}}))
	require.NoError(t, svc.InferCredentialHashes(cards, "backfill"))
	require.ElementsMatch(t, []string{"only", ""}, hashOf("only@example.com"))
}

// Entries written before the index columns existed are indexed on the first
// query, so they page, filter and search like new ones.
func TestQueryLogs_IndexesOlderEntries(t *testing.T) {
	svc := newTestLogServiceWithLocale(t, "en")
	require.NoError(t, svc.store.AddLog(&models.EudiLogEntry{
		ID:            datatypes.NewUUIDv4(),
		Type:          string(clientmodels.LogType_Issuance),
		Protocol:      string(clientmodels.Protocol_OpenID4VCI),
		CreatedAt:     time.Now(),
		RequestorId:   "https://issuer.example.com",
		RequestorName: []byte(`{"en":"Old Issuer","nl":"Oude Uitgever"}`),
		Credentials: []models.EudiLogCredential{{
			ID:           datatypes.NewUUIDv4(),
			CredentialId: "https://example.com/vct/legacy",
			Formats:      []byte(`["dc+sd-jwt"]`),
			Name:         []byte(`"Legacy"`),
			Attributes:   []byte(`[{"claim_path":["email"],"value":{"type":"string","string":"old@example.com"}}]`),
		}},
	}))

	require.Len(t, queryAll(t, svc, clientmodels.LogFilter{Text: "uitgever"}, 10), 1)
	require.Len(t, queryAll(t, svc, clientmodels.LogFilter{PartyKey: "https://issuer.example.com"}, 10), 1)
	require.Len(t, queryAll(t, svc, clientmodels.LogFilter{
		CredentialId: "https://example.com/vct/legacy", ClaimPath: []any{"email"}, Roles: []clientmodels.LogRole{clientmodels.LogRole_Issued},
	}, 10), 1)
}

func nestedCred(paths ...[]any) LogWriteCredential {
	attrs := make([]clientmodels.Attribute, len(paths))
	for i, p := range paths {
		attrs[i] = clientmodels.Attribute{ClaimPath: p, Value: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("x")}}
	}
	return LogWriteCredential{
		LogCredential: clientmodels.LogCredential{
			CredentialId: "https://example.com/vct/pid",
			Name:         "PID",
			Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
			Issuer:       clientmodels.TrustedParty{Id: "https://pid.example.com"},
			Attributes:   attrs,
			Hash:         "pid",
		},
		Role: clientmodels.LogRole_Disclosed,
	}
}

// A claim path in a filter names an attribute and everything under it, and
// array positions do not matter: groups, lists of values and fields of list
// items are all one kind of question.
func TestQueryLogs_NestedClaimPaths(t *testing.T) {
	svc := newTestLogService(t)
	add := func(who string, c LogWriteCredential) {
		require.NoError(t, svc.AddLog(LogWrite{Type: clientmodels.LogType_Disclosure, Requestor: &clientmodels.TrustedParty{Id: who}, Credentials: []LogWriteCredential{c}}))
	}
	add("rent", nestedCred([]any{"given_name"}, []any{"address", "street"}, []any{"address", "locality"}))
	add("job", nestedCred([]any{"degrees", 0, "name"}, []any{"degrees", 1, "name"}, []any{"degrees", 0, "institution"}))
	add("travel", nestedCred([]any{"nationalities", 0}, []any{"nationalities", 1}))
	add("post", nestedCred([]any{"address_line"}))

	who := func(paths ...[]any) []string {
		var ids []string
		for _, e := range queryAll(t, svc, clientmodels.LogFilter{CredentialHash: "pid", ClaimPaths: paths}, 10) {
			ids = append(ids, e.DisclosureLog.Verifier.Id)
		}
		return ids
	}

	// A group matches every field in it, and not a sibling that only
	// starts with the same letters.
	require.Equal(t, []string{"rent"}, who([]any{"address"}))
	require.Equal(t, []string{"rent"}, who([]any{"address", "street"}))
	require.Empty(t, who([]any{"address", "postal_code"}))
	// A field of any list item, with or without a position.
	require.Equal(t, []string{"job"}, who([]any{"degrees", nil, "name"}))
	require.Equal(t, []string{"job"}, who([]any{"degrees", 1, "name"}))
	require.Equal(t, []string{"job"}, who([]any{"degrees"}))
	// Any item of a list of values.
	require.Equal(t, []string{"travel"}, who([]any{"nationalities", nil}))
	require.Equal(t, []string{"travel"}, who([]any{"nationalities"}))
	// More paths: any of them.
	require.ElementsMatch(t, []string{"rent", "travel"}, who([]any{"address", "street"}, []any{"nationalities"}))
	require.ElementsMatch(t, []string{"rent", "post"}, who([]any{"given_name"}, []any{"address_line"}))

	// The single path still works.
	single := queryAll(t, svc, clientmodels.LogFilter{CredentialHash: "pid", ClaimPath: []any{"degrees", nil, "institution"}}, 10)
	require.Len(t, single, 1)

	// So does "who has seen it".
	parties, err := svc.ListParties(clientmodels.LogFilter{CredentialHash: "pid", ClaimPaths: [][]any{{"address"}, {"degrees"}}}, 0)
	require.NoError(t, err)
	require.Len(t, parties, 2)
}

// Entries indexed before attribute rows had a pattern key are indexed again
// on the next query, so their list fields can be found.
func TestQueryLogs_ReindexesForPatternKeys(t *testing.T) {
	svc := newTestLogServiceWithLocale(t, "en")
	require.NoError(t, svc.AddLog(LogWrite{Type: clientmodels.LogType_Disclosure, Requestor: &clientmodels.TrustedParty{Id: "job"},
		Credentials: []LogWriteCredential{nestedCred([]any{"degrees", 0, "name"})}}))

	// Make it look like the version 1 index wrote it.
	db := svc.store.(interface{ DB() *gorm.DB }).DB()
	require.NoError(t, db.Exec("UPDATE eudi_log_attributes SET claim_pattern_key = ''").Error)
	require.NoError(t, db.Exec("UPDATE eudi_log_entries SET index_version = 1").Error)

	found := queryAll(t, svc, clientmodels.LogFilter{CredentialHash: "pid", ClaimPaths: [][]any{{"degrees", nil, "name"}}}, 10)
	require.Len(t, found, 1)
}
