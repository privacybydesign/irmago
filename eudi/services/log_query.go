package services

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

func toStoreFilter(f clientmodels.LogFilter) db.LogStoreFilter {
	sf := db.LogStoreFilter{
		Types:          stringsOf(f.Types),
		Protocols:      stringsOf(f.Protocols),
		Formats:        stringsOf(f.Formats),
		Roles:          stringsOf(f.Roles),
		CredentialHash: f.CredentialHash,
		CredentialId:   f.CredentialId,
		PartyKey:       f.PartyKey,
		TextTokens:     searchTokens(f.Text),
		TextOrTypes:    stringsOf(f.TextOrTypes),
		IncludeHidden:  f.IncludeHidden,
	}
	if len(f.ClaimPath) > 0 {
		sf.ClaimPathKey = clientmodels.ClaimPathKey(f.ClaimPath)
	}
	if f.From != nil {
		ns := f.From.UnixNano()
		sf.FromNs = &ns
	}
	if f.To != nil {
		ns := f.To.UnixNano()
		sf.ToNs = &ns
	}
	return sf
}

func stringsOf[T ~string](values []T) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, len(values))
	for i, v := range values {
		result[i] = string(v)
	}
	return result
}

// encodeLogCursor and decodeLogCursor turn a page position into the opaque
// string the app passes back.
func encodeLogCursor(c db.LogCursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d:%s", c.Ns, c.ID)))
}

func decodeLogCursor(s string) (*db.LogCursor, error) {
	if s == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid log cursor: %w", err)
	}
	ns, id, ok := strings.Cut(string(raw), ":")
	if !ok {
		return nil, fmt.Errorf("invalid log cursor")
	}
	n, err := strconv.ParseInt(ns, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid log cursor: %w", err)
	}
	return &db.LogCursor{Ns: n, ID: id}, nil
}

func (s *eudiLogService) QueryLogs(q clientmodels.LogQuery) (clientmodels.LogPage, error) {
	if err := s.IndexLogs(); err != nil {
		return clientmodels.LogPage{}, err
	}
	limit := q.Limit
	if limit <= 0 {
		limit = clientmodels.DefaultLogPageSize
	}
	after, err := decodeLogCursor(q.Cursor)
	if err != nil {
		return clientmodels.LogPage{}, err
	}
	f := toStoreFilter(q.Filter)

	// One more than asked tells whether there is a next page.
	entries, err := s.store.Query(f, after, limit+1)
	if err != nil {
		return clientmodels.LogPage{}, err
	}
	page := clientmodels.LogPage{}
	if len(entries) > limit {
		entries = entries[:limit]
		last := entries[limit-1]
		page.NextCursor = encodeLogCursor(db.LogCursor{Ns: *last.CreatedAtNs, ID: last.ID.String()})
	}
	if page.Entries, err = s.entriesToLogInfos(entries); err != nil {
		return clientmodels.LogPage{}, err
	}

	if q.WithCounts {
		byType, err := s.store.CountByType(f)
		if err != nil {
			return clientmodels.LogPage{}, err
		}
		counts := &clientmodels.LogCounts{ByType: map[clientmodels.LogType]int{}}
		for t, n := range byType {
			counts.ByType[clientmodels.LogType(t)] = n
			if len(f.Types) == 0 || slices.Contains(f.Types, t) {
				counts.Total += n
			}
		}
		page.Counts = counts
	}
	return page, nil
}

func (s *eudiLogService) GetLog(id string) (*clientmodels.LogInfo, error) {
	if err := s.IndexLogs(); err != nil {
		return nil, err
	}
	entry, err := s.store.Get(id)
	if err != nil || entry == nil {
		return nil, err
	}
	infos, err := s.entriesToLogInfos([]*models.EudiLogEntry{entry})
	if err != nil {
		return nil, err
	}
	return &infos[0], nil
}

func (s *eudiLogService) CredentialActivity(hashes []string) (map[string]clientmodels.CredentialActivity, error) {
	if err := s.IndexLogs(); err != nil {
		return nil, err
	}
	rows, err := s.store.CredentialStats(hashes)
	if err != nil {
		return nil, err
	}
	result := map[string]clientmodels.CredentialActivity{}
	for _, h := range hashes {
		result[h] = clientmodels.CredentialActivity{Hash: h}
	}
	later := func(current *time.Time, ns int64) *time.Time {
		t := time.Unix(0, ns)
		if current == nil || t.After(*current) {
			return &t
		}
		return current
	}
	for _, r := range rows {
		a := result[r.CredentialHash]
		a.Hash = r.CredentialHash
		a.EventCount += r.Count
		role := clientmodels.LogRole(r.Role)
		if role == "" {
			role = roleOf(r.Type, &models.EudiLogCredential{})
		}
		switch role {
		case clientmodels.LogRole_Disclosed:
			a.LastUsed = later(a.LastUsed, r.LastNs)
			if r.HashConfidence == string(clientmodels.HashConfidence_Inferred) {
				a.InferredShareCount += r.Count
			} else {
				a.ShareCount += r.Count
			}
		case clientmodels.LogRole_Issued:
			a.LastReceived = later(a.LastReceived, r.LastNs)
		}
		result[r.CredentialHash] = a
	}
	return result, nil
}

func (s *eudiLogService) ListParties(f clientmodels.LogFilter, limit int) ([]clientmodels.PartySummary, error) {
	if err := s.IndexLogs(); err != nil {
		return nil, err
	}
	sf := toStoreFilter(f)
	rows, err := s.store.PartyStats(sf)
	if err != nil {
		return nil, err
	}

	byKey := map[string]*clientmodels.PartySummary{}
	var summaries []*clientmodels.PartySummary
	for _, r := range rows {
		p, ok := byKey[r.PartyKey]
		if !ok {
			p = &clientmodels.PartySummary{Key: r.PartyKey, ByType: map[clientmodels.LogType]int{}}
			byKey[r.PartyKey] = p
			summaries = append(summaries, p)
		}
		p.Count += r.Count
		p.ByType[clientmodels.LogType(r.Type)] += r.Count
		if t := time.Unix(0, r.LastNs); t.After(p.LastTime) {
			p.LastTime = t
		}
	}
	slices.SortFunc(summaries, func(a, b *clientmodels.PartySummary) int {
		return b.LastTime.Compare(a.LastTime)
	})
	if limit > 0 && len(summaries) > limit {
		summaries = summaries[:limit]
	}

	result := make([]clientmodels.PartySummary, 0, len(summaries))
	for _, p := range summaries {
		newest, err := s.store.NewestForParty(sf, p.Key)
		if err != nil {
			return nil, err
		}
		if newest != nil {
			p.Party = *s.requestorOf(newest)
		}
		result = append(result, *p)
	}
	return result, nil
}

func (s *eudiLogService) UpdateCredentialHash(oldHash, newHash string) error {
	return s.store.UpdateCredentialHash(nil, oldHash, newHash)
}

func (s *eudiLogService) DeleteLogsForCredentialTypes(prefixes []string) error {
	return s.store.DeleteByCredentialIdPrefixes(prefixes)
}

// InferCredentialHashes matches the log credentials that have no card hash
// to the given cards, and marks migration done. A log credential gets a card
// when its type matches and all of its logged values are in the card; when
// more than one card matches, the issuance date breaks the tie. With no
// single match it keeps no hash. Matches are stored as inferred, since a
// disclosure only logs what was shown and two cards can share those values.
//
// Runs once per migration name.
func (s *eudiLogService) InferCredentialHashes(cards []*clientmodels.Credential, migration string) error {
	if done, err := s.store.MigrationDone(migration); err != nil || done {
		return err
	}
	logged, err := s.store.UnhashedCredentials()
	if err != nil {
		return err
	}

	byType := map[string][]*clientmodels.Credential{}
	for _, c := range cards {
		byType[c.CredentialId] = append(byType[c.CredentialId], c)
	}

	hashes := map[string]string{}
	for _, l := range logged {
		if hash, ok := matchLoggedCredential(&l.EudiLogCredential, byType[l.CredentialId]); ok {
			hashes[l.ID.String()] = hash
		}
	}
	return s.store.SetInferredHashes(hashes, migration)
}

func matchLoggedCredential(l *models.EudiLogCredential, cards []*clientmodels.Credential) (string, bool) {
	if len(cards) == 0 {
		return "", false
	}
	var attrs []clientmodels.Attribute
	if err := json.Unmarshal(l.Attributes, &storedValuesOnly{&attrs}); err != nil {
		return "", false
	}
	logged := valuesByPath(attrs)

	var matches []*clientmodels.Credential
	for _, c := range cards {
		values := valuesByPath(c.Attributes)
		all := true
		for path, v := range logged {
			if values[path] != v {
				all = false
				break
			}
		}
		if all {
			matches = append(matches, c)
		}
	}

	distinct := func(cs []*clientmodels.Credential) (string, bool) {
		hash := ""
		for _, c := range cs {
			if hash != "" && c.Hash != hash {
				return "", false
			}
			hash = c.Hash
		}
		return hash, hash != ""
	}
	if hash, ok := distinct(matches); ok {
		return hash, true
	}
	if !l.IssuanceDate.Valid {
		return "", false
	}
	var sameDate []*clientmodels.Credential
	for _, c := range matches {
		if c.IssuanceDate != nil && *c.IssuanceDate == l.IssuanceDate.V.Unix() {
			sameDate = append(sameDate, c)
		}
	}
	return distinct(sameDate)
}

// storedValuesOnly decodes stored attributes for their claim paths and
// values, ignoring the names, which may be stored as translation maps.
type storedValuesOnly struct {
	attrs *[]clientmodels.Attribute
}

func (v *storedValuesOnly) UnmarshalJSON(b []byte) error {
	var stored []storedLogAttribute
	if err := json.Unmarshal(b, &stored); err != nil {
		return err
	}
	for _, s := range stored {
		*v.attrs = append(*v.attrs, clientmodels.Attribute{ClaimPath: s.ClaimPath, Value: s.Value})
	}
	return nil
}

// valuesByPath maps each attribute with a value to a comparable text of it.
func valuesByPath(attrs []clientmodels.Attribute) map[string]string {
	result := map[string]string{}
	for _, a := range attrs {
		if a.Value == nil {
			continue
		}
		b, err := json.Marshal(struct {
			Int    *int64  `json:"i,omitempty"`
			Bool   *bool   `json:"b,omitempty"`
			String *string `json:"s,omitempty"`
			Image  *string `json:"m,omitempty"`
		}{a.Value.Int, a.Value.Bool, a.Value.String, a.Value.Base64Image})
		if err != nil || string(b) == "{}" {
			continue
		}
		result[clientmodels.ClaimPathKey(a.ClaimPath)] = string(b)
	}
	return result
}

// LogMigrationDone reports whether the one-off log migration name has run.
func LogMigrationDone(s storage.Storage, name string) (bool, error) {
	return db.NewEudiLogStore(s.Db()).MigrationDone(name)
}
