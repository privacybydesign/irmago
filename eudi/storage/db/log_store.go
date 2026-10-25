package db

import (
	"slices"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// EudiLogStore persists and queries activity log entries.
//
// Queries rely on the derived columns (CreatedAtNs, PartyKey, SearchText,
// roles, attribute rows), so callers run the log index pass before querying
// (services.IndexLogs); entries it has not reached yet do not match.
type EudiLogStore interface {
	AddLog(entry *models.EudiLogEntry) error
	// AddLogs adds entries in one transaction, skipping those whose id is
	// already stored, and marks the migration done in the same transaction
	// when migration is not empty.
	AddLogs(entries []*models.EudiLogEntry, migration string) error

	// Query returns the page of entries matching f that follows after,
	// newest first, with their credentials in written order. A nil after
	// starts at the newest entry.
	Query(f LogStoreFilter, after *LogCursor, limit int) ([]*models.EudiLogEntry, error)
	// CountByType counts the entries matching f per type, ignoring f.Types.
	CountByType(f LogStoreFilter) (map[string]int, error)
	// Get returns one entry, or nil when there is none with this id.
	Get(id string) (*models.EudiLogEntry, error)
	// CredentialStats sums up, per card hash, role and confidence, the
	// entries about the given cards.
	CredentialStats(hashes []string) ([]CredentialStatRow, error)
	// PartyStats sums up the entries matching f per party and type.
	PartyStats(f LogStoreFilter) ([]PartyStatRow, error)
	// NewestForParty returns the newest entry matching f with this party.
	NewestForParty(f LogStoreFilter, partyKey string) (*models.EudiLogEntry, error)

	// UpdateCredentialHash points the log credentials of card oldHash at
	// newHash, for when the card's hash is recomputed.
	UpdateCredentialHash(tx *gorm.DB, oldHash, newHash string) error
	// DeleteByCredentialIdPrefixes deletes the entries with a credential whose
	// type starts with one of the prefixes.
	DeleteByCredentialIdPrefixes(prefixes []string) error
	DeleteAll() error

	// NeedingIndex returns up to limit entries whose derived columns are
	// older than version.
	NeedingIndex(version, limit int) ([]*models.EudiLogEntry, error)
	// SaveIndex stores the derived columns of entries (and replaces their
	// attribute rows) in one transaction.
	SaveIndex(entries []*models.EudiLogEntry) error
	// UnhashedCredentials returns the log credentials without a card hash,
	// with the type of their entry.
	UnhashedCredentials() ([]UnhashedCredential, error)
	// SetInferredHashes sets the card hash of log credentials, by their id,
	// as inferred, and marks the migration done, in one transaction.
	SetInferredHashes(hashes map[string]string, migration string) error

	MigrationDone(name string) (bool, error)
	MarkMigrationDone(name string) error
}

// LogStoreFilter is clientmodels.LogFilter in storage terms. See there.
type LogStoreFilter struct {
	Types          []string
	Protocols      []string
	Formats        []string
	Roles          []string
	CredentialHash string
	CredentialId   string
	// ClaimPatternKeys keeps entries with an attribute whose pattern key is
	// one of these, or lies under one of them.
	ClaimPatternKeys []string
	PartyKey         string
	// TextTokens are normalised words that must all occur in SearchText.
	TextTokens  []string
	TextOrTypes []string
	FromNs      *int64
	ToNs        *int64
	// IncludeHidden also matches hidden entries.
	IncludeHidden bool
}

// LogCursor is the position of the last entry of a page.
type LogCursor struct {
	Ns int64
	ID string
}

type CredentialStatRow struct {
	CredentialHash string
	Type           string
	Role           string
	HashConfidence string
	LastNs         int64
	Count          int
}

type PartyStatRow struct {
	PartyKey string
	Type     string
	LastNs   int64
	Count    int
}

type UnhashedCredential struct {
	models.EudiLogCredential
	EntryType   string
	CreatedAtNs int64
}

type eudiLogStore struct {
	db *gorm.DB
}

func NewEudiLogStore(db *gorm.DB) EudiLogStore {
	return &eudiLogStore{db: db}
}

// DB is the database the store works on, for tests that need to set up
// rows the store itself would not write.
func (s *eudiLogStore) DB() *gorm.DB {
	return s.db
}

func (s *eudiLogStore) AddLog(entry *models.EudiLogEntry) error {
	return s.db.Create(entry).Error
}

func (s *eudiLogStore) AddLogs(entries []*models.EudiLogEntry, migration string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var existing []string
		if err := tx.Model(&models.EudiLogEntry{}).Pluck("id", &existing).Error; err != nil {
			return err
		}
		stored := map[string]bool{}
		for _, id := range existing {
			stored[id] = true
		}
		for _, e := range entries {
			if stored[e.ID.String()] {
				continue
			}
			if err := tx.Create(e).Error; err != nil {
				return err
			}
		}
		if migration == "" {
			return nil
		}
		return tx.Save(&models.AppMigration{Name: migration, DoneAt: time.Now()}).Error
	})
}

// entries starts a query over the log entries, aliased e.
func (s *eudiLogStore) entries() *gorm.DB {
	return s.db.Table("eudi_log_entries AS e")
}

// apply narrows q (over e) down to the entries matching f.
func apply(q *gorm.DB, f LogStoreFilter, withTypes bool) *gorm.DB {
	q = q.Where("e.created_at_ns IS NOT NULL")
	if !f.IncludeHidden {
		q = q.Where("COALESCE(e.hidden, ?) = ?", false, false)
	}
	if withTypes && len(f.Types) > 0 {
		q = q.Where("e.type IN ?", f.Types)
	}
	if len(f.Protocols) > 0 {
		q = q.Where("e.protocol IN ?", f.Protocols)
	}
	if f.PartyKey != "" {
		q = q.Where("e.party_key = ?", f.PartyKey)
	}
	if f.FromNs != nil {
		q = q.Where("e.created_at_ns >= ?", *f.FromNs)
	}
	if f.ToNs != nil {
		q = q.Where("e.created_at_ns < ?", *f.ToNs)
	}

	// The credential conditions hold for one and the same credential.
	var conds []string
	var args []any
	if f.CredentialHash != "" {
		conds = append(conds, "c.credential_hash = ?")
		args = append(args, f.CredentialHash)
	}
	if f.CredentialId != "" {
		conds = append(conds, "c.credential_id = ?")
		args = append(args, f.CredentialId)
	}
	if len(f.Roles) > 0 {
		conds = append(conds, "c.role IN ?")
		args = append(args, f.Roles)
	}
	if len(f.Formats) > 0 {
		// Formats is a small JSON array of strings; matching its text keeps
		// this portable across the dialectors the holder database supports.
		var ors []string
		for _, format := range f.Formats {
			ors = append(ors, "CAST(c.formats AS TEXT) LIKE ? ESCAPE '\\'")
			args = append(args, "%"+likeEscape(`"`+format+`"`)+"%")
		}
		conds = append(conds, "("+strings.Join(ors, " OR ")+")")
	}
	if len(f.ClaimPatternKeys) > 0 {
		// A key matches itself and every key under it: ClaimPathKey puts a
		// '|' before each element, so the keys under "|saddress" all start
		// with "|saddress|".
		var ors []string
		for _, key := range f.ClaimPatternKeys {
			ors = append(ors, "a.claim_pattern_key = ? OR a.claim_pattern_key LIKE ? ESCAPE '\\'")
			args = append(args, key, likeEscape(key+"|")+"%")
		}
		conds = append(conds, "EXISTS (SELECT 1 FROM eudi_log_attributes a WHERE a.eudi_log_credential_id = c.id AND ("+strings.Join(ors, " OR ")+"))")
	}
	if len(conds) > 0 {
		q = q.Where("EXISTS (SELECT 1 FROM eudi_log_credentials c WHERE c.eudi_log_entry_id = e.id AND "+strings.Join(conds, " AND ")+")", args...)
	}

	if len(f.TextTokens) > 0 {
		var ands []string
		var textArgs []any
		for _, token := range f.TextTokens {
			ands = append(ands, "e.search_text LIKE ? ESCAPE '\\'")
			textArgs = append(textArgs, "%"+likeEscape(token)+"%")
		}
		text := strings.Join(ands, " AND ")
		if len(f.TextOrTypes) > 0 {
			text = "(" + text + ") OR e.type IN ?"
			textArgs = append(textArgs, f.TextOrTypes)
		}
		q = q.Where("("+text+")", textArgs...)
	}
	return q
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// withCredentials preloads the credentials of entries in written order.
func withCredentials(q *gorm.DB) *gorm.DB {
	return q.Preload("Credentials", func(db *gorm.DB) *gorm.DB {
		return db.Order("position ASC")
	})
}

func (s *eudiLogStore) Query(f LogStoreFilter, after *LogCursor, limit int) ([]*models.EudiLogEntry, error) {
	q := apply(s.entries(), f, true)
	if after != nil {
		q = q.Where("(e.created_at_ns < ? OR (e.created_at_ns = ? AND e.id < ?))", after.Ns, after.Ns, after.ID)
	}
	var rows []struct{ ID string }
	if err := q.Select("e.id AS id").Order("e.created_at_ns DESC").Order("e.id DESC").Limit(limit).Scan(&rows).Error; err != nil {
		return nil, err
	}
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	if len(ids) == 0 {
		return []*models.EudiLogEntry{}, nil
	}
	var entries []*models.EudiLogEntry
	if err := withCredentials(s.db).Where("id IN ?", ids).Find(&entries).Error; err != nil {
		return nil, err
	}
	position := map[string]int{}
	for i, id := range ids {
		position[id] = i
	}
	slices.SortFunc(entries, func(a, b *models.EudiLogEntry) int {
		return position[a.ID.String()] - position[b.ID.String()]
	})
	return entries, nil
}

func (s *eudiLogStore) CountByType(f LogStoreFilter) (map[string]int, error) {
	var rows []struct {
		Type  string
		Count int
	}
	if err := apply(s.entries(), f, false).
		Select("e.type AS type, COUNT(*) AS count").
		// A single column name would be quoted whole, alias included.
		Clauses(clause.GroupBy{Columns: []clause.Column{{Name: "e.type", Raw: true}}}).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Type] = r.Count
	}
	return counts, nil
}

func (s *eudiLogStore) Get(id string) (*models.EudiLogEntry, error) {
	var entries []*models.EudiLogEntry
	if err := withCredentials(s.db).Where("id = ?", id).Limit(1).Find(&entries).Error; err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return entries[0], nil
}

func (s *eudiLogStore) CredentialStats(hashes []string) ([]CredentialStatRow, error) {
	var rows []CredentialStatRow
	if len(hashes) == 0 {
		return rows, nil
	}
	err := s.db.Table("eudi_log_credentials AS c").
		Joins("JOIN eudi_log_entries AS e ON e.id = c.eudi_log_entry_id").
		Where("c.credential_hash IN ?", hashes).
		Where("e.created_at_ns IS NOT NULL").
		Select("c.credential_hash AS credential_hash, e.type AS type, COALESCE(c.role, '') AS role, " +
			"COALESCE(c.hash_confidence, '') AS hash_confidence, MAX(e.created_at_ns) AS last_ns, COUNT(DISTINCT e.id) AS count").
		Group("c.credential_hash, e.type, c.role, c.hash_confidence").
		Scan(&rows).Error
	return rows, err
}

func (s *eudiLogStore) PartyStats(f LogStoreFilter) ([]PartyStatRow, error) {
	var rows []PartyStatRow
	err := apply(s.entries(), f, true).
		Where("e.party_key IS NOT NULL AND e.party_key <> ''").
		Select("e.party_key AS party_key, e.type AS type, MAX(e.created_at_ns) AS last_ns, COUNT(*) AS count").
		Group("e.party_key, e.type").
		Scan(&rows).Error
	return rows, err
}

func (s *eudiLogStore) NewestForParty(f LogStoreFilter, partyKey string) (*models.EudiLogEntry, error) {
	f.PartyKey = partyKey
	entries, err := s.Query(f, nil, 1)
	if err != nil || len(entries) == 0 {
		return nil, err
	}
	return entries[0], nil
}

func (s *eudiLogStore) UpdateCredentialHash(tx *gorm.DB, oldHash, newHash string) error {
	if tx == nil {
		tx = s.db
	}
	return tx.Model(&models.EudiLogCredential{}).
		Where("credential_hash = ?", oldHash).
		Update("credential_hash", newHash).Error
}

func (s *eudiLogStore) DeleteByCredentialIdPrefixes(prefixes []string) error {
	if len(prefixes) == 0 {
		return nil
	}
	var ors []string
	var args []any
	for _, p := range prefixes {
		ors = append(ors, "c.credential_id LIKE ? ESCAPE '\\'")
		args = append(args, likeEscape(p)+"%")
	}
	sub := s.db.Table("eudi_log_credentials AS c").
		Select("c.eudi_log_entry_id").
		Where(strings.Join(ors, " OR "), args...)
	return s.db.Where("id IN (?)", sub).Delete(&models.EudiLogEntry{}).Error
}

func (s *eudiLogStore) DeleteAll() error {
	return s.db.Session(&gorm.Session{AllowGlobalUpdate: true}).
		Delete(&models.EudiLogEntry{}).Error
}

func (s *eudiLogStore) NeedingIndex(version, limit int) ([]*models.EudiLogEntry, error) {
	var entries []*models.EudiLogEntry
	err := s.db.Preload("Credentials").
		Where("index_version IS NULL OR index_version < ?", version).
		Order("created_at ASC").
		Limit(limit).
		Find(&entries).Error
	return entries, err
}

func (s *eudiLogStore) SaveIndex(entries []*models.EudiLogEntry) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, e := range entries {
			if err := tx.Model(&models.EudiLogEntry{}).Where("id = ?", e.ID).Updates(map[string]any{
				"created_at_ns": e.CreatedAtNs,
				"party_key":     e.PartyKey,
				"search_text":   e.SearchText,
				"index_version": e.IndexVersion,
			}).Error; err != nil {
				return err
			}
			if err := tx.Where("eudi_log_entry_id = ?", e.ID).Delete(&models.EudiLogAttribute{}).Error; err != nil {
				return err
			}
			for _, c := range e.Credentials {
				if err := tx.Model(&models.EudiLogCredential{}).Where("id = ?", c.ID).Updates(map[string]any{
					"role":     c.Role,
					"position": c.Position,
				}).Error; err != nil {
					return err
				}
				if len(c.AttributeRows) > 0 {
					if err := tx.Create(&c.AttributeRows).Error; err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

func (s *eudiLogStore) UnhashedCredentials() ([]UnhashedCredential, error) {
	var rows []UnhashedCredential
	err := s.db.Table("eudi_log_credentials AS c").
		Joins("JOIN eudi_log_entries AS e ON e.id = c.eudi_log_entry_id").
		Where("c.credential_hash IS NULL OR c.credential_hash = ''").
		Select("c.*, e.type AS entry_type, COALESCE(e.created_at_ns, 0) AS created_at_ns").
		Scan(&rows).Error
	return rows, err
}

func (s *eudiLogStore) SetInferredHashes(hashes map[string]string, migration string) error {
	inferred := "inferred"
	return s.db.Transaction(func(tx *gorm.DB) error {
		for id, hash := range hashes {
			h := hash
			if err := tx.Model(&models.EudiLogCredential{}).Where("id = ?", id).Updates(map[string]any{
				"credential_hash": &h,
				"hash_confidence": &inferred,
			}).Error; err != nil {
				return err
			}
		}
		if migration == "" {
			return nil
		}
		return tx.Save(&models.AppMigration{Name: migration, DoneAt: time.Now()}).Error
	})
}

func (s *eudiLogStore) MigrationDone(name string) (bool, error) {
	var count int64
	err := s.db.Model(&models.AppMigration{}).Where("name = ?", name).Count(&count).Error
	return count > 0, err
}

func (s *eudiLogStore) MarkMigrationDone(name string) error {
	return s.db.Save(&models.AppMigration{Name: name, DoneAt: time.Now()}).Error
}

// NewAttributeRow is a convenience for building attribute rows.
func NewAttributeRow(entryID, credentialID datatypes.UUID, claimPathKey, claimPatternKey string) models.EudiLogAttribute {
	return models.EudiLogAttribute{
		ID:                  datatypes.NewUUIDv4(),
		EudiLogEntryID:      entryID,
		EudiLogCredentialID: credentialID,
		ClaimPathKey:        claimPathKey,
		ClaimPatternKey:     claimPatternKey,
	}
}
