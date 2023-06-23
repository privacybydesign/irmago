package irma

import (
	"io"
	"sort"
	"sync"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/revocation"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type (
	revocationUpdateHead struct {
		SignedAccumulator *revocation.SignedAccumulator
		LatestUpdateEvent *revocation.Event
	}

	revocationRecordStorage interface {
		io.Closer

		// Storing accumulator updates:

		// Exists returns whether the record storage contains a revocation state for the given credential type and public key counter.
		Exists(id CredentialTypeIdentifier, pkCounter uint) (bool, error)
		// Events returns the revocation events for the given credential type, public key counter and event index range.
		// It returns an error if the requested range is not (fully) present in storage.
		Events(id CredentialTypeIdentifier, pkCounter uint, from, to uint64) ([]*revocation.Event, error)
		// LatestAccumulatorUpdates returns revocation update instances for the given credential type and (optionally) public key
		// containing the latest signed accumulator state, and the latest revocation events. The Events slice contains the revocation
		// events in ascending order, and the signed accumulator is based on to the last revocation event in the Events slice.
		// The length of the Events slice can be limited using the limit parameter. A limit is applied at the beginning of the slice,
		// i.e. if the latest accumulator signs event 5 and the limit is 3, then the Events slice will contain the events 3, 4 and 5.
		// If limit is set to 0, then all revocation events are being returned.
		LatestAccumulatorUpdates(id CredentialTypeIdentifier, pkCounter *uint, limit int) (map[uint]*revocation.Update, error)
		// AppendAccumulatorUpdate allows the caller to append an update to the revocation storage based on its current state.
		// The handler function gives the current state of the accumulator and the latest revocation event being stored (the),
		// and the caller can then determine how the storage should be updated. The returned updates (one per public key)
		// will be stored. If an update is omitted for a public key, then no changes are being made. If an update is given
		// for a new public key, a new accumulator record will be created for this.
		// We assume that the given revocation updates are valid, do nicely align with the current revocation state and
		// do not contain events that were stored already. It's the responsibility of the caller to validate this.
		AppendAccumulatorUpdate(id CredentialTypeIdentifier, handler func(heads map[uint]revocationUpdateHead) (map[uint]*revocation.Update, error)) error

		// Storing ssuance records:

		// AddIssuanceRecord adds the given issuance record to the revocation storage.
		AddIssuanceRecord(*IssuanceRecord) error
		// IssuanceRecords returns all issuance records matching the given credential type, revocation key and issuance time.
		// If the given issuance time is zero, then the issuance time is being ignored as condition.
		IssuanceRecords(id CredentialTypeIdentifier, key string, issued time.Time) ([]*IssuanceRecord, error)
		// UpdateIssuanceRecord allows the caller to update all issuance records matching the given credential type, revocation key and issuance time.
		UpdateIssuanceRecord(id CredentialTypeIdentifier, key string, issued time.Time, handler func([]*IssuanceRecord) error) error
		// DeleteExpiredIssuanceRecords deletes all issuance records for which ValidUntil has passed the current time.
		DeleteExpiredIssuanceRecords() error
	}

	// sqlRevStorage is a wrapper around gorm, storing any record type in a SQL database,
	// for use by revocation servers.
	sqlRevStorage struct {
		gorm *gorm.DB
	}

	sqlTraceLogger struct{}

	// memRevStorage is a much simpler in-memory database, suitable only for storing update messages.
	memRevStorage struct {
		mutex      sync.RWMutex
		pkCounters map[CredentialTypeIdentifier][]uint
		accs       map[memRecordKey]*revocation.SignedAccumulator
		events     map[memRecordKey][]*revocation.Event
	}

	memRecordKey struct {
		id        CredentialTypeIdentifier
		pkcounter uint
	}
)

func newSQLStorage(debug bool, dbtype, connstr string) (sqlRevStorage, error) {
	var dialector gorm.Dialector
	switch dbtype {
	case "postgres":
		dialector = postgres.Open(connstr)
	case "mysql":
		dialector = mysql.Open(connstr)
	default:
		return sqlRevStorage{}, errors.New("unsupported database type")
	}

	conf := &gorm.Config{}
	if debug {
		conf.Logger = logger.New(sqlTraceLogger{}, logger.Config{LogLevel: logger.Info})
	}

	g, err := gorm.Open(dialector, conf)
	if err != nil {
		return sqlRevStorage{}, err
	}

	// Ensure that the database is correctly initialized for revocation.
	if g.AutoMigrate((*EventRecord)(nil)); g.Error != nil {
		return sqlRevStorage{}, g.Error
	}
	if g.AutoMigrate((*AccumulatorRecord)(nil)); g.Error != nil {
		return sqlRevStorage{}, g.Error
	}
	if g.AutoMigrate((*IssuanceRecord)(nil)); g.Error != nil {
		return sqlRevStorage{}, g.Error
	}

	return sqlRevStorage{gorm: g}, nil
}

// Close implements revocationRecordStorage and io.Closer interface.
func (s sqlRevStorage) Close() error {
	if s.gorm == nil {
		return nil
	}
	Logger.Debug("closing revocation sql database connection")
	db, err := s.gorm.DB()
	if err != nil {
		return err
	}
	return db.Close()
}

// Exists implements revocationRecordStorage interface.
func (s sqlRevStorage) Exists(id CredentialTypeIdentifier, pkCounter uint) (bool, error) {
	var c int64
	err := s.gorm.Model((*AccumulatorRecord)(nil)).Where(map[string]interface{}{"cred_type": id, "pk_counter": pkCounter}).Count(&c).Error
	return c > 0, err
}

// Events implements revocationRecordStorage interface.
func (s sqlRevStorage) Events(id CredentialTypeIdentifier, pkCounter uint, from, to uint64) ([]*revocation.Event, error) {
	var records []*EventRecord
	if err := s.gorm.Find(&records,
		"cred_type = ? and pk_counter = ? and eventindex >= ? and eventindex < ?",
		id, pkCounter, from, to,
	).Error; err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, ErrRevocationStateNotFound
	}

	var events []*revocation.Event
	for _, r := range records {
		events = append(events, r.Event())
	}

	return events, nil
}

// LatestAccumulatorUpdates implements revocationRecordStorage interface.
func (s sqlRevStorage) LatestAccumulatorUpdates(id CredentialTypeIdentifier, pkCounter *uint, limit int) (map[uint]*revocation.Update, error) {
	accsMap := make(map[uint]*AccumulatorRecord)
	eventsMap := make(map[uint][]*EventRecord)
	if err := s.gorm.Transaction(func(tx *gorm.DB) error {
		// Find all accumulators for the given credential type.
		var accs []*AccumulatorRecord
		where := map[string]interface{}{"cred_type": id}
		// pkCounter is optional, so if it is specified we add it to the query.
		if pkCounter != nil {
			where["pk_counter"] = *pkCounter
		}
		if err := tx.Find(&accs, where).Error; err != nil {
			return err
		}

		// For every accumulator we find the corresponding revocation events.
		for _, acc := range accs {
			accsMap[*acc.PKCounter] = acc

			// Look for eventindex in decending order, such that the limit will be applied on the lower side.
			// The newUpdates function will reverse it to an ascending order.
			var events []*EventRecord
			query := tx.Where("cred_type = ?", id).Where("pk_counter = ?", acc.PKCounter).Order("eventindex DESC")
			if limit > 0 {
				query = query.Limit(limit)
			}
			if err := query.Find(&events).Error; err != nil {
				return err
			}
			eventsMap[*acc.PKCounter] = events
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return newUpdates(accsMap, eventsMap), nil
}

// newUpdates composes a set of revocation updates using the given accumulator and event records.
// It ensures that the revocation events are being ordered on eventindex in ascending order.
func newUpdates(recordsMap map[uint]*AccumulatorRecord, eventsMap map[uint][]*EventRecord) map[uint]*revocation.Update {
	updates := make(map[uint]*revocation.Update, len(recordsMap))
	for pkCounter, r := range recordsMap {
		updates[pkCounter] = &revocation.Update{SignedAccumulator: r.SignedAccumulator()}
	}
	for pkCounter, events := range eventsMap {
		update := updates[pkCounter]
		if update == nil {
			continue
		}
		for _, e := range events {
			update.Events = append(update.Events, e.Event())
		}
	}
	for _, update := range updates {
		sort.Slice(update.Events, func(i, j int) bool {
			return update.Events[i].Index < update.Events[j].Index
		})
	}
	return updates
}

// AppendAccumulatorUpdate implements revocationRecordStorage interface.
func (s sqlRevStorage) AppendAccumulatorUpdate(
	id CredentialTypeIdentifier,
	handler func(heads map[uint]revocationUpdateHead) (map[uint]*revocation.Update, error),
) error {
	return s.gorm.Transaction(func(tx *gorm.DB) error {
		// Retrieve the current accumulator state for every public key of the credential and lock the rows for update.
		var accs []*AccumulatorRecord
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Find(&accs, map[string]interface{}{"cred_type": id}).Error; err != nil {
			return err
		}

		// Accumulators always relate to the latest revocation event of its type. We retrieve those too and combine them in revocationUpdateHead instances.
		heads := make(map[uint]revocationUpdateHead, len(accs))
		for _, acc := range accs {
			var event *EventRecord
			if err := tx.Last(&event, map[string]interface{}{"cred_type": id, "pk_counter": *acc.PKCounter}).Error; err != nil {
				return err
			}
			heads[*acc.PKCounter] = revocationUpdateHead{acc.SignedAccumulator(), event.Event()}
		}

		// Call the handler.
		updates, err := handler(heads)
		if err != nil {
			return err
		}

		// Save the updates that the handler returned.
		for pkCounter, update := range updates {
			for _, event := range update.Events {
				eventRecord := new(EventRecord).Convert(id, pkCounter, event)
				// Use Create such that we cannot accidentally overwrite existing events.
				if err := tx.Create(eventRecord).Error; err != nil {
					return err
				}
			}
			accRecord := new(AccumulatorRecord).Convert(id, update.SignedAccumulator)
			if err := tx.Save(accRecord).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// AddIssuanceRecord implements revocationRecordStorage interface.
func (s sqlRevStorage) AddIssuanceRecord(r *IssuanceRecord) error {
	return s.gorm.Create(r).Error
}

// IssuanceRecord implements revocationRecordStorage interface.
func (s sqlRevStorage) IssuanceRecords(id CredentialTypeIdentifier, key string, issued time.Time) ([]*IssuanceRecord, error) {
	return txIssuanceRecords(s.gorm, id, key, issued)
}

// UpdateIssuanceRecord implements revocationRecordStorage interface.
func (s sqlRevStorage) UpdateIssuanceRecord(id CredentialTypeIdentifier, key string, issued time.Time, handler func([]*IssuanceRecord) error) error {
	return s.gorm.Transaction(func(tx *gorm.DB) error {
		records, err := txIssuanceRecords(tx, id, key, issued)
		if err != nil {
			return err
		}

		handler(records)

		for _, r := range records {
			if err := tx.Save(r).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteExpiredIssuanceRecords implements revocationRecordStorage interface.
func (s sqlRevStorage) DeleteExpiredIssuanceRecords() error {
	return s.gorm.Delete(IssuanceRecord{}, "valid_until < ?", time.Now().UnixNano()).Error
}

// txIssuanceRecords returns all issuance records matching the given credential type, revocation key and issuance time within
// the given GORM database transaction. If the given issuance time is zero, then the issuance time is being ignored as condition.
func txIssuanceRecords(tx *gorm.DB, id CredentialTypeIdentifier, key string, issued time.Time) ([]*IssuanceRecord, error) {
	where := map[string]interface{}{"cred_type": id, "revocationkey": key, "revoked_at": 0}
	if !issued.IsZero() {
		where["issued"] = issued.UnixNano()
	}

	var r []*IssuanceRecord
	if err := tx.Find(&r, where).Error; err != nil {
		return nil, err
	}
	if len(r) == 0 {
		return nil, ErrUnknownRevocationKey
	}
	return r, nil
}

// Printf implements the gorm.io/gorm/logger Writer interface.
func (l sqlTraceLogger) Printf(format string, args ...interface{}) {
	Logger.Tracef(format, args...)
}

func newMemStorage() *memRevStorage {
	return &memRevStorage{
		pkCounters: make(map[CredentialTypeIdentifier][]uint),
		accs:       make(map[memRecordKey]*revocation.SignedAccumulator),
		events:     make(map[memRecordKey][]*revocation.Event),
	}
}

// Close implements revocationRecordStorage and io.Closer interface.
func (m *memRevStorage) Close() error {
	return nil
}

// Exists implements revocationRecordStorage interface.
func (m *memRevStorage) Exists(id CredentialTypeIdentifier, pkCounter uint) (bool, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	_, ok := m.accs[memRecordKey{id, pkCounter}]
	return ok, nil
}

// Events implements revocationRecordStorage interface.
func (m *memRevStorage) Events(id CredentialTypeIdentifier, pkCounter uint, from, to uint64) ([]*revocation.Event, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	events := m.events[memRecordKey{id, pkCounter}]
	if len(events) == 0 {
		return nil, ErrRevocationStateNotFound
	}

	// The first revocation event in storage might not have eventindex 0.
	startIndex := int(from - events[0].Index)
	endIndex := int(to - events[0].Index)
	if startIndex < 0 || startIndex >= endIndex || endIndex > len(events) {
		return nil, errors.New("invalid range")
	}

	return events[startIndex:endIndex], nil
}

// LatestAccumulatorUpdates implements revocationRecordStorage interface.
func (m *memRevStorage) LatestAccumulatorUpdates(id CredentialTypeIdentifier, pkCounter *uint, limit int) (map[uint]*revocation.Update, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Get the pkCounters to find updates for.
	pkCounters, ok := m.pkCounters[id]
	if !ok {
		return nil, ErrRevocationStateNotFound
	}
	if pkCounter != nil {
		pkCounters = []uint{*pkCounter}
	}

	updatesMap := make(map[uint]*revocation.Update)
	for _, pkCounter := range pkCounters {
		acc, ok := m.accs[memRecordKey{id, pkCounter}]
		if !ok {
			return nil, ErrRevocationStateNotFound
		}

		events, ok := m.events[memRecordKey{id, pkCounter}]
		if !ok {
			return nil, ErrRevocationStateNotFound
		}
		offset := limit
		if limit == 0 {
			offset = len(events)
		}
		if offset > len(events) {
			offset = len(events)
		}
		updatesMap[pkCounter] = &revocation.Update{
			SignedAccumulator: acc,
			Events:            events[len(events)-offset:],
		}
	}
	return updatesMap, nil
}

// AppendAccumulatorUpdate implements revocationRecordStorage interface.
func (m *memRevStorage) AppendAccumulatorUpdate(
	id CredentialTypeIdentifier,
	handler func(heads map[uint]revocationUpdateHead) (map[uint]*revocation.Update, error),
) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	pkCounters := m.pkCounters[id]
	heads := make(map[uint]revocationUpdateHead, len(pkCounters))

	// Get the accumulator and the latest revocation event for every public key.
	for _, pkCounter := range pkCounters {
		recordKey := memRecordKey{id, pkCounter}
		events := m.events[recordKey]
		heads[pkCounter] = revocationUpdateHead{
			m.accs[recordKey],
			events[len(events)-1],
		}
	}

	// Call handler.
	updates, err := handler(heads)
	if err != nil {
		return err
	}

	// Store the updates that the handler returned.
	for pkCounter, update := range updates {
		found := false
		for _, counter := range pkCounters {
			if counter == pkCounter {
				found = true
			}
		}
		if !found {
			m.pkCounters[id] = append(m.pkCounters[id], pkCounter)
		}

		recordKey := memRecordKey{id, pkCounter}
		m.accs[recordKey] = update.SignedAccumulator
		m.events[recordKey] = append(m.events[recordKey], update.Events...)
	}
	return nil
}

// AddIssuanceRecord implements revocationRecordStorage interface.
// This functionality is not implemented to prevent misconfiguration.
// The memRevStorage is not persistent after a restart, which is important for the storage of issuance records.
func (m *memRevStorage) AddIssuanceRecord(r *IssuanceRecord) error {
	return errors.New("not implemented")
}

// IssuanceRecords implements revocationRecordStorage interface.
// This functionality is not implemented to prevent misconfiguration.
// The memRevStorage is not persistent after a restart, which is important for the storage of issuance records.
func (m *memRevStorage) IssuanceRecords(id CredentialTypeIdentifier, key string, issued time.Time) ([]*IssuanceRecord, error) {
	return nil, errors.New("not implemented")
}

// UpdateIssuanceRecord implements revocationRecordStorage interface.
// This functionality is not implemented to prevent misconfiguration.
// The memRevStorage is not persistent after a restart, which is important for the storage of issuance records.
func (m *memRevStorage) UpdateIssuanceRecord(id CredentialTypeIdentifier, key string, issued time.Time, handler func([]*IssuanceRecord) error) error {
	return errors.New("not implemented")
}

// DeleteExpiredIssuanceRecords implements revocationRecordStorage interface.
func (m *memRevStorage) DeleteExpiredIssuanceRecords() error {
	// The memRevStorage does not support storing issuance records, so nothing has to be deleted.
	return nil
}
