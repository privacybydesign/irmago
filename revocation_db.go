package irma

import (
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
	revocationUpdateHead struct { // TODO: name?
		SignedAccumulator *revocation.SignedAccumulator
		LatestUpdateEvent *revocation.Event // TODO: do we need the latest event?
	}

	revocationUpdateStorage interface {
		Exists(id CredentialTypeIdentifier, pkCounter uint) (bool, error)
		Events(id CredentialTypeIdentifier, pkCounter uint, from, to uint64) ([]*revocation.Event, error)
		LatestAccumulatorUpdates(id CredentialTypeIdentifier, pkCounter *uint, limit int) (map[uint]*revocation.Update, error)
		AddNewAccumulator(id CredentialTypeIdentifier, update *revocation.Update) error
		AppendUpdate(id CredentialTypeIdentifier, handler func(heads map[uint]revocationUpdateHead) (map[uint]*revocation.Update, error)) error // TODO: name?
	}

	revocationIssuanceRecordStorage interface {
		AddIssuanceRecord(*IssuanceRecord) error
		IssuanceRecords(id CredentialTypeIdentifier, key string, issued time.Time) ([]*IssuanceRecord, error)
		UpdateIssuanceRecord(id CredentialTypeIdentifier, key string, issued time.Time, handler func([]*IssuanceRecord) error) error
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

func (s sqlRevStorage) Exists(id CredentialTypeIdentifier, pkCounter uint) (bool, error) {
	var c int64
	err := s.gorm.Model((*AccumulatorRecord)(nil)).Where(map[string]interface{}{"cred_type": id, "pk_counter": pkCounter}).Count(&c).Error
	return c > 0, err
}

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

func (s sqlRevStorage) LatestAccumulatorUpdates(id CredentialTypeIdentifier, pkCounter *uint, limit int) (map[uint]*revocation.Update, error) {
	accsMap := make(map[uint]*AccumulatorRecord)
	eventsMap := make(map[uint][]*EventRecord)
	if err := s.gorm.Transaction(func(tx *gorm.DB) error {
		var accs []*AccumulatorRecord
		where := map[string]interface{}{"cred_type": id}
		if pkCounter != nil {
			where["pk_counter"] = *pkCounter
		}
		if err := tx.Find(&accs, where).Error; err != nil {
			return err
		}

		for _, acc := range accs {
			accsMap[*acc.PKCounter] = acc

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

func (s sqlRevStorage) AddNewAccumulator(id CredentialTypeIdentifier, update *revocation.Update) error {
	return s.AppendUpdate(id, func(heads map[uint]revocationUpdateHead) (map[uint]*revocation.Update, error) {
		if _, ok := heads[update.SignedAccumulator.PKCounter]; ok {
			return nil, errors.New("accumulator already exists") // TODO: duplicate error?
		}
		return map[uint]*revocation.Update{update.SignedAccumulator.PKCounter: update}, nil
	})
}

func (s sqlRevStorage) AppendUpdate(
	id CredentialTypeIdentifier,
	handler func(heads map[uint]revocationUpdateHead) (map[uint]*revocation.Update, error),
) error {
	return s.gorm.Transaction(func(tx *gorm.DB) error {
		// Retrieve the current accumulator state for every public key of the credential and lock the rows for update.
		var accs []*AccumulatorRecord
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Find(&accs, map[string]interface{}{"cred_type": id}).Error; err != nil {
			return err
		}

		heads := make(map[uint]revocationUpdateHead, len(accs))
		for _, acc := range accs {
			var event *EventRecord
			if err := tx.Last(&event, map[string]interface{}{"pk_counter": *acc.PKCounter}).Error; err != nil {
				return err
			}
			heads[*acc.PKCounter] = revocationUpdateHead{acc.SignedAccumulator(), event.Event()}
		}

		updates, err := handler(heads)
		if err != nil {
			return err
		}

		for pkCounter, update := range updates {
			for _, event := range update.Events {
				eventRecord := new(EventRecord).Convert(id, pkCounter, event)
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

func (s sqlRevStorage) AddIssuanceRecord(r *IssuanceRecord) error {
	return s.gorm.Create(r).Error
}

func (s sqlRevStorage) IssuanceRecords(id CredentialTypeIdentifier, key string, issued time.Time) ([]*IssuanceRecord, error) {
	return txIssuanceRecords(s.gorm, id, key, issued)
}

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

func (s sqlRevStorage) DeleteExpiredIssuanceRecords() error {
	return s.gorm.Delete(IssuanceRecord{}, "valid_until < ?", time.Now().UnixNano()).Error
}

func txIssuanceRecords(tx *gorm.DB, id CredentialTypeIdentifier, key string, issued time.Time) ([]*IssuanceRecord, error) {
	where := "cred_type = ? AND revocationkey = ? AND revoked_at = 0"

	var r []*IssuanceRecord
	var err error
	if issued.IsZero() {
		err = tx.Find(&r, where, id, key).Error
	} else {
		where += " AND issued = ?"
		err = tx.Find(&r, where, id, key, issued.UnixNano()).Error
	}
	if err != nil {
		return nil, err
	}
	if len(r) == 0 {
		return nil, ErrUnknownRevocationKey
	}
	return r, nil
}

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

func (m *memRevStorage) Exists(id CredentialTypeIdentifier, pkCounter uint) (bool, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	_, ok := m.accs[memRecordKey{id, pkCounter}]
	return ok, nil
}

func (m *memRevStorage) Events(id CredentialTypeIdentifier, pkCounter uint, from, to uint64) ([]*revocation.Event, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	events := m.events[memRecordKey{id, pkCounter}]
	if len(events) == 0 {
		return nil, ErrRevocationStateNotFound
	}

	startIndex := int(from - events[0].Index)
	endIndex := int(to - events[0].Index)
	if startIndex < 0 || startIndex >= endIndex || endIndex > len(events) {
		return nil, errors.New("invalid range")
	}

	return events[startIndex:endIndex], nil
}

func (m *memRevStorage) LatestAccumulatorUpdates(id CredentialTypeIdentifier, pkCounter *uint, limit int) (map[uint]*revocation.Update, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

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

func (m *memRevStorage) AddNewAccumulator(id CredentialTypeIdentifier, update *revocation.Update) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	recordKey := memRecordKey{id, update.SignedAccumulator.PKCounter}
	if _, ok := m.accs[recordKey]; ok {
		return errors.New("accumulator already exists") // TODO: duplicate error?
	}
	m.accs[recordKey] = update.SignedAccumulator
	m.events[recordKey] = update.Events
	return nil
}

func (m *memRevStorage) AppendUpdate(
	id CredentialTypeIdentifier,
	handler func(heads map[uint]revocationUpdateHead) (map[uint]*revocation.Update, error),
) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	pkCounters := m.pkCounters[id]
	heads := make(map[uint]revocationUpdateHead, len(pkCounters))

	for _, pkCounter := range pkCounters {
		recordKey := memRecordKey{id, pkCounter}
		events := m.events[recordKey]
		heads[pkCounter] = revocationUpdateHead{
			m.accs[recordKey],
			events[len(events)-1],
		}
	}

	updates, err := handler(heads)
	if err != nil {
		return err
	}

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
