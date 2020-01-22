package irma

import (
	"log"
	"sync"

	"github.com/go-errors/errors"
	"github.com/jinzhu/gorm"
	"github.com/privacybydesign/gabi/revocation"
	"github.com/sirupsen/logrus"
)

type (
	revStorage interface {
		// Transaction executes the given closure within a transaction.
		Transaction(f func(tx revStorage) error) (err error)
		// Insert a new record which must not yet exist.
		Insert(o interface{}) error
		// Save an existing record.
		Save(o interface{}) error
		// Last deserializes the last record into o.
		Last(dest interface{}, query interface{}, args ...interface{}) error
		// Exists checks whether records exist satisfying col = key.
		Exists(typ interface{}, query interface{}, args ...interface{}) (bool, error)
		// Delete records of the given type satisfying the query.
		Delete(typ interface{}, query interface{}, args ...interface{}) error
		// Find deserializes into o all records satisfying the specified query.
		Find(dest interface{}, query interface{}, args ...interface{}) error
		// Latest deserializes into o the last items; amount specified by count, ordered by col.
		Latest(dest interface{}, count uint64, query interface{}, args ...interface{}) error
		// Close the database.
		Close() error
	}

	// sqlRevStorage implements the revStorage interface, storing any record type in a SQL database,
	// for use by revocation servers.
	sqlRevStorage struct {
		gorm *gorm.DB
	}

	// memRevStorage is a much simpler in-memory database, suitable only for storing update messages.
	memRevStorage struct {
		sync.Mutex
		records map[CredentialTypeIdentifier]*memUpdateRecord
	}

	memUpdateRecord struct {
		sync.Mutex
		r map[uint]*revocation.Update
	}
)

func newSqlStorage(debug bool, dbtype, connstr string) (revStorage, error) {
	switch dbtype {
	case "postgres", "mysql":
	default:
		return nil, errors.New("unsupported database type")
	}

	g, err := gorm.Open(dbtype, connstr)
	if err != nil {
		return nil, err
	}

	if debug {
		g.LogMode(true)
		g.SetLogger(gorm.Logger{LogWriter: log.New(Logger.WriterLevel(logrus.DebugLevel), "db: ", 0)})
	}
	if g.AutoMigrate((*EventRecord)(nil)); g.Error != nil {
		return nil, g.Error
	}
	if g.AutoMigrate((*AccumulatorRecord)(nil)); g.Error != nil {
		return nil, g.Error
	}
	if g.AutoMigrate((*IssuanceRecord)(nil)); g.Error != nil {
		return nil, g.Error
	}

	return sqlRevStorage{gorm: g}, nil
}

func (s sqlRevStorage) Close() error {
	Logger.Debug("closing revocation sql database connection")
	return s.gorm.Close()
}

func (s sqlRevStorage) Transaction(f func(tx revStorage) error) (err error) {
	tx := sqlRevStorage{gorm: s.gorm.Begin()}
	defer func() {
		if e := recover(); e != nil {
			err = errors.WrapPrefix(e, "panic in db transaction", 0)
			tx.gorm.Rollback()
		}
	}()

	if err = f(tx); err != nil {
		tx.gorm.Rollback()
		return err
	}

	err = tx.gorm.Commit().Error
	return
}

func (s sqlRevStorage) Insert(o interface{}) error {
	return s.gorm.Create(o).Error
}

func (s sqlRevStorage) Save(o interface{}) error {
	return s.gorm.Save(o).Error
}

func (s sqlRevStorage) Last(dest interface{}, query interface{}, args ...interface{}) error {
	db := s.gorm
	if query != nil {
		db = db.Where(query, args...)
	}
	return db.Last(dest).Error
}

func (s sqlRevStorage) Exists(typ interface{}, query interface{}, args ...interface{}) (bool, error) {
	var c int
	db := s.gorm.Model(typ)
	if query != nil {
		db = db.Where(query, args...)
	}
	db = db.Count(&c)
	return c > 0, db.Error
}

func (s sqlRevStorage) Delete(typ interface{}, query interface{}, args ...interface{}) error {
	return s.gorm.Delete(typ, query, args).Error
}

func (s sqlRevStorage) Find(dest interface{}, query interface{}, args ...interface{}) error {
	return s.gorm.
		Where(query, args...).
		Set("gorm:order_by_primary_key", "ASC").
		Find(dest).Error
}

func (s sqlRevStorage) Latest(dest interface{}, count uint64, query interface{}, args ...interface{}) error {
	return s.gorm.
		Where(query, args...).
		Limit(count).
		Set("gorm:order_by_primary_key", "DESC").
		Find(dest).Error
}

func newMemStorage() memRevStorage {
	return memRevStorage{
		records: make(map[CredentialTypeIdentifier]*memUpdateRecord),
	}
}

func (m memRevStorage) get(typ CredentialTypeIdentifier) *memUpdateRecord {
	m.Lock()
	defer m.Unlock()
	return m.records[typ]
}

func (m memRevStorage) Latest(typ CredentialTypeIdentifier, count uint64) map[uint]*revocation.Update {
	record := m.get(typ)
	if record == nil {
		return nil
	}
	record.Lock()
	defer record.Unlock()

	updates := map[uint]*revocation.Update{}
	for _, r := range record.r {
		offset := int64(len(r.Events)) - int64(count) - 1
		if offset < 0 {
			offset = 0
		}
		update := &revocation.Update{
			SignedAccumulator: r.SignedAccumulator,
			Events:            make([]*revocation.Event, int64(len(r.Events))-offset),
		}
		copy(update.Events, r.Events[offset:])
		if len(update.Events) > 0 {
			Logger.Tracef("memdb: get %d-%d", update.Events[0].Index, update.Events[len(update.Events)-1].Index)
		}
		updates[r.SignedAccumulator.PKCounter] = update
	}

	return updates
}

func (m memRevStorage) SignedAccumulator(typ CredentialTypeIdentifier, pkcounter uint) *revocation.SignedAccumulator {
	updates := m.Latest(typ, 0)
	for _, u := range updates {
		return u.SignedAccumulator
	}
	return nil
}

func (m memRevStorage) Insert(typ CredentialTypeIdentifier, update *revocation.Update) {
	record := m.get(typ)
	if record == nil {
		record = &memUpdateRecord{r: map[uint]*revocation.Update{}}
		m.records[typ] = record
	}
	record.Lock()
	defer record.Unlock()

	r := record.r[update.SignedAccumulator.PKCounter]
	if r == nil || len(r.Events) == 0 {
		record.r[update.SignedAccumulator.PKCounter] = update
		return
	}
	if len(update.Events) == 0 && r.SignedAccumulator.Accumulator.Index == update.SignedAccumulator.Accumulator.Index {
		r.SignedAccumulator = update.SignedAccumulator
		return
	}

	ours := r.Events
	theirs := update.Events
	if len(theirs) == 0 {
		return
	}
	theirStart, theirEnd, ourEnd := theirs[0].Index, theirs[len(theirs)-1].Index, ours[len(ours)-1].Index
	if theirEnd <= ourEnd || ourEnd+1 < theirStart {
		return
	}

	Logger.Trace("memdb: inserting")
	offset := ourEnd + 1 - theirStart
	r.SignedAccumulator = update.SignedAccumulator
	r.Events = append(r.Events, theirs[offset:]...)
}
