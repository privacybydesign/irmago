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
	// sqlRevStorage is a wrapper around gorm, storing any record type in a SQL database,
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

func newSqlStorage(debug bool, dbtype, connstr string) (sqlRevStorage, error) {
	switch dbtype {
	case "postgres", "mysql", "mssql":
	default:
		return sqlRevStorage{}, errors.New("unsupported database type")
	}

	g, err := gorm.Open(dbtype, connstr)
	if err != nil {
		return sqlRevStorage{}, err
	}

	if dbtype == "mssql" {
		gorm.DefaultCallback.Create().Remove("mssql:set_identity_insert")
	}

	if debug {
		g.LogMode(true)
		g.SetLogger(gorm.Logger{LogWriter: log.New(Logger.WriterLevel(logrus.TraceLevel), "db: ", 0)})
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
	return s.gorm.Close()
}

func (s sqlRevStorage) Transaction(f func(tx sqlRevStorage) error) (err error) {
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

func (s sqlRevStorage) Exists(id interface{}, query interface{}, args ...interface{}) (bool, error) {
	var c int
	db := s.gorm.Model(id)
	if query != nil {
		db = db.Where(query, args...)
	}
	db = db.Count(&c)
	return c > 0, db.Error
}

func (s sqlRevStorage) Delete(id interface{}, query interface{}, args ...interface{}) error {
	return s.gorm.Delete(id, query, args).Error
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

func newMemStorage() *memRevStorage {
	return &memRevStorage{
		records: make(map[CredentialTypeIdentifier]*memUpdateRecord),
	}
}

func (m *memRevStorage) get(id CredentialTypeIdentifier) *memUpdateRecord {
	m.Lock()
	defer m.Unlock()
	return m.records[id]
}

func (m *memRevStorage) Latest(id CredentialTypeIdentifier, count uint64) map[uint]*revocation.Update {
	record := m.get(id)
	if record == nil {
		return nil
	}
	record.Lock()
	defer record.Unlock()

	updates := map[uint]*revocation.Update{}
	for _, r := range record.r {
		offset := int64(len(r.Events)) - int64(count)
		if offset < 0 {
			offset = 0
		}
		update := &revocation.Update{
			SignedAccumulator: r.SignedAccumulator,
			Events:            make([]*revocation.Event, int64(len(r.Events))-offset),
		}
		copy(update.Events, r.Events[offset:])
		if len(update.Events) > 0 {
			Logger.WithFields(logrus.Fields{
				"start": update.Events[0].Index, "end": update.Events[len(update.Events)-1].Index,
			}).Tracef("memdb: get latest")
		}
		updates[r.SignedAccumulator.PKCounter] = update
	}

	return updates
}

func (m *memRevStorage) SignedAccumulator(id CredentialTypeIdentifier, pkcounter uint) *revocation.SignedAccumulator {
	updates := m.Latest(id, 0)
	if update := updates[pkcounter]; update != nil {
		return update.SignedAccumulator
	}
	return nil
}

func (m *memRevStorage) Insert(id CredentialTypeIdentifier, update *revocation.Update) {
	logger := Logger.WithFields(logrus.Fields{
		"credtype": id, "counter": update.SignedAccumulator.PKCounter,
	})
	record := m.get(id)
	if record == nil {
		record = &memUpdateRecord{r: map[uint]*revocation.Update{}}
		m.records[id] = record
	}
	record.Lock()
	defer record.Unlock()

	r := record.r[update.SignedAccumulator.PKCounter]
	if r == nil {
		if len(update.Events) > 0 {
			logger.Trace("memdb: inserting new record")
			record.r[update.SignedAccumulator.PKCounter] = update
		}
		return
	}
	if len(update.Events) == 0 {
		if r.SignedAccumulator.Accumulator.Index == update.SignedAccumulator.Accumulator.Index {
			logger.Trace("memdb: received new accumulator")
			r.SignedAccumulator = update.SignedAccumulator
		}
		return
	}

	ours := r.Events
	theirs := update.Events
	theirStart, theirEnd, ourEnd := theirs[0].Index, theirs[len(theirs)-1].Index, ours[len(ours)-1].Index
	if theirEnd < ourEnd || ourEnd+1 < theirStart {
		logger.WithFields(logrus.Fields{"theirStart": theirStart, "theirEnd": theirEnd, "ourEnd": ourEnd}).Trace("memdb: events mismatch, discarding")
		return
	}

	logger.Trace("memdb: updating")
	offset := ourEnd + 1 - theirStart
	r.SignedAccumulator = update.SignedAccumulator
	r.Events = append(r.Events, theirs[offset:]...)
}
