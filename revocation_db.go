package irma

import (
	"fmt"
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
		// Get deserializes into o the record satisfying col = key.
		Get(typ CredentialTypeIdentifier, col string, key interface{}, o interface{}) error
		// Insert a new record which must not yet exist.
		Insert(o interface{}) error
		// Save an existing record.
		Save(o interface{}) error
		// Last deserializes the last record into o.
		Last(typ CredentialTypeIdentifier, o interface{}) error
		// Exists checks whether records exist satisfying col = key.
		Exists(typ CredentialTypeIdentifier, col string, key interface{}, o interface{}) (bool, error)
		// HasRecords checks whether any records exist for the given type.
		HasRecords(typ CredentialTypeIdentifier, o interface{}) (bool, error)
		// From deserializes into o all records where col >= key.
		From(typ CredentialTypeIdentifier, col string, key interface{}, o interface{}) error
		// Latest deserializes into o the last items; amount specified by count, ordered by col.
		Latest(typ CredentialTypeIdentifier, col string, count uint64, o interface{}) error
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
		r *revocation.Update
	}
)

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

func (m memRevStorage) Latest(typ CredentialTypeIdentifier, count uint64) *revocation.Update {
	record := m.get(typ)
	if record == nil {
		return nil
	}
	record.Lock()
	defer record.Unlock()

	offset := int64(len(record.r.Events)) - int64(count) - 1
	if offset < 0 {
		offset = 0
	}
	response := &revocation.Update{SignedAccumulator: record.r.SignedAccumulator}
	for _, rec := range record.r.Events[offset:] {
		Logger.Trace("membdb: get ", rec.Index)
		response.Events = append(response.Events, rec)
	}
	return response
}

func (m memRevStorage) Insert(typ CredentialTypeIdentifier, update *revocation.Update) {
	record := m.get(typ)
	if record == nil {
		record = &memUpdateRecord{r: &revocation.Update{}}
		m.records[typ] = record
	}
	record.Lock()
	defer record.Unlock()

	ours := record.r.Events
	if len(ours) == 0 {
		record.r = update
		return
	}
	theirs := update.Events
	if len(theirs) == 0 {
		return
	}
	theirStart, theirEnd, ourEnd := theirs[0].Index, theirs[len(theirs)-1].Index, ours[len(ours)-1].Index
	offset := ourEnd - theirStart
	if theirEnd <= ourEnd || offset < 0 {
		return
	}

	Logger.Trace("membdb: inserting")
	record.r.SignedAccumulator = update.SignedAccumulator
	record.r.Events = append(record.r.Events, theirs[offset:]...)
}

func (m memRevStorage) HasRecords(typ CredentialTypeIdentifier) bool {
	record := m.get(typ)
	if record == nil {
		return false
	}
	record.Lock()
	defer record.Unlock()
	return len(record.r.Events) > 0
}

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
	return s.gorm.Close()
}

func (s sqlRevStorage) Transaction(f func(tx revStorage) error) (err error) {
	tx := sqlRevStorage{gorm: s.gorm.Begin()}
	defer func() {
		if e := recover(); err != nil {
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

func (s sqlRevStorage) Get(typ CredentialTypeIdentifier, col string, key interface{}, o interface{}) error {
	return s.gorm.Where(map[string]interface{}{"cred_type": typ, col: key}).First(o).Error
}

func (s sqlRevStorage) Insert(o interface{}) error {
	return s.gorm.Create(o).Error
}

func (s sqlRevStorage) Save(o interface{}) error {
	return s.gorm.Save(o).Error
}

func (s sqlRevStorage) Last(typ CredentialTypeIdentifier, o interface{}) error {
	return s.gorm.Where(map[string]interface{}{"cred_type": typ}).Last(o).Error
}

func (s sqlRevStorage) Exists(typ CredentialTypeIdentifier, col string, key interface{}, o interface{}) (bool, error) {
	var c int
	s.gorm.Model(o).
		Where(map[string]interface{}{"cred_type": typ, col: key}).
		Count(&c)
	return c > 0, s.gorm.Error
}

func (s sqlRevStorage) HasRecords(typ CredentialTypeIdentifier, o interface{}) (bool, error) {
	var c int
	s.gorm.Model(o).
		Where(map[string]interface{}{"cred_type": typ}).
		Count(&c)
	return c > 0, s.gorm.Error
}

func (s sqlRevStorage) From(typ CredentialTypeIdentifier, col string, key interface{}, o interface{}) error {
	return s.gorm.Where(fmt.Sprintf("cred_type = ? and %s >= ?", col), typ, key).Order(col + " asc").Find(o).Error
}

func (s sqlRevStorage) Latest(typ CredentialTypeIdentifier, col string, count uint64, o interface{}) error {
	return s.gorm.Where(map[string]interface{}{"cred_type": typ}).Order(col + " asc").Limit(count).Find(o).Error
}
