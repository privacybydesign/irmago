package irma

import (
	"fmt"
	"log"
	"sync"

	"github.com/go-errors/errors"
	"github.com/jinzhu/gorm"
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

	// memRevStorage is a much simpler in-memory database, suitable only for storing the last
	// few revocation records, for requestors.
	memRevStorage struct {
		sync.Mutex
		records map[CredentialTypeIdentifier]*memRevRecords
	}

	memRevRecords struct {
		sync.Mutex
		r []*RevocationRecord
	}
)

func newMemStorage() memRevStorage {
	return memRevStorage{
		records: make(map[CredentialTypeIdentifier]*memRevRecords),
	}
}

func (m memRevStorage) get(typ CredentialTypeIdentifier) *memRevRecords {
	m.Lock()
	defer m.Unlock()
	if _, ok := m.records[typ]; !ok {
		m.records[typ] = &memRevRecords{r: make([]*RevocationRecord, 0, revocationUpdateCount)}
	}
	return m.records[typ]
}

func (m memRevStorage) Latest(typ CredentialTypeIdentifier, count uint64, r *[]*RevocationRecord) {
	records := m.get(typ)
	records.Lock()
	defer records.Unlock()

	c := count
	if c > uint64(len(records.r)) {
		c = uint64(len(records.r))
	}
	for _, rec := range records.r[:c] {
		Logger.Trace("membdb: get ", rec.StartIndex)
		*r = append(*r, rec)
	}
}

func (m memRevStorage) Insert(record *RevocationRecord) {
	r := m.get(record.CredType)
	r.Lock()
	defer r.Unlock()

	Logger.Trace("membdb: insert ", record)
	r.r = append(r.r, record)
}

func (m memRevStorage) HasRecords(typ CredentialTypeIdentifier) bool {
	r := m.get(typ)
	r.Lock()
	defer r.Unlock()
	return len(r.r) > 0
}

func newSqlStorage(debug bool, db string) (revStorage, error) {
	g, err := gorm.Open("postgres", db)
	if err != nil {
		return nil, err
	}

	if debug {
		g.LogMode(true)
		g.SetLogger(gorm.Logger{LogWriter: log.New(Logger.WriterLevel(logrus.DebugLevel), "db: ", 0)})
	}
	if g.AutoMigrate((*RevocationRecord)(nil)); g.Error != nil {
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
	return s.gorm.First(o, fmt.Sprintf("cred_type = ? and %s = ?", col), typ, key).Error
}

func (s sqlRevStorage) Insert(o interface{}) error {
	return s.gorm.Create(o).Error
}

func (s sqlRevStorage) Save(o interface{}) error {
	return s.gorm.Save(o).Error
}

func (s sqlRevStorage) Last(typ CredentialTypeIdentifier, o interface{}) error {
	return s.gorm.Last(o, "cred_type = ?", typ).Error
}

func (s sqlRevStorage) Exists(typ CredentialTypeIdentifier, col string, key interface{}, o interface{}) (bool, error) {
	var c int
	s.gorm.Model(o).
		Where(fmt.Sprintf("cred_type = ? and %s = ?", col), typ, key).
		Count(&c)
	return c > 0, s.gorm.Error
}

func (s sqlRevStorage) HasRecords(typ CredentialTypeIdentifier, o interface{}) (bool, error) {
	var c int
	s.gorm.Model(o).
		Where("cred_type = ?", typ).
		Count(&c)
	return c > 0, s.gorm.Error
}

func (s sqlRevStorage) From(typ CredentialTypeIdentifier, col string, key interface{}, o interface{}) error {
	return s.gorm.Where(fmt.Sprintf("cred_type = ? and %s >= ?", col), typ, key).Order(col + " asc").Find(o).Error
}

func (s sqlRevStorage) Latest(typ CredentialTypeIdentifier, col string, count uint64, o interface{}) error {
	return s.gorm.Where("cred_type = ?", typ).Order(col + " asc").Limit(count).Find(o).Error
}
