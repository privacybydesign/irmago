package irma

import (
	"fmt"
	"time"

	"github.com/go-errors/errors"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/revocation"
	"github.com/privacybydesign/gabi/signed"
)

type (
	RevocationStorage struct {
		conf     *Configuration
		db       revStorage
		memdb    memRevStorage
		sqlMode  bool
		settings map[CredentialTypeIdentifier]*RevocationSetting

		Keys   RevocationKeys
		client RevocationClient
	}

	RevocationClient struct {
		Conf *Configuration
	}

	RevocationKeys struct {
		Conf *Configuration
	}

	RevocationSetting struct {
		Mode     RevocationMode `json:"mode"`
		PostURLs []string       `json:"post_urls" mapstructure:"post_urls"`
		updated  time.Time
	}

	RevocationMode int

	RevocationRecord struct {
		revocation.Record `gorm:"embedded"`
		CredType          CredentialTypeIdentifier `gorm:"primary_key"`
	}

	TimeRecord struct {
		Index      uint64
		Start, End int64
	}

	// IssuanceRecord contains information generated during issuance, needed for later revocation.
	IssuanceRecord struct {
		CredType   CredentialTypeIdentifier `gorm:"primary_key"`
		Key        string                   `gorm:"primary_key"`
		Attr       *big.Int
		Issued     int64
		ValidUntil int64
		RevokedAt  int64 // 0 if not currently revoked
	}
)

const (
	RevocationModeRequestor RevocationMode = iota
	RevocationModeProxy
	RevocationModeServer
)

// Revocation record methods

func (rs *RevocationStorage) EnableRevocation(typ CredentialTypeIdentifier) error {
	hasRecords, err := rs.db.HasRecords(typ, (*RevocationRecord)(nil))
	if err != nil {
		return err
	}
	if hasRecords {
		return errors.New("revocation record table not empty")
	}

	sk, err := rs.Keys.PrivateKey(typ.IssuerIdentifier())
	if err != nil {
		return err
	}
	msg, acc, err := revocation.NewAccumulator(sk)
	if err != nil {
		return err
	}
	r := &RevocationRecord{
		Record: revocation.Record{
			PublicKeyIndex: sk.Counter,
			Message:        msg,
			StartIndex:     acc.Index,
			EndIndex:       acc.Index,
		},
		CredType: typ,
	}

	if err = rs.AddRevocationRecord(r); err != nil {
		return err
	}
	return nil
}

// Get returns all records that a client requires to update its revocation state if it is currently
// at the specified index, that is, all records whose end index is greater than or equal to
// the specified index.
func (rs *RevocationStorage) RevocationRecords(typ CredentialTypeIdentifier, index uint64) ([]*RevocationRecord, error) {
	var records []*RevocationRecord
	return records, rs.db.From(typ, "end_index", index, &records)
}

func (rs *RevocationStorage) LatestRevocationRecords(typ CredentialTypeIdentifier, count uint64) ([]*RevocationRecord, error) {
	var records []*RevocationRecord
	if rs.sqlMode {
		if err := rs.db.Latest(typ, "end_index", count, &records); err != nil {
			return nil, err
		}
	} else {
		rs.memdb.Latest(typ, count, &records)
	}
	if len(records) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return records, nil
}

func (rs *RevocationStorage) AddRevocationRecords(records []*RevocationRecord) error {
	var err error
	for _, r := range records {
		if err = rs.AddRevocationRecord(r); err != nil {
			return err
		}
	}
	return nil
}

func (rs *RevocationStorage) AddRevocationRecord(record *RevocationRecord) error {
	return rs.addRevocationRecord(rs.db, record)
}

func (rs *RevocationStorage) addRevocationRecord(tx revStorage, record *RevocationRecord) error {
	// Unmarshal and verify the record against the appropriate public key
	pk, err := rs.Keys.PublicKey(record.CredType.IssuerIdentifier(), record.PublicKeyIndex)
	if err != nil {
		return err
	}
	_, err = record.UnmarshalVerify(pk)
	if err != nil {
		return err
	}

	// Save record
	if rs.sqlMode {
		if err = tx.Insert(record); err != nil {
			return err
		}
	} else {
		rs.memdb.Insert(record)
	}

	s := rs.getSettings(record.CredType)
	s.updated = time.Now()
	go rs.client.PostRevocationRecord(s, record) // POST record to listeners, if any, asynchroniously

	return nil
}

// RevocationEnabled returns whether or not revocation is enabled for the given credential type,
// by checking if any revocation record exists in the database.
func (rs *RevocationStorage) RevocationEnabled(typ CredentialTypeIdentifier) (bool, error) {
	if rs.sqlMode {
		return rs.db.HasRecords(typ, (*RevocationRecord)(nil))
	} else {
		return rs.memdb.HasRecords(typ), nil
	}
}

// Issuance records

func (rs *RevocationStorage) IssuanceRecordExists(typ CredentialTypeIdentifier, key []byte) (bool, error) {
	return rs.db.Exists(typ, "key", key, &IssuanceRecord{})
}

func (rs *RevocationStorage) AddIssuanceRecord(r *IssuanceRecord) error {
	return rs.db.Insert(r)
}

func (rs *RevocationStorage) IssuanceRecord(typ CredentialTypeIdentifier, key []byte) (*IssuanceRecord, error) {
	var r IssuanceRecord
	err := rs.db.Get(typ, "key", key, &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// Revocation methods

// Revoke revokes the credential specified specified by key if found within the current database,
// by updating its revocation time to now, adding its revocation attribute to the current accumulator,
// and updating the revocation database on disk.
func (rs *RevocationStorage) Revoke(typ CredentialTypeIdentifier, key string) error {
	sk, err := rs.conf.PrivateKey(typ.IssuerIdentifier())
	if err != nil {
		return err
	}
	if sk == nil {
		return errors.New("private key not found")
	}
	rsk, err := sk.RevocationKey()
	if err != nil {
		return err
	}

	return rs.db.Transaction(func(tx revStorage) error {
		var err error
		cr := IssuanceRecord{}
		if err = tx.Get(typ, "key", key, &cr); err != nil {
			return err
		}
		cr.RevokedAt = time.Now().UnixNano()
		if err = tx.Save(&cr); err != nil {
			return err
		}
		return rs.revokeAttr(tx, typ, rsk, cr.Attr)
	})
}

func (rs *RevocationStorage) revokeAttr(tx revStorage, typ CredentialTypeIdentifier, sk *revocation.PrivateKey, e *big.Int) error {
	cur, err := rs.currentAccumulator(tx, typ)
	if err != nil {
		return err
	}
	if cur == nil {
		return errors.Errorf("cannot revoke for type %s, not enabled yet", typ)
	}

	newAcc, err := cur.Remove(sk, e)
	if err != nil {
		return err
	}
	update := &revocation.AccumulatorUpdate{
		Accumulator: *newAcc,
		StartIndex:  newAcc.Index,
		Revoked:     []*big.Int{e},
		Time:        time.Now().UnixNano(),
	}
	updateMsg, err := signed.MarshalSign(sk.ECDSA, update)
	if err != nil {
		return err
	}
	record := &RevocationRecord{
		Record: revocation.Record{
			StartIndex:     newAcc.Index,
			EndIndex:       newAcc.Index,
			PublicKeyIndex: sk.Counter,
			Message:        updateMsg,
		},
		CredType: typ,
	}
	if err = rs.addRevocationRecord(tx, record); err != nil {
		return err
	}
	return nil
}

// Accumulator methods

func (rs *RevocationStorage) CurrentAccumulator(typ CredentialTypeIdentifier) (*revocation.Accumulator, error) {
	return rs.currentAccumulator(rs.db, typ)
}

func (rs *RevocationStorage) currentAccumulator(tx revStorage, typ CredentialTypeIdentifier) (rec *revocation.Accumulator, err error) {
	record := &RevocationRecord{}

	if rs.sqlMode {
		if err := tx.Last(typ, record); err != nil {
			if gorm.IsRecordNotFoundError(err) {
				return nil, nil
			}
			return nil, err
		}
	} else {
		var r []*RevocationRecord
		rs.memdb.Latest(typ, 1, &r)
		if len(r) == 0 {
			return nil, nil
		}
		record = r[0]
	}

	pk, err := rs.Keys.PublicKey(typ.IssuerIdentifier(), record.PublicKeyIndex)
	if err != nil {
		return nil, err
	}
	var u revocation.AccumulatorUpdate
	if err = signed.UnmarshalVerify(pk.ECDSA, record.Message, &u); err != nil {
		return nil, err
	}
	return &u.Accumulator, nil
}

// Methods to update from remote revocation server

func (rs *RevocationStorage) UpdateDB(typ CredentialTypeIdentifier) error {
	records, err := rs.client.FetchLatestRevocationRecords(typ, revocationUpdateCount)
	if err != nil {
		return err
	}
	return rs.AddRevocationRecords(records)
}

func (rs *RevocationStorage) updateIfOld(typ CredentialTypeIdentifier) error {
	if rs.getSettings(typ).updated.Before(time.Now().Add(-5 * time.Minute)) {
		if err := rs.UpdateDB(typ); err != nil {
			return err
		}
	}
	return nil
}

// SaveIssuanceRecord either stores the issuance record locally, if we are the revocation server of
// the crecential type, or it signs and sends it to the remote revocation server.
func (rs *RevocationStorage) SaveIssuanceRecord(typ CredentialTypeIdentifier, rec *IssuanceRecord) error {
	// TODO store locally if appropriate?

	// Just store it if we are the revocation server for this credential type
	if rs.getSettings(typ).Mode == RevocationModeServer {
		return rs.AddIssuanceRecord(rec)
	}

	// We have to send it, sign it first
	credtype := rs.conf.CredentialTypes[typ]
	if credtype == nil {
		return errors.New("unknown credential type")
	}
	if credtype.RevocationServer == "" {
		return errors.New("credential type has no revocation server")
	}
	sk, err := rs.Keys.PrivateKey(typ.IssuerIdentifier())
	if err != nil {
		return err
	}
	message, err := signed.MarshalSign(sk.ECDSA, rec)
	if err != nil {
		return err
	}

	return rs.client.PostIssuanceRecord(typ, sk.Counter, message)
}

// Misscelaneous methods

func (rs *RevocationStorage) Load(debug bool, connstr string, settings map[CredentialTypeIdentifier]*RevocationSetting) error {
	if connstr == "" {
		for typ, s := range settings {
			if s.Mode != RevocationModeRequestor {
				return errors.Errorf("revocation mode for %s requires SQL database but no connection string given", typ)
			}
		}
	}

	if connstr == "" {
		Logger.Trace("Using memory revocation database")
		rs.memdb = newMemStorage()
		rs.sqlMode = false
	} else {
		Logger.Trace("Connecting to revocation SQL database")
		db, err := newSqlStorage(debug, connstr)
		if err != nil {
			return err
		}
		rs.db = db
		rs.sqlMode = true
	}
	if settings != nil {
		rs.settings = settings
	} else {
		rs.settings = map[CredentialTypeIdentifier]*RevocationSetting{}
	}
	rs.client = RevocationClient{Conf: rs.conf}
	rs.Keys = RevocationKeys{Conf: rs.conf}
	return nil
}

func (rs *RevocationStorage) Close() error {
	if rs.db != nil {
		return rs.db.Close()
	}
	return nil
}

// SetRevocationRecords retrieves the latest revocation records from the database, and attaches
// them to the request, for each credential type for which a nonrevocation proof is requested in
// b.Revocation.
func (rs *RevocationStorage) SetRevocationRecords(b *BaseRequest) error {
	if len(b.Revocation) == 0 {
		return nil
	}
	var err error
	b.RevocationUpdates = make(map[CredentialTypeIdentifier][]*RevocationRecord, len(b.Revocation))
	for _, credid := range b.Revocation {
		if err = rs.updateIfOld(credid); err != nil {
			return err
		}
		b.RevocationUpdates[credid], err = rs.LatestRevocationRecords(credid, revocationUpdateCount)
		if err != nil {
			return err
		}
	}
	return nil
}

func (rs *RevocationStorage) getSettings(typ CredentialTypeIdentifier) *RevocationSetting {
	if rs.settings[typ] == nil {
		rs.settings[typ] = &RevocationSetting{}
	}
	return rs.settings[typ]
}

// TODO support POSTing multiple records
func (RevocationClient) PostRevocationRecord(s *RevocationSetting, record *RevocationRecord) {
	transport := NewHTTPTransport("")
	for _, url := range s.PostURLs {
		if err := transport.Post(url+"/-/revocation/records", nil, &[]*RevocationRecord{record}); err != nil {
			Logger.Warn("error sending revocation update", err)
		}
	}
}

func (client RevocationClient) PostIssuanceRecord(typ CredentialTypeIdentifier, counter uint, message signed.Message) error {
	return NewHTTPTransport(client.Conf.CredentialTypes[typ].RevocationServer).Post(
		fmt.Sprintf("-/revocation/issuancerecord/%s/%d", typ, counter), nil, []byte(message),
	)
}

// FetchRevocationRecords gets revocation update messages from the revocation server, of the specified index and greater.
func (client RevocationClient) FetchRevocationRecords(typ CredentialTypeIdentifier, index uint64) ([]*RevocationRecord, error) {
	var records []*RevocationRecord
	err := NewHTTPTransport(client.Conf.CredentialTypes[typ].RevocationServer).
		Get(fmt.Sprintf("-/revocation/records/%s/%d", typ, index), &records)
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (client RevocationClient) FetchLatestRevocationRecords(typ CredentialTypeIdentifier, count uint64) ([]*RevocationRecord, error) {
	var records []*RevocationRecord
	err := NewHTTPTransport(client.Conf.CredentialTypes[typ].RevocationServer).
		Get(fmt.Sprintf("-/revocation/latestrecords/%s/%d", typ, count), &records)
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (rs RevocationKeys) PrivateKey(issid IssuerIdentifier) (*revocation.PrivateKey, error) {
	sk, err := rs.Conf.PrivateKey(issid)
	if err != nil {
		return nil, err
	}
	if sk == nil {
		return nil, errors.Errorf("unknown private key: %s", issid)
	}
	revsk, err := sk.RevocationKey()
	if err != nil {
		return nil, err
	}
	return revsk, nil
}

func (rs RevocationKeys) PublicKey(issid IssuerIdentifier, counter uint) (*revocation.PublicKey, error) {
	pk, err := rs.Conf.PublicKey(issid, int(counter))
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, errors.Errorf("unknown public key: %s-%d", issid, counter)
	}
	revpk, err := pk.RevocationKey()
	if err != nil {
		return nil, err
	}
	return revpk, nil
}
