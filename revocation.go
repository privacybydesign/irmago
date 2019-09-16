package irma

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/go-errors/errors"
	"github.com/hashicorp/go-multierror"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/revocation"
	"github.com/privacybydesign/gabi/signed"
	"github.com/timshannon/bolthold"
	bolt "go.etcd.io/bbolt"
)

type (
	// Keystore provides support for revocation public key rollover.
	Keystore interface {
		// PublicKey either returns the specified, non-nil public key or an error
		PublicKey(counter uint) (*revocation.PublicKey, error)
	}

	// DB is a bolthold database storing revocation state for a particular accumulator
	// (Record instances, and IssuanceRecord instances if used by an issuer).
	DB struct {
		Current  revocation.Accumulator
		Updated  time.Time
		onChange []func(*Record)
		bolt     *bolthold.Store
		keystore Keystore
	}

	RevocationStorage struct {
		dbs  map[CredentialTypeIdentifier]*DB
		conf *Configuration
	}

	// Record contains a signed AccumulatorUpdate and associated information.
	Record struct {
		StartIndex     uint64
		EndIndex       uint64
		PublicKeyIndex uint
		Message        signed.Message // signed revocation.AccumulatorUpdate
	}

	TimeRecord struct {
		Index      uint64
		Start, End int64
	}

	// IssuanceRecord contains information generated during issuance, needed for later revocation.
	IssuanceRecord struct {
		Key        string
		Attr       *big.Int
		Issued     int64
		ValidUntil int64
		RevokedAt  int64 // 0 if not currently revoked
	}

	currentRecord struct {
		Index uint64
	}
)

const boltCurrentIndexKey = "currentIndex"

func (conf *Configuration) RevocationKeystore(issuerid IssuerIdentifier) Keystore {
	return &issuerKeystore{issid: issuerid, conf: conf}
}

// issuerKeystore implements Keystore.
type issuerKeystore struct {
	issid IssuerIdentifier
	conf  *Configuration
}

var _ Keystore = (*issuerKeystore)(nil)

func (ks *issuerKeystore) PublicKey(counter uint) (*revocation.PublicKey, error) {
	pk, err := ks.conf.PublicKey(ks.issid, int(counter))
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, errors.Errorf("public key %d of issuer %s not found", counter, ks.issid)
	}
	if !pk.RevocationSupported() {
		return nil, errors.Errorf("public key %d of issuer %s does not support revocation", counter, ks.issid)
	}
	rpk, err := pk.RevocationKey()
	if err != nil {
		return nil, err
	}
	return rpk, nil
}

func (rdb *DB) EnableRevocation(sk *revocation.PrivateKey) error {
	msg, acc, err := revocation.NewAccumulator(sk)
	if err != nil {
		return err
	}
	if err = rdb.Add(msg, sk.Counter); err != nil {
		return err
	}
	rdb.Current = acc
	return nil
}

// Revoke revokes the credential specified specified by key if found within the current database,
// by updating its revocation time to now, adding its revocation attribute to the current accumulator,
// and updating the revocation database on disk.
func (rdb *DB) Revoke(sk *revocation.PrivateKey, key []byte) error {
	return rdb.bolt.Bolt().Update(func(tx *bolt.Tx) error {
		var err error
		cr := IssuanceRecord{}
		if err = rdb.bolt.TxGet(tx, key, &cr); err != nil {
			return err
		}
		cr.RevokedAt = time.Now().UnixNano()
		if err = rdb.bolt.TxUpdate(tx, key, &cr); err != nil {
			return err
		}
		return rdb.revokeAttr(sk, cr.Attr, tx)
	})
}

// Get returns all records that a client requires to update its revocation state if it is currently
// at the specified index, that is, all records whose end index is greater than or equal to
// the specified index.
func (rdb *DB) RevocationRecords(index int) ([]*Record, error) {
	var records []*Record
	if err := rdb.bolt.Find(&records, bolthold.Where(bolthold.Key).Ge(uint64(index))); err != nil {
		return nil, err
	}
	return records, nil
}

func (rdb *DB) LatestRecords(count int) ([]*Record, error) {
	c := int(rdb.Current.Index) - count + 1
	if c < 0 {
		c = 0
	}
	return rdb.RevocationRecords(c)
}

func (rdb *DB) IssuanceRecordExists(key []byte) (bool, error) {
	_, err := rdb.IssuanceRecord(key)
	switch err {
	case nil:
		return true, nil
	case bolthold.ErrNotFound:
		return false, nil
	default:
		return false, err
	}
}

func (rdb *DB) AddIssuanceRecord(r *IssuanceRecord) error {
	return rdb.bolt.Insert([]byte(r.Key), r)
}

func (rdb *DB) IssuanceRecord(key []byte) (*IssuanceRecord, error) {
	r := &IssuanceRecord{}
	if err := rdb.bolt.Get(key, r); err != nil {
		return nil, err
	}
	return r, nil
}

func (rdb *DB) AddRecords(records []*Record) error {
	var err error
	for _, r := range records {
		if err = rdb.Add(r.Message, r.PublicKeyIndex); err != nil {
			return err
		}
	}
	rdb.Updated = time.Now() // TODO update this in add()?
	return nil
}

func (rdb *DB) Add(updateMsg signed.Message, counter uint) error {
	var err error
	var update revocation.AccumulatorUpdate

	pk, err := rdb.keystore.PublicKey(counter)
	if err != nil {
		return err
	}

	if err = signed.UnmarshalVerify(pk.ECDSA, updateMsg, &update); err != nil {
		return err
	}

	return rdb.bolt.Bolt().Update(func(tx *bolt.Tx) error {
		return rdb.add(update, updateMsg, counter, tx)
	})
}

func (rdb *DB) add(update revocation.AccumulatorUpdate, updateMsg signed.Message, pkCounter uint, tx *bolt.Tx) error {
	var err error
	record := &Record{
		StartIndex:     update.StartIndex,
		EndIndex:       update.Accumulator.Index,
		PublicKeyIndex: pkCounter,
		Message:        updateMsg,
	}
	if err = rdb.bolt.TxInsert(tx, update.Accumulator.Index, record); err != nil {
		return err
	}

	if update.Accumulator.Index != 0 {
		var tr TimeRecord
		if err = rdb.bolt.TxGet(tx, update.Accumulator.Index-1, &tr); err == nil {
			tr.End = time.Now().UnixNano()
			if err = rdb.bolt.TxUpdate(tx, update.Accumulator.Index-1, &tr); err != nil {
				return err
			}
		}
	}
	if err = rdb.bolt.TxInsert(tx, update.Accumulator.Index, &TimeRecord{
		Index: update.Accumulator.Index,
		Start: time.Now().UnixNano(),
	}); err != nil {
		return err
	}

	if err = rdb.bolt.TxUpsert(tx, boltCurrentIndexKey, &currentRecord{update.Accumulator.Index}); err != nil {
		return err
	}

	for _, f := range rdb.onChange {
		f(record)
	}

	rdb.Current = update.Accumulator
	return nil
}

func (rdb *DB) Enabled() bool {
	var currentIndex currentRecord
	err := rdb.bolt.Get(boltCurrentIndexKey, &currentIndex)
	return err == nil
}

func (rdb *DB) loadCurrent() error {
	var currentIndex currentRecord
	if err := rdb.bolt.Get(boltCurrentIndexKey, &currentIndex); err == bolthold.ErrNotFound {
		return errors.New("revocation database not initialized")
	} else if err != nil {
		return err
	}

	var record Record
	if err := rdb.bolt.Get(currentIndex.Index, &record); err != nil {
		return err
	}
	pk, err := rdb.keystore.PublicKey(record.PublicKeyIndex)
	if err != nil {
		return err
	}
	var u revocation.AccumulatorUpdate
	if err = signed.UnmarshalVerify(pk.ECDSA, record.Message, &u); err != nil {
		return err
	}
	rdb.Current = u.Accumulator
	return nil
}

func (rdb *DB) RevokeAttr(sk *revocation.PrivateKey, e *big.Int) error {
	return rdb.bolt.Bolt().Update(func(tx *bolt.Tx) error {
		return rdb.revokeAttr(sk, e, tx)
	})
}

func (rdb *DB) revokeAttr(sk *revocation.PrivateKey, e *big.Int, tx *bolt.Tx) error {
	// don't update rdb.Current until after all possible errors are handled
	newAcc, err := rdb.Current.Remove(sk, e)
	if err != nil {
		return err
	}
	update := revocation.AccumulatorUpdate{
		Accumulator: *newAcc,
		StartIndex:  newAcc.Index,
		Revoked:     []*big.Int{e},
		Time:        time.Now().UnixNano(),
	}
	updateMsg, err := signed.MarshalSign(sk.ECDSA, update)
	if err != nil {
		return err
	}
	if err = rdb.add(update, updateMsg, sk.Counter, tx); err != nil {
		return err
	}
	rdb.Current = *newAcc
	return nil
}

func (rdb *DB) Close() error {
	rdb.onChange = nil
	if rdb.bolt != nil {
		return rdb.bolt.Close()
	}
	return nil
}

func (rdb *DB) OnChange(handler func(*Record)) {
	rdb.onChange = append(rdb.onChange, handler)
}

func (r *Record) UnmarshalVerify(keystore Keystore) (*revocation.AccumulatorUpdate, error) {
	pk, err := keystore.PublicKey(r.PublicKeyIndex)
	if err != nil {
		return nil, err
	}
	msg := &revocation.AccumulatorUpdate{}
	if err := signed.UnmarshalVerify(pk.ECDSA, r.Message, msg); err != nil {
		return nil, err
	}
	if (r.StartIndex != msg.StartIndex) ||
		(r.EndIndex > 0 && r.EndIndex != msg.StartIndex+uint64(len(msg.Revoked))-1) {
		return nil, errors.New("record has invalid start or end index")
	}
	return msg, nil
}

func (rs *RevocationStorage) LoadDB(credid CredentialTypeIdentifier) (*DB, error) {
	path := filepath.Join(rs.conf.RevocationPath, credid.String())
	keystore := rs.conf.RevocationKeystore(credid.IssuerIdentifier())

	b, err := bolthold.Open(path, 0600, &bolthold.Options{Options: &bolt.Options{Timeout: 1 * time.Second}})
	if err != nil {
		return nil, err
	}
	db := &DB{
		bolt:     b,
		keystore: keystore,
	}
	if db.Enabled() {
		if err = db.loadCurrent(); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return db, nil
}

func (rs *RevocationStorage) PrivateKey(issid IssuerIdentifier) (*revocation.PrivateKey, error) {
	pk, err := rs.conf.PrivateKey(issid)
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, errors.Errorf("unknown public key: %s", issid)
	}
	revpk, err := pk.RevocationKey()
	if err != nil {
		return nil, err
	}
	return revpk, nil
}

func (rs *RevocationStorage) PublicKey(issid IssuerIdentifier, counter uint) (*revocation.PublicKey, error) {
	pk, err := rs.conf.PublicKey(issid, int(counter))
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

func (rs *RevocationStorage) UpdateWitness(w *revocation.Witness, msgs []*Record, issid IssuerIdentifier) (bool, error) {
	var err error
	var pk *revocation.PublicKey
	oldindex := w.Index
	for _, msg := range msgs {
		if pk, err = rs.PublicKey(issid, msg.PublicKeyIndex); err != nil {
			return false, err
		}
		if err = w.Update(pk, msg.Message); err != nil {
			return false, err
		}
	}
	return w.Index == oldindex, nil
}

func (rs *RevocationStorage) RevocationGetUpdates(credid CredentialTypeIdentifier, index uint64) ([]*Record, error) {
	var records []*Record
	err := NewHTTPTransport(rs.conf.CredentialTypes[credid].RevocationServer).
		Get(fmt.Sprintf("-/revocation/records/%s/%d", credid, index), &records)
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (rs *RevocationStorage) RevocationUpdateAll() error {
	var err error
	for credid := range rs.dbs {
		if err = rs.RevocationUpdateDB(credid); err != nil {
			return err
		}
	}
	return nil
}

func (rs *RevocationStorage) RevocationSetRecords(b *BaseRequest) error {
	if len(b.Revocation) == 0 {
		return nil
	}
	b.RevocationUpdates = make(map[CredentialTypeIdentifier][]*Record, len(b.Revocation))
	for _, credid := range b.Revocation {
		db, err := rs.RevocationDB(credid)
		if err != nil {
			return err
		}
		if err = rs.revocationUpdateDelayed(credid, db); err != nil {
			return err
		}
		b.RevocationUpdates[credid], err = db.LatestRecords(revocationUpdateCount)
		if err != nil {
			return err
		}
	}
	return nil
}

func (rs *RevocationStorage) RevocationUpdateDB(credid CredentialTypeIdentifier) error {
	db, err := rs.RevocationDB(credid)
	if err != nil {
		return err
	}
	var index uint64
	if db.Enabled() {
		index = db.Current.Index + 1
	}
	records, err := rs.RevocationGetUpdates(credid, index)
	if err != nil {
		return err
	}
	return db.AddRecords(records)
}

func (rs *RevocationStorage) RevocationDB(credid CredentialTypeIdentifier) (*DB, error) {
	if _, known := rs.conf.CredentialTypes[credid]; !known {
		return nil, errors.New("unknown credential type")
	}
	if rs.dbs == nil {
		rs.dbs = make(map[CredentialTypeIdentifier]*DB)
	}
	if rs.dbs[credid] == nil {
		var err error
		db, err := rs.LoadDB(credid)
		if err != nil {
			return nil, err
		}
		rs.dbs[credid] = db
	}
	return rs.dbs[credid], nil
}

func (rs *RevocationStorage) revocationUpdateDelayed(credid CredentialTypeIdentifier, db *DB) error {
	if db.Updated.Before(time.Now().Add(-5 * time.Minute)) {
		if err := rs.RevocationUpdateDB(credid); err != nil {
			return err
		}
	}
	return nil
}

func (rs *RevocationStorage) SendRevocationIssuanceRecord(
	cred CredentialTypeIdentifier, rec *IssuanceRecord,
) error {
	credtype := rs.conf.CredentialTypes[cred]
	if credtype == nil {
		return errors.New("unknown credential type")
	}
	if credtype.RevocationServer == "" {
		return errors.New("credential type has no revocation server")
	}
	sk, err := rs.conf.PrivateKey(cred.IssuerIdentifier())
	if err != nil {
		return err
	}
	if sk == nil {
		return errors.New("private key not found")
	}
	revsk, err := sk.RevocationKey()
	if err != nil {
		return err
	}

	message, err := signed.MarshalSign(revsk.ECDSA, rec)
	if err != nil {
		return err
	}
	return NewHTTPTransport(credtype.RevocationServer).Post(
		fmt.Sprintf("-/revocation/issuancerecord/%s/%d", cred, sk.Counter), nil, []byte(message),
	)
}

func (rs *RevocationStorage) Revoke(credid CredentialTypeIdentifier, key string) error {
	sk, err := rs.conf.PrivateKey(credid.IssuerIdentifier())
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

	db, err := rs.RevocationDB(credid)
	if err != nil {
		return err
	}
	return db.Revoke(rsk, []byte(key))
}

func (rs *RevocationStorage) Close() error {
	merr := &multierror.Error{}
	var err error
	for _, db := range rs.dbs {
		if err = db.Close(); err != nil {
			merr = multierror.Append(merr, err)
		}
	}
	rs.dbs = nil
	return merr.ErrorOrNil()
}
