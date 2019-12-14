package irma

import (
	"database/sql/driver"
	"fmt"
	"time"

	"github.com/go-errors/errors"
	"github.com/hashicorp/go-multierror"
	"github.com/jinzhu/gorm"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/revocation"
	"github.com/privacybydesign/gabi/signed"

	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type (
	// RevocationStorage stores and retrieves revocation-related data from and to a SQL database,
	// and offers a revocation API for all other irmago code, including a Revoke() method that
	// revokes an earlier issued credential.
	RevocationStorage struct {
		conf     *Configuration
		db       revStorage
		memdb    memRevStorage
		sqlMode  bool
		settings map[CredentialTypeIdentifier]*RevocationSetting

		Keys   RevocationKeys
		client RevocationClient
	}

	// RevocationClient offers an HTTP client to the revocation server endpoints.
	RevocationClient struct {
		Conf *Configuration
	}

	// RevocationKeys contains helper functions for retrieving revocation private and public keys
	// from an irma.Configuration instance.
	RevocationKeys struct {
		Conf *Configuration
	}

	// RevocationSetting contains revocation settings for a given credential type.
	RevocationSetting struct {
		Mode                     RevocationMode `json:"mode" mapstructure:"mode"`
		PostURLs                 []string       `json:"post_urls" mapstructure:"post_urls"`
		ServerURL                string         `json:"server_url" mapstructure:"server_url"`
		MaxNonrevocationDuration uint           `json:"max_nonrev_duration" mapstructure:"max_nonrev_duration"` // in seconds, min 30

		// set to now whenever a new update is received, or when the RA indicates
		// there are no new updates. Thus it specifies up to what time our nonrevocation
		// guarantees lasts.
		updated time.Time
	}

	// RevocationMode specifies for a given credential type what revocation operations are
	// supported, and how the associated data is stored (SQL or memory).
	RevocationMode string
)

// Structs corresponding to SQL table rows, ending in Record
type (
	// signedMessage is a signed.Message with DB (un)marshaling methods.
	signedMessage signed.Message
	// RevocationAttribute is a big.Int with DB (un)marshaling methods.
	RevocationAttribute big.Int
	// eventHash is a revocation.Hash with DB (un)marshaling methods.
	eventHash revocation.Hash

	AccumulatorRecord struct {
		CredType CredentialTypeIdentifier `gorm:"primary_key"`
		Data     signedMessage
		PKIndex  uint
	}

	EventRecord struct {
		Index      uint64                   `gorm:"primary_key;column:eventindex"`
		CredType   CredentialTypeIdentifier `gorm:"primary_key"`
		E          *RevocationAttribute
		ParentHash eventHash
	}

	// IssuanceRecord contains information generated during issuance, needed for later revocation.
	IssuanceRecord struct {
		Key        string                   `gorm:"primary_key;column:revocationkey"`
		CredType   CredentialTypeIdentifier `gorm:"primary_key"`
		Attr       *RevocationAttribute
		Issued     int64
		ValidUntil int64
		RevokedAt  int64 // 0 if not currently revoked
	}

	// TODO
	TimeRecord struct {
		Index      uint64
		Start, End int64
	}
)

const (
	// RevocationModeRequestor is the default revocation mode in which only RevocationRecord instances
	// are consumed for issuance or verification. Uses an in-memory store.
	RevocationModeRequestor RevocationMode = ""

	// RevocationModeProxy indicates that this server
	// (1) allows fetching of revocation update messages from its database,
	// (2) relays all revocation updates it receives to the URLs configured in the containing
	// RevocationSetting struct.
	// Requires a SQL server to store and retrieve update messages from.
	RevocationModeProxy RevocationMode = "proxy"

	// RevocationModeServer indicates that this is a revocation server for a credential type.
	// IssuanceRecord instances are sent to this server, as well as revocation commands, through
	// revocation sessions or through the RevocationStorage.Revoke() method.
	// Requires a SQL server to store and retrieve all records from and requires the issuer's
	// private key to be accessible, in order to revoke and to sign new revocation update messages.
	// In addition this mode exposes the same endpoints as RevocationModeProxy.
	RevocationModeServer RevocationMode = "server"

	// revocationUpdateCount specifies how many revocation events are attached to session requests
	// for the client to update its revocation state.
	revocationUpdateCount = 5

	// revocationMaxAccumulatorAge is the default maximum in seconds for the 'accumulator age',
	// which we define to be the amount of time since the last confirmation from the RA that the
	// latest accumulator that we know is still the latest one: clients should prove nonrevocation
	// against a 'younger' accumulator.
	revocationMaxAccumulatorAge uint = 5 * 60
)

// EnableRevocation creates an initial accumulator for a given credential type. This function is the
// only way to create such an initial accumulator and it must be called before anyone can use
// revocation for this credential type. Requires the issuer private key.
func (rs *RevocationStorage) EnableRevocation(typ CredentialTypeIdentifier, sk *revocation.PrivateKey) error {
	hasRecords, err := rs.db.HasRecords(typ, (*EventRecord)(nil))
	if err != nil {
		return err
	}
	if hasRecords {
		return errors.New("revocation event record table not empty")
	}

	update, err := revocation.NewAccumulator(sk)
	if err != nil {
		return err
	}

	if err = rs.addUpdate(rs.db, typ, update, true); err != nil {
		return err
	}
	return nil
}

// RevocationEnabled returns whether or not revocation is enabled for the given credential type,
// by checking if any revocation record exists in the database.
func (rs *RevocationStorage) RevocationEnabled(typ CredentialTypeIdentifier) (bool, error) {
	if rs.sqlMode {
		return rs.db.HasRecords(typ, (*EventRecord)(nil))
	} else {
		return rs.memdb.HasRecords(typ), nil
	}
}

// Revocation update message methods

// UpdateFrom returns all records that a client requires to update its revocation state if it is currently
// at the specified index, that is, all records whose end index is greater than or equal to
// the specified index.
func (rs *RevocationStorage) UpdateFrom(typ CredentialTypeIdentifier, index uint64) (*revocation.Update, error) {
	// Only requires SQL implementation
	var update *revocation.Update
	if err := rs.db.Transaction(func(tx revStorage) error {
		acc, _, err := rs.currentAccumulator(tx, typ)
		if err != nil {
			return err
		}
		var events []*EventRecord
		if err := tx.From(typ, "index", index, &events); err != nil {
			return err
		}
		update = rs.newUpdate(acc, events)
		return nil
	}); err != nil {
		return nil, err
	}
	return update, nil
}

func (rs *RevocationStorage) UpdateLatest(typ CredentialTypeIdentifier, count uint64) (*revocation.Update, error) {
	// TODO what should this function and UpdateFrom return when no records are found?
	if rs.sqlMode {
		var update *revocation.Update
		if err := rs.db.Transaction(func(tx revStorage) error {
			acc, _, err := rs.currentAccumulator(tx, typ)
			if err != nil {
				return err
			}
			var events []*EventRecord
			if err := tx.Latest(typ, "eventindex", count, &events); err != nil {
				return err
			}
			update = rs.newUpdate(acc, events)
			return nil
		}); err != nil {
			return nil, err
		}
		return update, nil
	} else {
		return rs.memdb.Latest(typ, count), nil
	}
}

func (*RevocationStorage) newUpdate(acc *revocation.SignedAccumulator, events []*EventRecord) *revocation.Update {
	updates := make([]*revocation.Event, len(events))
	for i := range events {
		updates[i] = events[i].Event()
	}
	return &revocation.Update{
		SignedAccumulator: acc,
		Events:            updates,
	}
}

func (rs *RevocationStorage) AddUpdate(typ CredentialTypeIdentifier, record *revocation.Update) error {
	return rs.addUpdate(rs.db, typ, record, false)
}

func (rs *RevocationStorage) addUpdate(tx revStorage, typ CredentialTypeIdentifier, update *revocation.Update, create bool) error {
	// Unmarshal and verify the record against the appropriate public key
	pk, err := rs.Keys.PublicKey(typ.IssuerIdentifier(), update.SignedAccumulator.PKIndex)
	if err != nil {
		return err
	}
	if _, _, err = update.Verify(pk, 0); err != nil {
		return err
	}

	// Save record
	if rs.sqlMode {
		save := tx.Save
		if create {
			save = tx.Insert
		}
		if err = save(new(AccumulatorRecord).Convert(typ, update.SignedAccumulator)); err != nil {
			return err
		}
		for _, event := range update.Events {
			if err = tx.Insert(new(EventRecord).Convert(typ, event)); err != nil {
				return err
			}
		}
	} else {
		rs.memdb.Insert(typ, update)
	}

	s := rs.getSettings(typ)
	s.updated = time.Now()
	// POST record to listeners, if any, asynchroniously
	go rs.client.PostUpdate(typ, s.PostURLs, update)

	return nil
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

// Revoke revokes the credential specified by key if found within the current database,
// by updating its revocation time to now, removing its revocation attribute from the current accumulator,
// and updating the revocation database on disk.
func (rs *RevocationStorage) Revoke(typ CredentialTypeIdentifier, key string, sk *revocation.PrivateKey) error {
	if rs.getSettings(typ).Mode != RevocationModeServer {
		return errors.Errorf("cannot revoke %s", typ)
	}

	return rs.db.Transaction(func(tx revStorage) error {
		var err error
		issrecord := IssuanceRecord{}
		if err = tx.Get(typ, "revocationkey", key, &issrecord); err != nil {
			return err
		}
		issrecord.RevokedAt = time.Now().UnixNano()
		if err = tx.Save(&issrecord); err != nil {
			return err
		}
		return rs.revokeAttr(tx, typ, sk, issrecord.Attr)
	})
}

func (rs *RevocationStorage) revokeAttr(tx revStorage, typ CredentialTypeIdentifier, sk *revocation.PrivateKey, e *RevocationAttribute) error {
	_, cur, err := rs.currentAccumulator(tx, typ)
	if err != nil {
		return err
	}
	if cur == nil {
		return errors.Errorf("cannot revoke for type %s, not enabled yet", typ)
	}
	var parent EventRecord
	if err = rs.db.Last(typ, &parent); err != nil {
		return err
	}

	update, err := cur.Remove(sk, (*big.Int)(e), parent.Event())
	if err != nil {
		return err
	}
	if err = rs.addUpdate(tx, typ, update, false); err != nil {
		return err
	}
	return nil
}

// Accumulator methods

func (rs *RevocationStorage) currentAccumulator(tx revStorage, typ CredentialTypeIdentifier) (
	*revocation.SignedAccumulator, *revocation.Accumulator, error,
) {
	var err error
	var sacc *revocation.SignedAccumulator
	if rs.sqlMode {
		record := &AccumulatorRecord{}
		if err = tx.Last(typ, record); err != nil {
			if gorm.IsRecordNotFoundError(err) {
				return nil, nil, nil
			}
		}
		sacc = record.SignedAccumulator()
	} else {
		u := rs.memdb.Latest(typ, 0)
		if u == nil {
			return nil, nil, nil
		}
		sacc = u.SignedAccumulator
	}

	pk, err := rs.Keys.PublicKey(typ.IssuerIdentifier(), sacc.PKIndex)
	if err != nil {
		return nil, nil, err
	}
	acc, err := sacc.UnmarshalVerify(pk)
	if err != nil {
		return nil, nil, err
	}
	return sacc, acc, nil
}

// Methods to update from remote revocation server

func (rs *RevocationStorage) UpdateDB(typ CredentialTypeIdentifier) error {
	update, err := rs.client.FetchUpdateLatest(typ, revocationUpdateCount)
	if err != nil {
		return err
	}

	if err = rs.AddUpdate(typ, update); err != nil {
		return err
	}

	// bump updated even if no new records were added
	rs.getSettings(typ).updated = time.Now()
	return nil
}

func (rs *RevocationStorage) UpdateIfOld(typ CredentialTypeIdentifier) error {
	settings := rs.getSettings(typ)
	// update 10 seconds before the maximum, to stay below it
	if settings.updated.Before(time.Now().Add(time.Duration(-settings.MaxNonrevocationDuration+10) * time.Second)) {
		if err := rs.UpdateDB(typ); err != nil {
			return err
		}
	}
	return nil
}

// SaveIssuanceRecord either stores the issuance record locally, if we are the revocation server of
// the crecential type, or it signs and sends it to the remote revocation server.
func (rs *RevocationStorage) SaveIssuanceRecord(typ CredentialTypeIdentifier, rec *IssuanceRecord, sk *gabi.PrivateKey) error {
	credtype := rs.conf.CredentialTypes[typ]
	if credtype == nil {
		return errors.New("unknown credential type")
	}
	if !credtype.SupportsRevocation() {
		return errors.New("cannot save issuance record: credential type does not support revocation")
	}

	// Just store it if we are the revocation server for this credential type
	settings := rs.getSettings(typ)
	if settings.Mode == RevocationModeServer {
		return rs.AddIssuanceRecord(rec)
	}

	// We have to send it, sign it first
	if settings.ServerURL == "" {
		return errors.New("cannot send issuance record: no server_url configured")
	}
	rsk, err := sk.RevocationKey()
	if err != nil {
		return err
	}
	return rs.client.PostIssuanceRecord(typ, rsk, rec, settings.ServerURL)
}

// Misscelaneous methods

func (rs *RevocationStorage) Load(debug bool, dbtype, connstr string, settings map[CredentialTypeIdentifier]*RevocationSetting) error {
	var t *CredentialTypeIdentifier

	for typ, s := range settings {
		switch s.Mode {
		case RevocationModeServer:
			if s.ServerURL != "" {
				return errors.New("server_url cannot be combined with server mode")
			}
			t = &typ
		case RevocationModeProxy:
			t = &typ
		case RevocationModeRequestor: // noop
		default:
			return errors.Errorf(`invalid revocation mode "%s" for %s (supported: "%s", "%s", "%s")`,
				s.Mode, typ, RevocationModeRequestor, RevocationModeServer, RevocationModeProxy)
		}
	}
	if t != nil && connstr == "" {
		return errors.Errorf("revocation mode for %s requires SQL database but no connection string given", *t)
	}

	if connstr == "" {
		Logger.Trace("Using memory revocation database")
		rs.memdb = newMemStorage()
		rs.sqlMode = false
	} else {
		Logger.Trace("Connecting to revocation SQL database")
		db, err := newSqlStorage(debug, dbtype, connstr)
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
	for id, settings := range rs.settings {
		if settings.MaxNonrevocationDuration != 0 && settings.MaxNonrevocationDuration < 30 {
			return errors.Errorf("max_nonrev_duration setting for %s must be at least 30 seconds, was %d",
				id, settings.MaxNonrevocationDuration)
		}
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

// SetRevocationUpdates retrieves the latest revocation records from the database, and attaches
// them to the request, for each credential type for which a nonrevocation proof is requested in
// b.Revocation.
func (rs *RevocationStorage) SetRevocationUpdates(b *BaseRequest) error {
	if len(b.Revocation) == 0 {
		return nil
	}
	var err error
	b.RevocationUpdates = make(map[CredentialTypeIdentifier]*revocation.Update, len(b.Revocation))
	for _, credid := range b.Revocation {
		if !rs.conf.CredentialTypes[credid].SupportsRevocation() {
			return errors.Errorf("cannot request nonrevocation proof for %s: revocation not enabled in scheme")
		}
		if err = rs.UpdateIfOld(credid); err != nil {
			updated := rs.getSettings(credid).updated
			if !updated.IsZero() {
				Logger.Warnf("failed to fetch revocation updates for %s, nonrevocation is guaranteed only until %s ago:",
					credid, time.Now().Sub(updated).String())
				Logger.Warn(err)
			} else {
				Logger.Errorf("revocation is disabled for %s: failed to fetch revocation updates and none are known locally", credid)
				Logger.Warn(err)
				// We can offer no nonrevocation guarantees at all while the requestor explicitly
				// asked for it; fail the session by returning an error
				return err
			}
		}
		b.RevocationUpdates[credid], err = rs.UpdateLatest(credid, revocationUpdateCount)
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
	s := rs.settings[typ]
	if s.MaxNonrevocationDuration == 0 {
		s.MaxNonrevocationDuration = revocationMaxAccumulatorAge
	}
	return s
}

func (client RevocationClient) PostUpdate(typ CredentialTypeIdentifier, urls []string, update *revocation.Update) {
	transport := NewHTTPTransport("")
	transport.Binary = true
	for _, url := range urls {
		err := transport.Post(fmt.Sprintf("%s/revocation/update/%s", url, typ.String()), nil, update)
		if err != nil {
			Logger.Warn("error sending revocation update", err)
		}
	}
}

func (client RevocationClient) PostIssuanceRecord(typ CredentialTypeIdentifier, sk *revocation.PrivateKey, rec *IssuanceRecord, url string) error {
	message, err := signed.MarshalSign(sk.ECDSA, rec)
	if err != nil {
		return err
	}
	return NewHTTPTransport(url).Post(
		fmt.Sprintf("revocation/issuancerecord/%s/%d", typ, sk.Counter), nil, []byte(message),
	)
}

// FetchRevocationRecords gets revocation update messages from the revocation server, of the specified index and greater.
func (client RevocationClient) FetchUpdateFrom(typ CredentialTypeIdentifier, index uint64) (*revocation.Update, error) {
	return client.fetchUpdate(typ, "updatefrom", index)
}

func (client RevocationClient) FetchUpdateLatest(typ CredentialTypeIdentifier, count uint64) (*revocation.Update, error) {
	return client.fetchUpdate(typ, "updatelatest", count)
}

func (client RevocationClient) fetchUpdate(typ CredentialTypeIdentifier, u string, i uint64) (*revocation.Update, error) {
	var (
		err       error
		errs      multierror.Error
		update    = &revocation.Update{}
		transport = NewHTTPTransport("")
	)
	transport.Binary = true
	for _, url := range client.Conf.CredentialTypes[typ].RevocationServers {
		transport.Server = url
		err = transport.Get(fmt.Sprintf("revocation/%s/%s/%d", u, typ, i), &update)
		if err == nil {
			return update, nil
		} else {
			errs.Errors = append(errs.Errors, err)
		}
	}
	return nil, errors.WrapPrefix(errs, "failed to download revocation update", 0)
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

// Conversion methods to/from database structs, SQL table rows, gob

func (e *EventRecord) Event() *revocation.Event {
	return &revocation.Event{
		Index:      e.Index,
		E:          (*big.Int)(e.E),
		ParentHash: revocation.Hash(e.ParentHash),
	}
}

func (e *EventRecord) Convert(typ CredentialTypeIdentifier, event *revocation.Event) *EventRecord {
	*e = EventRecord{
		Index:      event.Index,
		E:          (*RevocationAttribute)(event.E),
		ParentHash: eventHash(event.ParentHash),
		CredType:   typ,
	}
	return e
}

func (a *AccumulatorRecord) SignedAccumulator() *revocation.SignedAccumulator {
	return &revocation.SignedAccumulator{
		PKIndex: a.PKIndex,
		Data:    signed.Message(a.Data),
	}
}

func (a *AccumulatorRecord) Convert(typ CredentialTypeIdentifier, sacc *revocation.SignedAccumulator) *AccumulatorRecord {
	*a = AccumulatorRecord{
		Data:     signedMessage(sacc.Data),
		PKIndex:  sacc.PKIndex,
		CredType: typ,
	}
	return a
}

func (signedMessage) GormDataType(dialect gorm.Dialect) string {
	switch dialect.GetName() {
	case "postgres":
		return "bytea"
	case "mysql":
		return "blob"
	default:
		return ""
	}
}

// Value implements driver.Valuer, for SQL marshaling (to []byte).
func (i *RevocationAttribute) Value() (driver.Value, error) {
	return (*big.Int)(i).Bytes(), nil
}

// Scan implements sql.Scanner, for SQL unmarshaling (from a []byte).
func (i *RevocationAttribute) Scan(src interface{}) error {
	b, ok := src.([]byte)
	if !ok {
		return errors.New("cannot convert source: not a byte slice")
	}
	(*big.Int)(i).SetBytes(b)
	return nil
}

func (RevocationAttribute) GormDataType(dialect gorm.Dialect) string {
	switch dialect.GetName() {
	case "postgres":
		return "bytea"
	case "mysql":
		return "blob"
	default:
		return ""
	}
}

func (i *RevocationAttribute) GobEncode() ([]byte, error) {
	return MarshalBinary((*big.Int)(i))
}

func (i *RevocationAttribute) GobDecode(data []byte) error {
	return UnmarshalBinary(data, (*big.Int)(i))
}

func (hash eventHash) Value() (driver.Value, error) {
	return []byte(hash), nil
}

func (hash *eventHash) Scan(src interface{}) error {
	s, ok := src.([]byte)
	if !ok {
		return errors.New("cannot convert source: not a []byte")
	}
	*hash = make([]byte, len(s))
	copy(*hash, s)
	return nil
}

func (eventHash) GormDataType(dialect gorm.Dialect) string {
	switch dialect.GetName() {
	case "postgres":
		return "bytea"
	case "mysql":
		return "blob"
	default:
		return ""
	}
}
