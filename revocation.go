package irma

import (
	"database/sql/driver"
	"fmt"
	"sort"
	"time"

	"github.com/fxamacker/cbor"
	"github.com/getsentry/raven-go"
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
		sqldb    sqlRevStorage
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
		Mode                RevocationMode `json:"mode" mapstructure:"mode"`
		PostURLs            []string       `json:"post_urls" mapstructure:"post_urls"`
		RevocationServerURL string         `json:"revocation_server_url" mapstructure:"revocation_server_url"`
		Tolerance           uint           `json:"tolerance" mapstructure:"tolerance"` // in seconds, min 30

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
		CredType  CredentialTypeIdentifier `gorm:"primary_key"`
		Data      signedMessage
		PKCounter uint `gorm:"primary_key;auto_increment:false"`
	}

	EventRecord struct {
		Index      uint64                   `gorm:"primary_key;column:eventindex"`
		CredType   CredentialTypeIdentifier `gorm:"primary_key"`
		PKCounter  uint                     `gorm:"primary_key;auto_increment:false"`
		E          *RevocationAttribute
		ParentHash eventHash
	}

	// IssuanceRecord contains information generated during issuance, needed for later revocation.
	IssuanceRecord struct {
		Key        string                   `gorm:"primary_key;column:revocationkey"`
		CredType   CredentialTypeIdentifier `gorm:"primary_key"`
		Issued     int64                    `gorm:"primary_key;auto_increment:false"`
		PKCounter  uint
		Attr       *RevocationAttribute
		ValidUntil int64
		RevokedAt  int64 `json:",omitempty"` // 0 if not currently revoked
	}
)

const (
	// RevocationModeRequestor is the default revocation mode in which only RevocationRecord instances
	// are consumed for issuance or verification. Uses an in-memory store.
	RevocationModeRequestor RevocationMode = ""
	revocationModeRequestor RevocationMode = "requestor" // synonym for RevocationModeRequestor

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

	// RevocationDefaultUpdateEventCount specifies how many revocation events are attached to session requests
	// for the client to update its revocation state.
	RevocationDefaultUpdateEventCount = 10

	// RevocationRequestorUpdateInterval is the time period in minutes for requestor servers
	// updating their revocation state at th RA.
	RevocationRequestorUpdateInterval uint64 = 5

	// revocationDefaultTolerance is the default tolerance in seconds: nonrevocation should be proved
	// by clients up to maximally this amount of seconds ago at verification time. If not, the
	// server will report the time up until nonrevocation of the attribute is guaranteed to the requestor.
	revocationDefaultTolerance uint = 5 * 60

	// If server mode is enabled for a credential type, then once every so many seconds
	// the timestamp in each accumulator is updated to now.
	revocationAccumulatorUpdateInterval uint64 = 60

	// DELETE issuance records of expired credential every so many minutes
	revocationDeleteIssuanceRecordsInterval uint64 = 300
)

// EnableRevocation creates an initial accumulator for a given credential type. This function is the
// only way to create such an initial accumulator and it must be called before anyone can use
// revocation for this credential type. Requires the issuer private key.
func (rs *RevocationStorage) EnableRevocation(typ CredentialTypeIdentifier, sk *revocation.PrivateKey) error {
	enabled, err := rs.Exists(typ, sk.Counter)
	if err != nil {
		return err
	}
	if enabled {
		return errors.New("revocation already enabled")
	}

	update, err := revocation.NewAccumulator(sk)
	if err != nil {
		return err
	}

	if err = rs.addUpdate(rs.sqldb, typ, update, true); err != nil {
		return err
	}
	return nil
}

// Exists returns whether or not an accumulator exists in the database for the given credential type.
func (rs *RevocationStorage) Exists(typ CredentialTypeIdentifier, counter uint) (bool, error) {
	// only requires sql implementation
	return rs.sqldb.Exists((*AccumulatorRecord)(nil), map[string]interface{}{"cred_type": typ, "pk_counter": counter})
}

// Revocation update message methods

// UpdateFrom returns all records that a client requires to update its revocation state if it is currently
// at the specified index, that is, all records whose end index is greater than or equal to
// the specified index.
func (rs *RevocationStorage) UpdateFrom(typ CredentialTypeIdentifier, pkcounter uint, index uint64) (*revocation.Update, error) {
	// Only requires SQL implementation
	var update *revocation.Update
	if err := rs.sqldb.Transaction(func(tx sqlRevStorage) error {
		acc, err := rs.accumulator(tx, typ, pkcounter)
		if err != nil {
			return err
		}
		var events []*EventRecord
		if err := tx.Find(&events, "cred_type = ? and pk_counter = ? and eventindex >= ?", typ, pkcounter, index); err != nil {
			return err
		}
		update = rs.newUpdate(acc, events)
		return nil
	}); err != nil {
		return nil, err
	}
	return update, nil
}

func (rs *RevocationStorage) UpdateLatest(typ CredentialTypeIdentifier, count uint64) (map[uint]*revocation.Update, error) {
	// TODO what should this function and UpdateFrom return when no records are found?
	if rs.sqlMode {
		var update map[uint]*revocation.Update
		if err := rs.sqldb.Transaction(func(tx sqlRevStorage) error {
			var (
				records []*AccumulatorRecord
				events  []*EventRecord
			)
			if err := tx.Last(&records, map[string]interface{}{"cred_type": typ}); err != nil {
				return err
			}
			if err := tx.Latest(&events, count, map[string]interface{}{"cred_type": typ}); err != nil {
				return err
			}
			update = rs.newUpdates(records, events)
			return nil
		}); err != nil {
			return nil, err
		}
		return update, nil
	} else {
		return rs.memdb.Latest(typ, count), nil
	}
}

func (*RevocationStorage) newUpdates(records []*AccumulatorRecord, events []*EventRecord) map[uint]*revocation.Update {
	accs := map[uint]*revocation.SignedAccumulator{}
	for _, r := range records {
		accs[r.PKCounter] = r.SignedAccumulator()
	}
	updates := make(map[uint]*revocation.Update, len(accs))
	for _, e := range events {
		i := e.PKCounter
		if accs[i] == nil {
			continue
		}
		update, present := updates[i]
		if !present {
			update = &revocation.Update{SignedAccumulator: accs[i]}
			updates[i] = update
		}
		update.Events = append(update.Events, e.Event())
	}
	for _, update := range updates {
		sort.Slice(update.Events, func(i, j int) bool {
			return update.Events[i].Index < update.Events[j].Index
		})
	}
	return updates
}

func (rs *RevocationStorage) newUpdate(acc *revocation.SignedAccumulator, events []*EventRecord) *revocation.Update {
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
	return rs.addUpdate(rs.sqldb, typ, record, false)
}

func (rs *RevocationStorage) addUpdate(tx sqlRevStorage, typ CredentialTypeIdentifier, update *revocation.Update, create bool) error {
	// Unmarshal and verify the record against the appropriate public key
	pk, err := rs.Keys.PublicKey(typ.IssuerIdentifier(), update.SignedAccumulator.PKCounter)
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
			if err = tx.Insert(new(EventRecord).Convert(typ, update.SignedAccumulator.PKCounter, event)); err != nil {
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

func (rs *RevocationStorage) AddIssuanceRecord(r *IssuanceRecord) error {
	return rs.sqldb.Insert(r)
}

func (rs *RevocationStorage) IssuanceRecords(typ CredentialTypeIdentifier, key string, issued time.Time) ([]*IssuanceRecord, error) {
	where := map[string]interface{}{"cred_type": typ, "revocationkey": key, "revoked_at": 0}
	if !issued.IsZero() {
		where["Issued"] = issued.UnixNano()
	}
	var r []*IssuanceRecord
	err := rs.sqldb.Find(&r, where)
	if err != nil {
		return nil, err
	}
	if len(r) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return r, nil
}

// Revocation methods

// Revoke revokes the credential(s) specified by key and issued, if found within the current database,
// by updating their revocation time to now, removing their revocation attribute from the current accumulator,
// and updating the revocation database on disk.
// If issued is not specified, i.e. passed the zero value, all credentials specified by key are revoked.
func (rs *RevocationStorage) Revoke(typ CredentialTypeIdentifier, key string, issued time.Time) error {
	if rs.getSettings(typ).Mode != RevocationModeServer {
		return errors.Errorf("cannot revoke %s", typ)
	}
	return rs.sqldb.Transaction(func(tx sqlRevStorage) error {
		return rs.revoke(tx, typ, key, issued)
	})
}

func (rs *RevocationStorage) revoke(tx sqlRevStorage, typ CredentialTypeIdentifier, key string, issued time.Time) error {
	var err error
	issrecords, err := rs.IssuanceRecords(typ, key, issued)
	if err != nil {
		return err
	}

	// get all relevant accumulators and events from the database
	accs, events, err := rs.revokeReadRecords(tx, typ, issrecords)

	// For each issuance record, perform revocation, adding an Event and advancing the accumulator
	for _, issrecord := range issrecords {
		e := events[issrecord.PKCounter]
		newacc, event, err := rs.revokeCredential(tx, issrecord, accs[issrecord.PKCounter], e[len(e)-1])
		accs[issrecord.PKCounter] = newacc
		if err != nil {
			return err
		}
		events[issrecord.PKCounter] = append(e, event)
	}

	// Gather accumulators and update events per key counter into revocation updates,
	// and add them to the database
	for counter := range accs {
		sk, err := rs.Keys.PrivateKey(typ.IssuerIdentifier(), counter)
		if err != nil {
			return err
		}
		// exclude parent event from the events
		update, err := revocation.NewUpdate(sk, accs[counter], events[counter][1:])
		if err != nil {
			return err
		}
		if err = rs.addUpdate(tx, typ, update, false); err != nil {
			return err
		}
	}

	return nil
}

func (rs *RevocationStorage) revokeReadRecords(
	tx sqlRevStorage,
	typ CredentialTypeIdentifier,
	issrecords []*IssuanceRecord,
) (map[uint]*revocation.Accumulator, map[uint][]*revocation.Event, error) {
	// gather all keys used in the issuance requests
	var keycounters []uint
	for _, issrecord := range issrecords {
		keycounters = append(keycounters, issrecord.PKCounter)
	}

	// get all relevant accumulators from the database
	var records []AccumulatorRecord
	if err := tx.Find(&records, "cred_type = ? and pk_counter in (?)", typ, keycounters); err != nil {
		return nil, nil, err
	}
	var eventrecords []EventRecord
	err := tx.Find(&eventrecords, "eventindex = (?)", tx.gorm.
		Table("event_records e2").
		Select("max(e2.eventindex)").
		Where("e2.cred_type = event_records.cred_type and e2.pk_counter = event_records.pk_counter").
		QueryExpr(),
	)
	if err != nil {
		return nil, nil, err
	}

	accs := map[uint]*revocation.Accumulator{}
	events := map[uint][]*revocation.Event{}
	for _, r := range records {
		sacc := r.SignedAccumulator()
		pk, err := rs.Keys.PublicKey(typ.IssuerIdentifier(), sacc.PKCounter)
		if err != nil {
			return nil, nil, err
		}
		accs[r.PKCounter], err = sacc.UnmarshalVerify(pk)
		if err != nil {
			return nil, nil, err
		}
	}
	for _, e := range eventrecords {
		events[e.PKCounter] = append(events[e.PKCounter], e.Event())
	}
	return accs, events, nil
}

func (rs *RevocationStorage) revokeCredential(
	tx sqlRevStorage,
	issrecord *IssuanceRecord,
	acc *revocation.Accumulator,
	parent *revocation.Event,
) (*revocation.Accumulator, *revocation.Event, error) {
	issrecord.RevokedAt = time.Now().UnixNano()
	if err := tx.Save(&issrecord); err != nil {
		return nil, nil, err
	}
	sk, err := rs.Keys.PrivateKey(issrecord.CredType.IssuerIdentifier(), issrecord.PKCounter)
	if err != nil {
		return nil, nil, err
	}
	newacc, event, err := acc.Remove(sk, (*big.Int)(issrecord.Attr), parent)
	if err != nil {
		return nil, nil, err
	}
	return newacc, event, nil
}

// Accumulator methods

func (rs *RevocationStorage) Accumulator(typ CredentialTypeIdentifier, pkcounter uint) (
	*revocation.SignedAccumulator, error,
) {
	return rs.accumulator(rs.sqldb, typ, pkcounter)
}

// accumulator retrieves, verifies and deserializes the accumulator of the given type and key.
func (rs *RevocationStorage) accumulator(tx sqlRevStorage, typ CredentialTypeIdentifier, pkcounter uint) (
	*revocation.SignedAccumulator, error,
) {
	var err error
	var sacc *revocation.SignedAccumulator
	if rs.sqlMode {
		record := &AccumulatorRecord{}
		if err = tx.Last(record, map[string]interface{}{"cred_type": typ, "pk_counter": pkcounter}); err != nil {
			if gorm.IsRecordNotFoundError(err) {
				return nil, nil
			}
		}
		sacc = record.SignedAccumulator()
	} else {
		sacc = rs.memdb.SignedAccumulator(typ, pkcounter)
		if sacc == nil {
			return nil, nil
		}
	}

	pk, err := rs.Keys.PublicKey(typ.IssuerIdentifier(), sacc.PKCounter)
	if err != nil {
		return nil, err
	}
	_, err = sacc.UnmarshalVerify(pk)
	if err != nil {
		return nil, err
	}
	return sacc, nil
}

// Methods to update from remote revocation server

func (rs *RevocationStorage) UpdateDB(typ CredentialTypeIdentifier) error {
	updates, err := rs.client.FetchUpdateLatest(typ, RevocationDefaultUpdateEventCount)
	if err != nil {
		return err
	}
	for _, u := range updates {
		if err = rs.AddUpdate(typ, u); err != nil {
			return err
		}
	}
	// bump updated even if no new records were added
	rs.getSettings(typ).updated = time.Now()
	return nil
}

func (rs *RevocationStorage) UpdateIfOld(typ CredentialTypeIdentifier) error {
	settings := rs.getSettings(typ)
	// update 10 seconds before the maximum, to stay below it
	if settings.updated.Before(time.Now().Add(time.Duration(-settings.Tolerance+10) * time.Second)) {
		Logger.WithField("credtype", typ).Tracef("fetching revocation updates")
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
	if !credtype.RevocationSupported() {
		return errors.New("cannot save issuance record: credential type does not support revocation")
	}

	// Just store it if we are the revocation server for this credential type
	settings := rs.getSettings(typ)
	if settings.Mode == RevocationModeServer {
		return rs.AddIssuanceRecord(rec)
	}

	// We have to send it, sign it first
	if settings.RevocationServerURL == "" {
		return errors.New("cannot send issuance record: no server_url configured")
	}
	rsk, err := sk.RevocationKey()
	if err != nil {
		return err
	}
	return rs.client.PostIssuanceRecord(typ, rsk, rec, settings.RevocationServerURL)
}

// Misscelaneous methods

func (rs *RevocationStorage) updateAccumulatorTimes(types []CredentialTypeIdentifier) error {
	return rs.sqldb.Transaction(func(tx sqlRevStorage) error {
		var err error
		var records []AccumulatorRecord
		Logger.Tracef("updating accumulator times")
		if err = tx.Find(&records, "cred_type in (?)", types); err != nil {
			return err
		}
		for _, r := range records {
			pk, err := rs.Keys.PublicKey(r.CredType.IssuerIdentifier(), r.PKCounter)
			if err != nil {
				return err
			}
			sk, err := rs.Keys.PrivateKey(r.CredType.IssuerIdentifier(), r.PKCounter)
			if err != nil {
				return err
			}
			acc, err := r.SignedAccumulator().UnmarshalVerify(pk)
			if err != nil {
				return err
			}
			acc.Time = time.Now().Unix()
			sacc, err := acc.Sign(sk)
			if err != nil {
				return err
			}
			r.Data = signedMessage(sacc.Data)
			if err = tx.Save(r); err != nil {
				return err
			}

			s := rs.getSettings(r.CredType)
			s.updated = time.Now()
			// POST record to listeners, if any, asynchroniously
			go rs.client.PostUpdate(r.CredType, s.PostURLs, &revocation.Update{SignedAccumulator: sacc})
		}
		return nil
	})
}

func (rs *RevocationStorage) Load(debug bool, dbtype, connstr string, settings map[CredentialTypeIdentifier]*RevocationSetting) error {
	var t *CredentialTypeIdentifier
	var ourtypes []CredentialTypeIdentifier
	for typ, s := range settings {
		switch s.Mode {
		case RevocationModeServer:
			if s.RevocationServerURL != "" {
				return errors.New("server_url cannot be combined with server mode")
			}
			ourtypes = append(ourtypes, typ)
			t = &typ
		case RevocationModeProxy:
			t = &typ
		case RevocationModeRequestor: // noop
		case revocationModeRequestor:
			s.Mode = RevocationModeRequestor
		default:
			return errors.Errorf(`invalid revocation mode "%s" for %s (supported: "%s" (or empty string), "%s", "%s")`,
				s.Mode, typ, revocationModeRequestor, RevocationModeServer, RevocationModeProxy)
		}
	}
	if t != nil && connstr == "" {
		return errors.Errorf("revocation mode for %s requires SQL database but no connection string given", *t)
	}

	if len(ourtypes) > 0 {
		rs.conf.Scheduler.Every(revocationAccumulatorUpdateInterval).Seconds().Do(func() {
			if err := rs.updateAccumulatorTimes(ourtypes); err != nil {
				err = errors.WrapPrefix(err, "failed to write updated accumulator record", 0)
				raven.CaptureError(err, nil)
			}
		})
	}
	rs.conf.Scheduler.Every(revocationDeleteIssuanceRecordsInterval).Minutes().Do(func() {
		if !rs.sqlMode {
			return
		}
		if err := rs.sqldb.Delete(IssuanceRecord{}, "valid_until < ?", time.Now().UnixNano()); err != nil {
			err = errors.WrapPrefix(err, "failed to delete expired issuance records", 0)
			raven.CaptureError(err, nil)
		}
	})

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
		rs.sqldb = db
		rs.sqlMode = true
	}
	if settings != nil {
		rs.settings = settings
	} else {
		rs.settings = map[CredentialTypeIdentifier]*RevocationSetting{}
	}
	for id, settings := range rs.settings {
		if settings.Tolerance != 0 && settings.Tolerance < 30 {
			return errors.Errorf("max_nonrev_duration setting for %s must be at least 30 seconds, was %d",
				id, settings.Tolerance)
		}
	}
	rs.client = RevocationClient{Conf: rs.conf}
	rs.Keys = RevocationKeys{Conf: rs.conf}
	return nil
}

func (rs *RevocationStorage) Close() error {
	return rs.sqldb.Close()
}

// SetRevocationUpdates retrieves the latest revocation records from the database, and attaches
// them to the request, for each credential type for which a nonrevocation proof is requested in
// b.Revocation.
func (rs *RevocationStorage) SetRevocationUpdates(b *BaseRequest) error {
	if len(b.Revocation) == 0 {
		return nil
	}
	var err error
	b.RevocationUpdates = make(map[CredentialTypeIdentifier]map[uint]*revocation.Update, len(b.Revocation))
	for _, credid := range b.Revocation {
		if !rs.conf.CredentialTypes[credid].RevocationSupported() {
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
		b.RevocationUpdates[credid], err = rs.UpdateLatest(credid, RevocationDefaultUpdateEventCount)
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
	if s.Tolerance == 0 {
		s.Tolerance = revocationDefaultTolerance
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
func (client RevocationClient) FetchUpdateFrom(typ CredentialTypeIdentifier, pkcounter uint, index uint64) (*revocation.Update, error) {
	update := &revocation.Update{}
	return update, client.getMultiple(
		client.Conf.CredentialTypes[typ].RevocationServers,
		fmt.Sprintf("revocation/updatefrom/%s/%d/%d", typ, pkcounter, index),
		&update,
	)
}

func (client RevocationClient) FetchUpdateLatest(typ CredentialTypeIdentifier, count uint64) (map[uint]*revocation.Update, error) {
	update := map[uint]*revocation.Update{}
	return update, client.getMultiple(
		client.Conf.CredentialTypes[typ].RevocationServers,
		fmt.Sprintf("revocation/updatelatest/%s/%d", typ, count),
		&update,
	)
}

func (RevocationClient) getMultiple(urls []string, path string, dest interface{}) error {
	var (
		errs      multierror.Error
		transport = NewHTTPTransport("")
	)
	transport.Binary = true
	for _, url := range urls {
		transport.Server = url
		err := transport.Get(path, dest)
		if err == nil {
			return nil
		} else {
			errs.Errors = append(errs.Errors, err)
		}
	}
	return &errs
}

func (rs RevocationKeys) PrivateKeyLatest(issid IssuerIdentifier) (*revocation.PrivateKey, error) {
	sk, err := rs.Conf.PrivateKeyLatest(issid)
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

func (rs RevocationKeys) PrivateKey(issid IssuerIdentifier, counter uint) (*revocation.PrivateKey, error) {
	sk, err := rs.Conf.PrivateKey(issid, counter)
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
	pk, err := rs.Conf.PublicKey(issid, counter)
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

func (e *EventRecord) Convert(typ CredentialTypeIdentifier, pkcounter uint, event *revocation.Event) *EventRecord {
	*e = EventRecord{
		Index:      event.Index,
		E:          (*RevocationAttribute)(event.E),
		ParentHash: eventHash(event.ParentHash),
		CredType:   typ,
		PKCounter:  pkcounter,
	}
	return e
}

func (a *AccumulatorRecord) SignedAccumulator() *revocation.SignedAccumulator {
	return &revocation.SignedAccumulator{
		PKCounter: a.PKCounter,
		Data:      signed.Message(a.Data),
	}
}

func (a *AccumulatorRecord) Convert(typ CredentialTypeIdentifier, sacc *revocation.SignedAccumulator) *AccumulatorRecord {
	*a = AccumulatorRecord{
		Data:      signedMessage(sacc.Data),
		PKCounter: sacc.PKCounter,
		CredType:  typ,
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

func (i *RevocationAttribute) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*big.Int)(i), cbor.EncOptions{})
}

func (i *RevocationAttribute) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*big.Int)(i))
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
