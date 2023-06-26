package irma

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/bits"
	"strings"
	"sync"
	"time"

	"github.com/alexandrevicenzi/go-sse"
	"github.com/go-errors/errors"
	"github.com/hashicorp/go-multierror"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/revocation"
	"github.com/privacybydesign/gabi/signed"
	sseclient "github.com/sietseringers/go-sse"
)

type (
	// RevocationStorage stores and retrieves revocation-related data from and to a SQL database,
	// and offers a revocation API for all other irmago code, including a Revoke() method that
	// revokes an earlier issued credential.
	RevocationStorage struct {
		conf          *Configuration
		recordStorage revocationRecordStorage
		settings      RevocationSettings

		Keys   RevocationKeys
		client RevocationClient

		ServerSentEvents *sse.Server

		close  chan struct{} // to close sseclient
		events chan *sseclient.Event
	}

	// RevocationClient offers an HTTP client to the revocation server endpoints.
	RevocationClient struct {
		Conf     *Configuration
		Settings RevocationSettings
		http     *HTTPTransport
	}

	// RevocationKeys contains helper functions for retrieving revocation private and public keys
	// from an irma.Configuration instance.
	RevocationKeys struct {
		Conf *Configuration
	}

	// RevocationSetting contains revocation settings for a given credential type.
	RevocationSetting struct {
		Server              bool   `json:"server,omitempty" mapstructure:"server"`
		Authority           bool   `json:"authority,omitempty" mapstructure:"authority"`
		RevocationServerURL string `json:"revocation_server_url,omitempty" mapstructure:"revocation_server_url"`
		Tolerance           uint64 `json:"tolerance,omitempty" mapstructure:"tolerance"` // in seconds, min 30
		SSE                 bool   `json:"sse,omitempty" mapstructure:"sse"`

		// set to now whenever a new update is received, or when the RA indicates
		// there are no new updates. Thus it specifies up to what time our nonrevocation
		// guarantees lasts.
		updated time.Time
	}

	// RevocationSettings specifies per credential type what the revocation settings are.
	RevocationSettings map[CredentialTypeIdentifier]*RevocationSetting
)

var (
	ErrRevocationStateNotFound = errors.New("revocation state not found")
	ErrUnknownRevocationKey    = errors.New("unknown revocationKey")
	ErrorUnknownCredentialType = errors.New("unknown credential type")
)

// RevocationParameters contains global revocation constants and default values.
var RevocationParameters = struct {
	// DefaultUpdateEventCount specifies how many revocation events are attached to session requests
	// for the client to update its revocation state.
	DefaultUpdateEventCount uint64

	// RequestorUpdateInterval is the time period in minutes for requestor servers
	// updating their revocation state at th RA.
	RequestorUpdateInterval int

	// DefaultTolerance is the default tolerance in seconds: nonrevocation should be proved
	// by clients up to maximally this amount of seconds ago at verification time. If not, the
	// server will report the time up until nonrevocation of the attribute is guaranteed to the requestor.
	DefaultTolerance uint64

	// If server mode is enabled for a credential type, then once every so many seconds
	// the timestamp in each accumulator is updated to now.
	AccumulatorUpdateInterval int

	// DELETE issuance records of expired credential every so many minutes
	DeleteIssuanceRecordsInterval int

	// ClientUpdateInterval is the time interval with which the irmaclient periodically
	// retrieves a revocation update from the RA and updates its revocation state with a small but
	// increasing probability.
	ClientUpdateInterval int

	// ClientDefaultUpdateSpeed is the amount of time in hours after which it becomes very likely
	// that the app will update its witness, quickly after it has been opened.
	ClientDefaultUpdateSpeed uint64

	// ClientUpdateTimeout is the amount of time in milliseconds that the irmaclient waits
	// for nonrevocation witness updating to complete, before it continues with the session even
	// if updating is not yet done (in which case the candidate set computed by the client
	// may contain credentials that were revoked by one of the requestor's update messages).
	ClientUpdateTimeout uint64

	// Cache-control: max-age HTTP return header (in seconds)
	EventsCacheMaxAge uint64

	UpdateMinCount      uint64
	UpdateMaxCount      uint64
	UpdateMinCountPower int
	UpdateMaxCountPower int
}{
	RequestorUpdateInterval:       10,
	DefaultTolerance:              10 * 60,
	AccumulatorUpdateInterval:     60,
	DeleteIssuanceRecordsInterval: 5 * 60,
	ClientUpdateInterval:          10,
	ClientDefaultUpdateSpeed:      7 * 24,
	ClientUpdateTimeout:           1000,
	UpdateMinCountPower:           4,
	UpdateMaxCountPower:           9,
	EventsCacheMaxAge:             60 * 60,
}

func init() {
	// compute derived revocation parameters
	RevocationParameters.UpdateMinCount = 1 << RevocationParameters.UpdateMinCountPower
	RevocationParameters.UpdateMaxCount = 1 << RevocationParameters.UpdateMaxCountPower
	RevocationParameters.DefaultUpdateEventCount = RevocationParameters.UpdateMinCount
}

// EnableRevocation creates an initial accumulator for a given credential type. This function is the
// only way to create such an initial accumulator and it must be called before anyone can use
// revocation for this credential type. Requires the issuer private key.
func (rs *RevocationStorage) EnableRevocation(id CredentialTypeIdentifier, sk *gabikeys.PrivateKey) error {
	enabled, err := rs.Exists(id, sk.Counter)
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

	if err = rs.AddUpdate(id, update); err != nil {
		return err
	}
	return nil
}

// Exists returns whether or not an accumulator exists in the database for the given credential type.
func (rs *RevocationStorage) Exists(id CredentialTypeIdentifier, counter uint) (bool, error) {
	return rs.recordStorage.Exists(id, counter)
}

// Revocation update message methods

// Events returns the revocation events for the given credential type, public key counter and event index range.
// It returns an error if the requested range is not (fully) present.
func (rs *RevocationStorage) Events(id CredentialTypeIdentifier, pkcounter uint, from, to uint64) (*revocation.EventList, error) {
	if from >= to || from%RevocationParameters.UpdateMinCount != 0 || to%RevocationParameters.UpdateMinCount != 0 {
		return nil, errors.New("illegal update interval")
	}

	events, err := rs.recordStorage.Events(id, pkcounter, from, to)
	if err != nil {
		return nil, err
	}

	return revocation.NewEventList(events...), nil
}

// LatestUpdates returns revocation update instances for the given credential type and (optionally) public key
// containing the latest signed accumulator, and the latest revocation events.
// If limit is set to 0, then all revocation events are returned.
// If pkCounter is set to nil, then an update is returned for every public key.
func (rs *RevocationStorage) LatestUpdates(id CredentialTypeIdentifier, limit uint64, pkCounter *uint) (map[uint]*revocation.Update, error) {
	if limit > math.MaxInt {
		return nil, errors.New("invalid limit")
	}
	limitInt := int(limit)
	updates, err := rs.recordStorage.LatestAccumulatorUpdates(id, pkCounter, limitInt)
	if err != nil {
		return nil, err
	}

	// We need to run UnmarshalVerify for every update's SignedAccumulator to initialize the SignedAccumulator.Accumulator field.
	for _, u := range updates {
		pk, err := rs.Keys.PublicKey(id.IssuerIdentifier(), u.SignedAccumulator.PKCounter)
		if err != nil {
			return nil, err
		}
		if _, err := u.SignedAccumulator.UnmarshalVerify(pk); err != nil {
			return nil, err
		}
	}
	return updates, nil
}

// AddUpdate validates, processes and stores the given revocation update.
func (rs *RevocationStorage) AddUpdate(id CredentialTypeIdentifier, update *revocation.Update) error {
	pkCounter := update.SignedAccumulator.PKCounter

	// Unmarshal and verify the record against the appropriate public key
	pk, err := rs.Keys.PublicKey(id.IssuerIdentifier(), pkCounter)
	if err != nil {
		return err
	}
	if _, err = update.Verify(pk); err != nil {
		return err
	}

	return rs.recordStorage.AppendAccumulatorUpdate(id, func(heads map[uint]revocationUpdateHead) (map[uint]*revocation.Update, error) {
		// We should only add events to the storage that we do not have already.
		// If no records are present at all, we can only add it if the update contains the full event chain.
		newEvents := update.Events
		if head, ok := heads[pkCounter]; ok {
			// If the stored revocation state is newer than the given update, then we don't have to do anything.
			if head.LatestUpdateEvent.Index > update.SignedAccumulator.Accumulator.Index {
				return map[uint]*revocation.Update{}, nil
			}

			// Collect the events that are not present in storage yet.
			for _, event := range update.Events {
				if event.Index == head.LatestUpdateEvent.Index+1 {
					acc, err := head.SignedAccumulator.UnmarshalVerify(pk)
					if err != nil {
						return nil, err
					}
					if !acc.EventHash.Equal(event.ParentHash) {
						return nil, errors.New("revocation update does not align with stored hash chain")
					}
					break
				}
				newEvents = newEvents[1:]
			}

			// If the update does not contain new events, then the update's accumulator should re-sign the current event chain.
			// We validate this to prevent that we store an incorrect accumulator.
			if len(newEvents) == 0 {
				u := &revocation.Update{
					SignedAccumulator: update.SignedAccumulator,
					Events:            []*revocation.Event{head.LatestUpdateEvent},
				}
				if _, err := u.Verify(pk); err != nil {
					return nil, err
				}
			}
		} else if len(update.Events) == 0 {
			return nil, errors.New("accumulator refers to unknown revocation event index")
		}

		return map[uint]*revocation.Update{pkCounter: {
			SignedAccumulator: update.SignedAccumulator,
			Events:            newEvents,
		}}, nil
	})
}

// Issuance records

// AddIssuanceRecord stores the given issuance record.
func (rs *RevocationStorage) AddIssuanceRecord(r *IssuanceRecord) error {
	return rs.recordStorage.AddIssuanceRecord(r)
}

// IssuanceRecords returns all issuance records matching the given credential type, revocation key and issuance time.
// If the given issuance time is zero, then the issuance time is being ignored as condition.
func (rs *RevocationStorage) IssuanceRecords(id CredentialTypeIdentifier, key string, issued time.Time) ([]*IssuanceRecord, error) {
	return rs.recordStorage.IssuanceRecords(id, key, issued)
}

// Revocation methods

// Revoke revokes the credential(s) specified by key and issued, if found within the current revocation storage.
// It updates their revocation time to now, removes their revocation attribute from the current accumulator,
// and updates the revocation storage.
// If issued is not specified, i.e. passed the zero value, all credentials specified by key are revoked.
func (rs *RevocationStorage) Revoke(id CredentialTypeIdentifier, key string, issued time.Time) error {
	if !rs.settings.Get(id).Authority {
		return errors.Errorf("cannot revoke %s", id)
	}
	return rs.recordStorage.UpdateIssuanceRecord(id, key, issued, func(records []*IssuanceRecord) error {
		return rs.recordStorage.AppendAccumulatorUpdate(id, func(heads map[uint]revocationUpdateHead) (map[uint]*revocation.Update, error) {
			accsMap := make(map[uint]*revocation.Accumulator)
			eventsMap := make(map[uint][]*revocation.Event)
			// We initialize accsMap and accsMap with the current state from head such that we can build upon it as parent.
			for pkCounter, head := range heads {
				// Find the public key corresponding to the current pkCounter.
				pk, err := rs.Keys.PublicKey(id.IssuerIdentifier(), pkCounter)
				if err != nil {
					return nil, err
				}

				// Unmarshal the accumulator.
				acc, err := head.SignedAccumulator.UnmarshalVerify(pk)
				if err != nil {
					return nil, err
				}

				accsMap[pkCounter] = acc
				eventsMap[pkCounter] = []*revocation.Event{head.LatestUpdateEvent}
			}

			// For each issuance record, perform revocation, adding an Event and advancing the accumulator.
			for _, record := range records {
				parentAcc, ok := accsMap[*record.PKCounter]
				if !ok {
					return nil, ErrRevocationStateNotFound
				}
				parentEvent := eventsMap[*record.PKCounter][len(eventsMap[*record.PKCounter])-1]
				newAcc, newEvent, err := rs.revokeCredential(record, parentAcc, parentEvent)
				if err != nil {
					return nil, err
				}
				accsMap[*record.PKCounter] = newAcc
				eventsMap[*record.PKCounter] = append(eventsMap[*record.PKCounter], newEvent)
			}

			// Generate a signed update per public key based on the revocation events we generated above.
			updates := make(map[uint]*revocation.Update)
			for pkCounter, acc := range accsMap {
				newEvents := eventsMap[pkCounter][1:] // Skip the parent event.
				// We don't have to generate an update if nothing changed.
				if len(newEvents) == 0 {
					continue
				}

				sk, err := rs.Keys.PrivateKey(id.IssuerIdentifier(), pkCounter)
				if err != nil {
					return nil, err
				}
				update, err := revocation.NewUpdate(sk, acc, newEvents)
				if err != nil {
					return nil, err
				}

				// Unmarshal and verify the record against the appropriate public key.
				pk, err := rs.Keys.PublicKey(id.IssuerIdentifier(), pkCounter)
				if err != nil {
					return nil, err
				}
				if _, err = update.Verify(pk); err != nil {
					return nil, err
				}

				updates[pkCounter] = update
			}
			return updates, nil
		})
	})
}

// revokeCredential generates a new revocation event that revokes the given issuance record.
// The revocation event is being removed from the given accumulator. The generated event
// and the new accumulator state are being returned.
func (rs *RevocationStorage) revokeCredential(
	issrecord *IssuanceRecord,
	acc *revocation.Accumulator,
	parent *revocation.Event,
) (*revocation.Accumulator, *revocation.Event, error) {
	issrecord.RevokedAt = time.Now().UnixNano()
	sk, err := rs.Keys.PrivateKey(issrecord.CredType.IssuerIdentifier(), *issrecord.PKCounter)
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

// Accumulator returns the current state of the accumutor that belongs to the given credential type and public key.
func (rs *RevocationStorage) Accumulator(id CredentialTypeIdentifier, pkCounter uint) (
	*revocation.SignedAccumulator, error,
) {
	return rs.accumulator(id, pkCounter)
}

// accumulator retrieves, verifies and deserializes the accumulator of the given type and key.
func (rs *RevocationStorage) accumulator(id CredentialTypeIdentifier, pkCounter uint) (
	*revocation.SignedAccumulator, error,
) {
	updates, err := rs.recordStorage.LatestAccumulatorUpdates(id, &pkCounter, 1)
	if err != nil {
		return nil, err
	}
	update, ok := updates[pkCounter]
	if !ok {
		return nil, ErrRevocationStateNotFound
	}

	sacc := update.SignedAccumulator

	pk, err := rs.Keys.PublicKey(id.IssuerIdentifier(), sacc.PKCounter)
	if err != nil {
		return nil, err
	}
	_, err = sacc.UnmarshalVerify(pk)
	if err != nil {
		return nil, err
	}
	return sacc, nil
}

// updateAccumulatorTimes sets the signing time of all accumulators of which this revocation storage is the authority.
// to time.Now(). In this way we can confirm to verifiers that no credentials have been revoked between the previous
// signing time and now.
func (rs *RevocationStorage) updateAccumulatorTimes() error {
	var types []CredentialTypeIdentifier
	for id, settings := range rs.settings {
		if settings.Authority {
			types = append(types, id)
		}
	}

	for _, id := range types {
		Logger.Tracef("updating accumulator times %s", id)
		updates := make(map[uint]*revocation.Update)
		if err := rs.recordStorage.AppendAccumulatorUpdate(id, func(heads map[uint]revocationUpdateHead) (map[uint]*revocation.Update, error) {
			for pkCounter, head := range heads {
				pk, err := rs.Keys.PublicKey(id.IssuerIdentifier(), pkCounter)
				if err != nil {
					return nil, err
				}
				sk, err := rs.Keys.PrivateKey(id.IssuerIdentifier(), pkCounter)
				if err != nil {
					return nil, err
				}
				acc, err := head.SignedAccumulator.UnmarshalVerify(pk)
				if err != nil {
					return nil, err
				}
				acc.Time = time.Now().Unix()
				update, err := revocation.NewUpdate(sk, acc, []*revocation.Event{})
				if err != nil {
					return nil, err
				}
				updates[pkCounter] = update
			}
			return updates, nil
		}); err != nil {
			return err
		}

		for _, update := range updates {
			s := rs.settings.Get(id)
			s.updated = time.Now()

			// POST record to listeners, if any, asynchroniously
			rs.PostUpdate(id, update)
		}
	}
	return nil
}

// Methods to update from remote revocation server

// SyncDB fetches the current revocation state of the given credential at its revocation authority
// and stores this for caching purposes. This is useful to prevent that you have to contact
// the revocation authority at the exact moment you want to disclose a revocation proof.
func (rs *RevocationStorage) SyncDB(id CredentialTypeIdentifier) error {
	ct := rs.conf.CredentialTypes[id]
	if ct == nil {
		return ErrorUnknownCredentialType
	}
	if settings, ok := rs.settings[id]; ok && settings.Authority {
		return nil
	}

	Logger.WithField("credtype", id).Tracef("fetching revocation updates")
	updates, err := rs.client.FetchUpdatesLatest(id, ct.RevocationUpdateCount)
	if err != nil {
		return err
	}
	for _, u := range updates {
		if err = rs.AddUpdate(id, u); err != nil {
			return err
		}
	}
	// bump updated even if no new records were added
	rs.settings.Get(id).updated = time.Now()
	return nil
}

// SyncIfOld ensures that SyncDB will be called if the current revocation state
// is older than the given maxage.
func (rs *RevocationStorage) SyncIfOld(id CredentialTypeIdentifier, maxage uint64) error {
	if rs.settings.Get(id).updated.Before(time.Now().Add(time.Duration(-maxage) * time.Second)) {
		if err := rs.SyncDB(id); err != nil {
			return err
		}
	}
	return nil
}

// SaveIssuanceRecord either stores the issuance record locally, if we are the revocation server of
// the crecential type, or it signs and sends it to the remote revocation server.
func (rs *RevocationStorage) SaveIssuanceRecord(id CredentialTypeIdentifier, rec *IssuanceRecord, sk *gabikeys.PrivateKey) error {
	credtype := rs.conf.CredentialTypes[id]
	if credtype == nil {
		return ErrorUnknownCredentialType
	}
	if !credtype.RevocationSupported() {
		return errors.New("cannot save issuance record: credential type does not support revocation")
	}

	// Just store it if we are the revocation server for this credential type
	settings := rs.settings.Get(id)
	if settings.Authority {
		return rs.AddIssuanceRecord(rec)
	}

	// We have to send it, sign it first
	if settings.RevocationServerURL == "" {
		return errors.New("cannot send issuance record: no server_url configured")
	}
	return rs.client.PostIssuanceRecord(id, sk, rec, settings.RevocationServerURL)
}

// Misscelaneous methods

func (rs *RevocationStorage) handleSSEUpdates() {
	for {
		select {
		case event := <-rs.events:
			segments := strings.Split(event.URI, "/")
			if len(segments) < 2 {
				Logger.Warn("malformed SSE URL: ", event.URI)
				continue
			}
			var (
				id     = NewCredentialTypeIdentifier(segments[len(segments)-2])
				logger = Logger.WithField("credtype", id)
				update revocation.Update
				err    error
			)
			if err = json.Unmarshal(event.Data, &update); err != nil {
				logger.Warn("failed to unmarshal pushed update: ", err)
			} else {
				logger.Trace("received SSE update event")
				if err = rs.AddUpdate(id, &update); err != nil {
					logger.Warn("failed to add pushed update: ", err)
				}
			}
		case <-rs.close:
			Logger.Trace("stop handling SSE events")
			return
		}
	}
}

func (rs *RevocationStorage) listenUpdates(id CredentialTypeIdentifier, url string) {
	logger := Logger.WithField("credtype", id)
	logger.Trace("listening for SSE update events")

	// make a context that closes when rs.close closes
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-rs.close:
			cancel()
		case <-ctx.Done():
			return
		}
	}()
	err := sseclient.Notify(ctx, url, true, rs.events)
	if err != nil {
		logger.Warn("SSE connection closed: ", err)
	}
}

func updateURL(id CredentialTypeIdentifier, conf *Configuration, rs RevocationSettings) ([]string, error) {
	settings := rs[id]
	if settings != nil && settings.RevocationServerURL != "" {
		return []string{settings.RevocationServerURL}, nil
	} else {
		credtype := conf.CredentialTypes[id]
		if credtype == nil {
			return nil, ErrorUnknownCredentialType
		}
		if !credtype.RevocationSupported() {
			return nil, errors.New("credential type does not support revocation")
		}
		return credtype.RevocationServers, nil
	}
}

// Load initializes the revocation storage and starts background jobs to keep the storage up-to-date.
func (rs *RevocationStorage) Load(debug bool, dbtype, connstr string, settings RevocationSettings) error {
	settings.fixCase(rs.conf)
	settings.fixSlash()
	var t *CredentialTypeIdentifier
	for id, s := range settings {
		if !s.Authority {
			if s.Server && s.RevocationServerURL == "" {
				return errors.Errorf("revocation server mode for %s requires URL to be configured", id.String())
			}
		} else {
			s.Server = true
			if s.RevocationServerURL != "" {
				return errors.Errorf("revocation authority mode for %s cannot be combined with URL", id.String())
			}
		}
		if s.Server {
			t = &id
		}
		if s.SSE {
			urls, err := updateURL(id, rs.conf, settings)
			if err != nil {
				return err
			}
			if rs.close == nil {
				rs.close = make(chan struct{})
				rs.events = make(chan *sseclient.Event)
				go rs.handleSSEUpdates()
			}
			url := fmt.Sprintf("%s/revocation/%s/updateevents", urls[0], id.String())
			go rs.listenUpdates(id, url)
		}
	}
	if t != nil && connstr == "" {
		return errors.Errorf("revocation mode for %s requires SQL database but no connection string given", *t)
	}

	if _, err := rs.conf.Scheduler.Every(RevocationParameters.AccumulatorUpdateInterval).Seconds().WaitForSchedule().Do(func() {
		if err := rs.updateAccumulatorTimes(); err != nil {
			Logger.WithField("error", err).Error("failed to write updated accumulator record")
		}
	}); err != nil {
		return err
	}

	if _, err := rs.conf.Scheduler.Every(RevocationParameters.DeleteIssuanceRecordsInterval).Minutes().WaitForSchedule().Do(func() {
		if err := rs.recordStorage.DeleteExpiredIssuanceRecords(); err != nil {
			Logger.WithField("error", err).Error("failed to delete expired issuance records")
		}
	}); err != nil {
		return err
	}

	if connstr == "" {
		Logger.Trace("Using memory revocation database")
		rs.recordStorage = newMemStorage()
	} else {
		Logger.Trace("Connecting to revocation SQL database")
		storage, err := newSQLStorage(debug, dbtype, connstr)
		if err != nil {
			return err
		}
		rs.recordStorage = storage
	}
	if settings != nil {
		rs.settings = settings
	} else {
		rs.settings = RevocationSettings{}
	}
	for id, settings := range rs.settings {
		if settings.Tolerance != 0 && settings.Tolerance < 30 {
			return errors.Errorf("max_nonrev_duration setting for %s must be at least 30 seconds, was %d",
				id, settings.Tolerance)
		}
	}
	rs.client = RevocationClient{Conf: rs.conf, Settings: rs.settings}
	rs.Keys = RevocationKeys{Conf: rs.conf}
	return nil
}

// Close ensures the revocation storage is being closed.
// Limitation: the background jobs being started by Load() are not being stopped.
// This can only be done now by clearing all jobs in the Configuration's Scheduler.
func (rs *RevocationStorage) Close() error {
	if rs.close != nil {
		close(rs.close)
	}
	if err := rs.recordStorage.Close(); err != nil {
		return err
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
	for credid, params := range b.Revocation {
		ct := rs.conf.CredentialTypes[credid]
		if ct == nil {
			return ErrorUnknownCredentialType
		}
		if !ct.RevocationSupported() {
			return errors.Errorf("cannot request nonrevocation proof for %s: revocation not enabled in scheme", credid)
		}
		settings := rs.settings.Get(credid)
		tolerance := settings.Tolerance
		if params.Tolerance != 0 {
			tolerance = params.Tolerance
		}
		if err = rs.SyncIfOld(credid, tolerance/2); err != nil {
			updated := settings.updated
			if !updated.IsZero() {
				Logger.WithError(err).Warnf(
					"failed to fetch revocation updates for %s, nonrevocation is guaranteed only until %s ago",
					credid,
					time.Now().Sub(updated).String(),
				)
			} else {
				Logger.WithError(err).Errorf("revocation is disabled for %s: failed to fetch revocation updates and none are known locally", credid)
				// We can offer no nonrevocation guarantees at all while the requestor explicitly
				// asked for it; fail the session by returning an error
				return err
			}
		}
		params.Updates, err = rs.LatestUpdates(credid, ct.RevocationUpdateCount, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

func (rs *RevocationStorage) PostUpdate(id CredentialTypeIdentifier, update *revocation.Update) {
	if rs.ServerSentEvents == nil || !rs.settings.Get(id).Authority {
		return
	}
	Logger.WithField("credtype", id).Tracef("sending SSE update event")
	bts, _ := json.Marshal(update)
	rs.ServerSentEvents.SendMessage("revocation/"+id.String(), sse.SimpleMessage(string(bts)))
}

func (client RevocationClient) PostIssuanceRecord(id CredentialTypeIdentifier, sk *gabikeys.PrivateKey, rec *IssuanceRecord, url string) error {
	message, err := signed.MarshalSign(sk.ECDSA, rec)
	if err != nil {
		return err
	}
	return client.transport(false).Post(
		fmt.Sprintf("%s/revocation/%s/issuancerecord/%d", url, id, sk.Counter), nil, []byte(message),
	)
}

func (client RevocationClient) FetchUpdateFrom(id CredentialTypeIdentifier, pkcounter uint, from uint64) (*revocation.Update, error) {
	// First fetch accumulator + latest few events
	ct := client.Conf.CredentialTypes[id]
	if ct == nil {
		return nil, ErrorUnknownCredentialType
	}
	update, err := client.FetchUpdateLatest(id, pkcounter, ct.RevocationUpdateCount)
	if err != nil {
		return nil, err
	}
	pk, err := RevocationKeys{client.Conf}.PublicKey(id.IssuerIdentifier(), pkcounter)
	if err != nil {
		return nil, err
	}
	acc, err := update.SignedAccumulator.UnmarshalVerify(pk)
	if err != nil {
		return nil, err
	}

	to := acc.Index - uint64(len(update.Events))
	if from >= to {
		return update, err
	}

	// Fetch events not included in the response above
	indices := binaryPartition(from, to)
	eventsChan := make(chan *revocation.EventList)
	var wg sync.WaitGroup
	var eventsList []*revocation.EventList
	for _, i := range indices {
		wg.Add(1)
		go func(i [2]uint64) {
			events := &revocation.EventList{ComputeProduct: true}
			if e := client.getMultiple(
				client.Conf.CredentialTypes[id].RevocationServers,
				fmt.Sprintf("/revocation/%s/events/%d/%d/%d", id, pkcounter, i[0], i[1]),
				events,
			); e != nil {
				err = e
			}
			eventsChan <- events
			wg.Done()
		}(i)
	}

	// Gather responses from async GETs above
	wg.Add(1)
	go func() {
		for i := 0; i < len(indices); i++ {
			e := <-eventsChan
			eventsList = append(eventsList, e)
		}
		wg.Done()
	}()

	// Wait for everything to be done
	wg.Wait()
	if err != nil {
		return nil, err
	}

	el, err := revocation.FlattenEventLists(eventsList)
	if err != nil {
		return nil, err
	}
	return update, update.Prepend(el)
}

func (client RevocationClient) FetchUpdateLatest(id CredentialTypeIdentifier, pkcounter uint, count uint64) (*revocation.Update, error) {
	urls, err := updateURL(id, client.Conf, client.Settings)
	if err != nil {
		return nil, err
	}
	update := &revocation.Update{}
	return update, client.getMultiple(
		urls,
		fmt.Sprintf("/revocation/%s/update/%d/%d", id, count, pkcounter),
		&update,
	)
}

func (client RevocationClient) FetchUpdatesLatest(id CredentialTypeIdentifier, count uint64) (map[uint]*revocation.Update, error) {
	urls, err := updateURL(id, client.Conf, client.Settings)
	if err != nil {
		return nil, err
	}
	update := map[uint]*revocation.Update{}
	return update, client.getMultiple(
		urls,
		fmt.Sprintf("/revocation/%s/update/%d", id, count),
		&update,
	)
}

func (client RevocationClient) getMultiple(urls []string, path string, dest interface{}) error {
	var (
		errs      multierror.Error
		transport = client.transport(false)
	)
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

func (client RevocationClient) transport(forceHTTPS bool) *HTTPTransport {
	if client.http == nil {
		client.http = NewHTTPTransport("", forceHTTPS)
		client.http.Binary = true
	}
	return client.http
}

func (rs RevocationKeys) PrivateKeyLatest(issid IssuerIdentifier) (*gabikeys.PrivateKey, error) {
	sk, err := rs.Conf.PrivateKeys.Latest(issid)
	if err != nil {
		return nil, err
	}
	if sk == nil {
		return nil, errors.Errorf("unknown private key: %s", issid)
	}
	if !sk.RevocationSupported() {
		return nil, errors.New("private key does not support revocation")
	}
	return sk, nil
}

func (rs RevocationKeys) PrivateKey(issid IssuerIdentifier, counter uint) (*gabikeys.PrivateKey, error) {
	sk, err := rs.Conf.PrivateKeys.Get(issid, counter)
	if err != nil {
		return nil, err
	}
	if sk == nil {
		return nil, errors.Errorf("unknown private key: %s", issid)
	}
	if !sk.RevocationSupported() {
		return nil, errors.New("private key does not support revocation")
	}
	return sk, nil
}

func (rs RevocationKeys) PublicKey(issid IssuerIdentifier, counter uint) (*gabikeys.PublicKey, error) {
	pk, err := rs.Conf.PublicKey(issid, counter)
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, errors.Errorf("unknown public key: %s-%d", issid, counter)
	}
	if !pk.RevocationSupported() {
		return nil, errors.New("public key does not support revocation")
	}
	return pk, nil
}

func (rs RevocationSettings) Get(id CredentialTypeIdentifier) *RevocationSetting {
	if rs[id] == nil {
		rs[id] = &RevocationSetting{}
	}
	s := rs[id]
	if s.Tolerance == 0 {
		s.Tolerance = RevocationParameters.DefaultTolerance
	}
	return s
}

func (rs RevocationSettings) fixCase(conf *Configuration) {
	for id := range conf.CredentialTypes {
		idlc := NewCredentialTypeIdentifier(strings.ToLower(id.String()))
		if settings := rs[idlc]; settings != nil {
			delete(rs, idlc)
			rs[id] = settings
		}
	}
}

func (rs RevocationSettings) fixSlash() {
	for _, s := range rs {
		s.RevocationServerURL = strings.TrimRight(s.RevocationServerURL, "/")
	}
}

// binaryPartition splits the interval [from, to] into multiple adjacent intervals
// whose union cover [from, to], and whose length is a power of two decreasing as they near 'to'.
func binaryPartition(from, to uint64) [][2]uint64 {
	min, max := RevocationParameters.UpdateMinCount, RevocationParameters.UpdateMaxCount
	start := from / max * max     // round down to nearest multiple of max
	end := (to + min) / min * min // round up to nearest multiple of min

	pow := bits.Len64(end) - 1
	if pow > RevocationParameters.UpdateMaxCountPower {
		pow = RevocationParameters.UpdateMaxCountPower
	}

	var intervals [][2]uint64
	for i := start; i < end; {
		for i+1<<pow > end {
			pow--
		}
		intervals = append(intervals, [2]uint64{i, i + 1<<pow})
		i += 1 << pow
	}
	return intervals
}
