package myirmaserver

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	etcd_client "go.etcd.io/etcd/client/v3"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/server"
)

const sessionLookupPrefix = "myirmaserver/session/"

var errUnknownSession = errors.New("unknown session")

type session struct {
	Token  string `json:"token"`
	UserID *int64 `json:"user_id,omitempty"`

	LoginSessionToken irma.RequestorToken `json:"login_session_token,omitempty"`
	EmailSessionToken irma.RequestorToken `json:"email_session_token,omitempty"`

	Expiry time.Time `json:"expiry"`
}

type sessionStore interface {
	add(ses session) error
	// TODO: delete get function here. They are only used in tests, so it should be a helper there.
	get(token string) (session, error)
	update(token string, handler func(ses *session) error) error
	flush()
}

type memorySessionStore struct {
	sync.Mutex
	data map[string]session
}

type etcdSessionStore struct {
	client *etcd_client.Client
}

func newMemorySessionStore() sessionStore {
	return &memorySessionStore{
		data: map[string]session{},
	}
}

func (s *memorySessionStore) add(ses session) error {
	s.Lock()
	defer s.Unlock()
	s.data[ses.Token] = ses
	return nil
}

func (s *memorySessionStore) get(token string) (session, error) {
	s.Lock()
	defer s.Unlock()
	ses, ok := s.data[token]
	if !ok {
		return session{}, errUnknownSession
	}
	return ses, nil
}

func (s *memorySessionStore) update(token string, handler func(ses *session) error) error {
	s.Lock()
	defer s.Unlock()
	ses, ok := s.data[token]
	if !ok {
		return errUnknownSession
	}
	if err := handler(&ses); err != nil {
		return err
	}
	s.data[token] = ses
	return nil
}

func (s *memorySessionStore) flush() {
	now := time.Now()
	s.Lock()
	defer s.Unlock()
	for k, v := range s.data {
		if now.After(v.Expiry) {
			delete(s.data, k)
		}
	}
}

func (s *etcdSessionStore) add(ses session) error {
	ctx := context.TODO()

	bytes, err := json.Marshal(ses)
	if err != nil {
		return err
	}

	ttl := time.Until(ses.Expiry).Seconds()
	lease, err := s.client.Grant(ctx, int64(ttl))
	if err != nil {
		server.LogError(err, "failed to grant lease")
		return keysharecore.ErrStorageFailure
	}

	if _, err := s.client.Put(ctx, sessionLookupPrefix+ses.Token, string(bytes), etcd_client.WithLease(lease.ID)); err != nil {
		server.LogError(err, "failed to store session")
		return keysharecore.ErrStorageFailure
	}
	return nil
}

func (s *etcdSessionStore) get(token string) (session, error) {
	ctx := context.TODO()

	resp, err := s.client.Get(ctx, sessionLookupPrefix+token)
	if err != nil {
		server.LogError(err, "failed to retrieve session")
		return session{}, keysharecore.ErrStorageFailure
	}
	if len(resp.Kvs) == 0 {
		return session{}, errUnknownSession
	}

	session := session{}
	return session, json.Unmarshal(resp.Kvs[0].Value, &session)
}

func (s *etcdSessionStore) update(token string, handler func(ses *session) error) error {
	ctx := context.TODO()

	key := sessionLookupPrefix + token
	respGet, err := s.client.Get(ctx, key)
	if err != nil {
		server.LogError(err, "failed to retrieve session")
		return keysharecore.ErrStorageFailure
	}
	if len(respGet.Kvs) == 0 {
		return errUnknownSession
	}

	session := &session{}
	if err := json.Unmarshal(respGet.Kvs[0].Value, session); err != nil {
		return err
	}

	if err := handler(session); err != nil {
		return err
	}

	bytes, err := json.Marshal(session)
	if err != nil {
		return err
	}

	ttl := time.Until(session.Expiry).Seconds()
	lease, err := s.client.Grant(ctx, int64(ttl))
	if err != nil {
		server.LogError(err, "failed to grant lease")
		return keysharecore.ErrStorageFailure
	}

	respPut, err := s.client.Txn(ctx).
		If(etcd_client.Compare(etcd_client.ModRevision(key), "=", respGet.Kvs[0].ModRevision)).
		Then(etcd_client.OpPut(key, string(bytes), etcd_client.WithLease(lease.ID))).
		Commit()
	if err == nil && !respPut.Succeeded {
		// TODO: ensure that this error leads to another error than 500.
		err = errors.New("session has been updated by another server")
	}
	if err != nil {
		server.LogError(err, "failed to store session")
		// Revoke newly created lease
		if _, err := s.client.Revoke(ctx, lease.ID); err != nil {
			server.LogError(err, "failed to revoke lease")
		}
		return keysharecore.ErrStorageFailure
	}

	// Revoke previous lease
	if _, err := s.client.Revoke(ctx, etcd_client.LeaseID(respGet.Kvs[0].Lease)); err != nil {
		server.LogError(err, "failed to revoke previous lease")
	}

	return nil
}

func (s *etcdSessionStore) flush() {
	// Leases expire automatically.
}
