package keyshareserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	etcd_client "go.etcd.io/etcd/client/v3"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/server"
)

const (
	commitmentLookupPrefix    = "keysharecore/commitment/"
	authChallengeLookupPrefix = "keysharecore/authChallenge/"
	sessionLookupPrefix       = "keyshareserver/session/"
)

type session struct {
	KeyID    irma.PublicKeyIdentifier // last used key, used in signing the issuance message
	CommitID uint64
	Hw       gabi.KeyshareCommitmentRequest
	expiry   time.Time
}

type sessionStore interface {
	keysharecore.ConsistentStorage

	add(username string, session *session)
	get(username string) *session
	flush()
}

type memorySessionStore struct {
	sync.Mutex
	*keysharecore.MemoryConsistentStorage

	sessions        map[string]*session
	sessionLifetime time.Duration
}

type etcdSessionStore struct {
	client          *etcd_client.Client
	sessionLifetime time.Duration
}

func newMemorySessionStore(sessionLifetime time.Duration) sessionStore {
	return &memorySessionStore{
		MemoryConsistentStorage: keysharecore.NewMemoryConsistentStorage(),

		sessionLifetime: sessionLifetime,
		sessions:        map[string]*session{},
	}
}

func (s *memorySessionStore) add(username string, session *session) {
	s.Lock()
	defer s.Unlock()
	session.expiry = time.Now().Add(s.sessionLifetime)
	s.sessions[username] = session
}

func (s *memorySessionStore) get(username string) *session {
	s.Lock()
	defer s.Unlock()
	return s.sessions[username]
}

func (s *memorySessionStore) flush() {
	now := time.Now()
	s.Lock()
	defer s.Unlock()
	for k, v := range s.sessions {
		if now.After(v.expiry) {
			delete(s.sessions, k)
		}
	}
}

// StoreCommitment implements sessionStore.
func (s *etcdSessionStore) StoreCommitment(id uint64, commitment *big.Int) error {
	ctx := context.TODO()

	encodedCommitment, err := commitment.MarshalText()
	if err != nil {
		return err
	}

	// TODO: shouldn't we use a lease to prevent that unconsumed commitments stay in the store forever?
	if _, err := s.client.Put(ctx, fmt.Sprintf("%s%x", commitmentLookupPrefix, id), string(encodedCommitment)); err != nil {
		server.LogError(err, "failed to store commitment")
		return keysharecore.ErrStorageFailure
	}
	return nil
}

// ConsumeCommitment implements sessionStore.
func (s *etcdSessionStore) ConsumeCommitment(id uint64) (*big.Int, error) {
	ctx := context.TODO()

	key := fmt.Sprintf("%s%x", commitmentLookupPrefix, id)
	txResp, err := s.client.Txn(ctx).Then(
		etcd_client.OpGet(key),
		etcd_client.OpDelete(key),
	).Commit()
	if err != nil {
		server.LogError(err, "failed to retrieve commitment")
		return nil, keysharecore.ErrStorageFailure
	}

	if len(txResp.Responses) != 2 {
		server.LogError(errors.New("unexpected number of responses"), "failed to retrieve commitment")
		return nil, keysharecore.ErrStorageFailure
	}
	resp := txResp.Responses[0].GetResponseRange()

	if len(resp.Kvs) != 1 {
		return nil, keysharecore.ErrUnknownCommit
	}

	commitmentBytes, err := base64.StdEncoding.DecodeString(string(resp.Kvs[0].Value))
	if err != nil {
		return nil, err
	}
	return big.NewInt(0).SetBytes(commitmentBytes), nil
}

// StoreAuthChallenge implements sessionStore.
func (s *etcdSessionStore) StoreAuthChallenge(id []byte, challenge []byte) error {
	ctx := context.TODO()

	encodedKey := base64.StdEncoding.EncodeToString(id)
	encodedValue := base64.StdEncoding.EncodeToString(challenge)

	// TODO: shouldn't we use a lease to prevent that unconsumed commitments stay in the store forever?
	if _, err := s.client.Put(ctx, commitmentLookupPrefix+encodedKey, encodedValue); err != nil {
		server.LogError(err, "failed to store commitment")
		return keysharecore.ErrStorageFailure
	}
	return nil
}

// ConsumeAuthChallenge implements sessionStore.
func (s *etcdSessionStore) ConsumeAuthChallenge(id []byte) ([]byte, error) {
	ctx := context.TODO()

	encodedKey := base64.StdEncoding.EncodeToString(id)

	txResp, err := s.client.Txn(ctx).Then(
		etcd_client.OpGet(authChallengeLookupPrefix+encodedKey),
		etcd_client.OpDelete(authChallengeLookupPrefix+encodedKey),
	).Commit()
	if err != nil {
		server.LogError(err, "failed to retrieve commitment")
		return nil, keysharecore.ErrStorageFailure
	}

	if len(txResp.Responses) != 2 {
		server.LogError(errors.New("unexpected number of responses"), "failed to retrieve commitment")
		return nil, keysharecore.ErrStorageFailure
	}
	resp := txResp.Responses[0].GetResponseRange()

	if len(resp.Kvs) != 1 {
		return nil, keysharecore.ErrInvalidChallenge
	}

	return base64.StdEncoding.DecodeString(string(resp.Kvs[0].Value))
}

// add implements sessionStore.
func (s *etcdSessionStore) add(username string, session *session) {
	ctx := context.TODO()

	encodedSession, err := json.Marshal(session)
	if err != nil {
		server.LogError(err, "failed to marshal session")
		return
	}

	ttl := s.sessionLifetime.Seconds()
	lease, err := s.client.Lease.Grant(ctx, int64(ttl))
	if err != nil {
		server.LogError(err, "failed to create lease")
		return
	}

	if _, err := s.client.Put(ctx, sessionLookupPrefix+username, string(encodedSession), etcd_client.WithLease(lease.ID)); err != nil {
		server.LogError(err, "failed to store session")
		return
	}
}

// flush implements sessionStore.
func (s *etcdSessionStore) flush() {
	// Expired leases get automatically flushed by etcd.
}

// get implements sessionStore.
func (s *etcdSessionStore) get(username string) *session {
	ctx := context.TODO()

	resp, err := s.client.Get(ctx, sessionLookupPrefix+username)
	if err != nil {
		server.LogError(err, "failed to retrieve session")
		return nil
	}
	if len(resp.Kvs) != 1 {
		return nil
	}

	session := &session{}
	if err := json.Unmarshal(resp.Kvs[0].Value, session); err != nil {
		server.LogError(err, "failed to unmarshal session")
		return nil
	}
	return session
}
