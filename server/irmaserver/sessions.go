package irmaserver

import (
	//TODO: use redigo instead of redis-go v8?
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/alexandrevicenzi/go-sse"
	"github.com/go-redis/redis/v8"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"

	"github.com/sirupsen/logrus"
)

type session struct {
	//TODO: check if we can get rid of this Mutex for Redis
	sync.Mutex `json:-`
	//TODO: note somewhere that state with redis will not support sse for the moment
	sse      *sse.Server
	locked   bool
	sessions sessionStore
	conf     *server.Configuration
	request  irma.SessionRequest

	sessionData
}

type sessionData struct {
	Action             irma.Action
	Token              string
	ClientToken        string
	Version            *irma.ProtocolVersion `json:",omitempty"`
	Rrequest           irma.RequestorRequest
	LegacyCompatible   bool // if the request is convertible to pre-condiscon format
	ImplicitDisclosure irma.AttributeConDisCon
	Status             server.Status
	PrevStatus         server.Status
	ResponseCache      responseCache
	LastActive         time.Time
	Result             *server.SessionResult
	KssProofs          map[irma.SchemeManagerIdentifier]*gabi.ProofP
}

type responseCache struct {
	message       []byte
	response      []byte
	status        int
	sessionStatus server.Status
}

type sessionStore interface {
	get(token string) *session
	clientGet(token string) *session
	add(session *session)
	update(session *session)
	deleteExpired()
	stop()
}

type memorySessionStore struct {
	sync.RWMutex
	conf *server.Configuration

	requestor map[string]*session
	client    map[string]*session
}

type redisSessionStore struct {
	client *redis.Client
	conf   *server.Configuration
}

const (
	maxSessionLifetime  = 5 * time.Minute // After this a session is cancelled
	tokenLookupPrefix   = "token:"
	sessionLookupPrefix = "session:"
)

var (
	minProtocolVersion = irma.NewVersion(2, 4)
	maxProtocolVersion = irma.NewVersion(2, 7)
)

func (s *memorySessionStore) get(t string) *session {
	s.RLock()
	defer s.RUnlock()
	return s.requestor[t]
}

func (s *memorySessionStore) clientGet(t string) *session {
	s.RLock()
	defer s.RUnlock()
	return s.client[t]
}

func (s *memorySessionStore) add(session *session) {
	s.Lock()
	defer s.Unlock()
	s.requestor[session.Token] = session
	s.client[session.ClientToken] = session
}

func (s *memorySessionStore) update(session *session) {
	session.onUpdate()
}

func (s *memorySessionStore) stop() {
	s.Lock()
	defer s.Unlock()
	for _, session := range s.requestor {
		if session.sse != nil {
			session.sse.CloseChannel("session/" + session.Token)
			session.sse.CloseChannel("session/" + session.ClientToken)
		}
	}
}

func (s *memorySessionStore) deleteExpired() {
	// First check which sessions have expired
	// We don't need a write lock for this yet, so postpone that for actual deleting
	s.RLock()
	expired := make([]string, 0, len(s.requestor))
	for Token, session := range s.requestor {
		session.Lock()

		timeout := maxSessionLifetime
		if session.Status == server.StatusInitialized && session.Rrequest.Base().ClientTimeout != 0 {
			timeout = time.Duration(session.Rrequest.Base().ClientTimeout) * time.Second
		}

		if session.LastActive.Add(timeout).Before(time.Now()) {
			if !session.Status.Finished() {
				s.conf.Logger.WithFields(logrus.Fields{"session": session.Token}).Infof("Session expired")
				session.markAlive()
				session.setStatus(server.StatusTimeout)
			} else {
				s.conf.Logger.WithFields(logrus.Fields{"session": session.Token}).Infof("Deleting session")
				expired = append(expired, Token)
			}
		}
		session.Unlock()
	}
	s.RUnlock()

	// Using a write lock, delete the expired sessions
	s.Lock()
	for _, Token := range expired {
		session := s.requestor[Token]
		if session.sse != nil {
			session.sse.CloseChannel("session/" + session.Token)
			session.sse.CloseChannel("session/" + session.ClientToken)
		}
		delete(s.client, session.ClientToken)
		delete(s.requestor, Token)
	}
	s.Unlock()
}

// MarshalJSON marshals sessionData to be used in the Redis in-memory datastore.
func (s *sessionData) MarshalJSON() ([]byte, error) {
	return json.Marshal(*s)
}

// UnmarshalJSON unmarshals sessionData.
func (s *sessionData) UnmarshalJSON(data []byte) error {
	type rawSessionData sessionData

	var temp struct {
		Rrequest *json.RawMessage `json:",omitempty"`
		rawSessionData
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	*s = sessionData(temp.rawSessionData)

	if temp.Rrequest == nil {
		s.Rrequest = nil
		// TODO: return custom error
		fmt.Printf("temp.Rrequest == nil: %d \n", temp.Rrequest)
		return nil
	}

	// unmarshal Rrequest
	ipR := &irma.IdentityProviderRequest{}
	spR := &irma.ServiceProviderRequest{}
	sigR := &irma.SignatureRequestorRequest{}

	if err := json.Unmarshal(*temp.Rrequest, ipR); err == nil && s.Action == "issuing" {
		s.Rrequest = ipR
	} else if err = json.Unmarshal(*temp.Rrequest, spR); err == nil && s.Action == "disclosing" {
		s.Rrequest = spR
	} else if err = json.Unmarshal(*temp.Rrequest, sigR); err == nil && s.Action == "signing" {
		s.Rrequest = sigR
	} else {
		fmt.Printf("unable to unmarshal rrequest: %s \n", err)
		return err
	}

	return nil
}

func (s *redisSessionStore) get(t string) *session {
	//TODO: input validation string?
	val, err := s.client.Get(context.TODO(), tokenLookupPrefix+t).Result()
	if err != nil {
		// return nil? compare with in memory
		fmt.Printf("unable to get corresponding clientToken for token %s from redis: %s \n", t, err)
	}

	return s.clientGet(val)
}

func (s *redisSessionStore) clientGet(t string) *session {
	val, err := s.client.Get(context.TODO(), sessionLookupPrefix+t).Result()
	if err != nil {
		fmt.Printf("unable to get session data for clientToken %s from redis: %s \n", t, err)
	}

	var session session
	session.conf = s.conf
	session.sessions = s
	if err := session.sessionData.UnmarshalJSON([]byte(val)); err != nil {
		//TODO: return with error? general question how to deal with Redis errors
		fmt.Printf("unable to unmarshal data into the new example struct due to: %s \n", err)
	}
	session.request = session.Rrequest.SessionRequest()

	return &session
}

func (s *redisSessionStore) add(session *session) {
	add(session, s.client, maxSessionLifetime)
}

func add(session *session, client *redis.Client, ttl time.Duration) {
	sessionJSON, err := session.sessionData.MarshalJSON()
	if err != nil {
		fmt.Printf("unable to marshal data to json due to: %s \n", err)
	}

	err = client.Set(context.TODO(), tokenLookupPrefix+session.sessionData.Token, session.sessionData.ClientToken, ttl).Err()
	if err != nil {
		fmt.Printf("unable to save token lookup in Redis datastore: %s \n", err)
	}
	err = client.Set(context.TODO(), sessionLookupPrefix+session.sessionData.ClientToken, sessionJSON, ttl).Err()
	if err != nil {
		fmt.Printf("unable to save session data as JSON in Redis datastore: %s \n", err)
	}
}

func (s *redisSessionStore) update(session *session) {
	ttl, _ := s.client.TTL(context.TODO(), session.ClientToken).Result()
	add(session, s.client, ttl)
}

func (s *redisSessionStore) stop() {
	err := s.client.Close()
	if err != nil {
		fmt.Printf("closing the redis client failed due to %s \n", err)
	}
}

func (s *redisSessionStore) deleteExpired() {
	// This method is not used as data is directly stored in Redis with a corresponding expiration time.
}

var one *big.Int = big.NewInt(1)

func (s *Server) newSession(action irma.Action, request irma.RequestorRequest) *session {
	token := common.NewSessionToken()
	clientToken := common.NewSessionToken()

	base := request.SessionRequest().Base()
	if s.conf.AugmentClientReturnURL && base.AugmentReturnURL && base.ClientReturnURL != "" {
		if strings.Contains(base.ClientReturnURL, "?") {
			base.ClientReturnURL += "&Token=" + token
		} else {
			base.ClientReturnURL += "?Token=" + token
		}
	}

	sd := sessionData{
		Action:      action,
		Rrequest:    request,
		LastActive:  time.Now(),
		Token:       token,
		ClientToken: clientToken,
		Status:      server.StatusInitialized,
		PrevStatus:  server.StatusInitialized,
		Result: &server.SessionResult{
			LegacySession: request.SessionRequest().Base().Legacy(),
			Token:         token,
			Type:          action,
			Status:        server.StatusInitialized,
		},
	}
	ses := &session{
		sessionData: sd,
		sessions:    s.sessions,
		sse:         s.serverSentEvents,
		conf:        s.conf,
		request:     request.SessionRequest(),
	}

	s.conf.Logger.WithFields(logrus.Fields{"session": ses.Token}).Debug("New session started")
	nonce, _ := gabi.GenerateNonce()
	base.Nonce = nonce
	base.Context = one
	s.sessions.add(ses)

	return ses
}
