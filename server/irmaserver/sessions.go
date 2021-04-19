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
	sse           *sse.Server `json:-`
	locked bool `json:-`
	Sessions sessionStore `json:-`
	Conf     *server.Configuration `json:-`
	Request            irma.SessionRequest `json:-`

	sessionData
}

type sessionData struct {
	Action             irma.Action
	Token              string
	ClientToken        string
	Version            *irma.ProtocolVersion `json:",omitempty"`
	Rrequest           irma.RequestorRequest
	LegacyCompatible   bool // if the Request is convertible to pre-condiscon format
	ImplicitDisclosure irma.AttributeConDisCon
	Status        server.Status
	PrevStatus    server.Status
	ResponseCache responseCache
	LastActive time.Time
	Result     *server.SessionResult
	KssProofs map[irma.SchemeManagerIdentifier]*gabi.ProofP
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
	conf *server.Configuration
}

const (
	maxSessionLifetime = 5 * time.Minute // After this a session is cancelled
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

	// Using a write lock, delete the expired Sessions
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

// MarshalJSON marshals a session to be used in the Redis in-memory datastore.
func (s *session) MarshalJSON() ([]byte, error) {
	return json.Marshal(*s)
}

// UnmarshalJSON unmarshals the sessionData of a session.
func (s *session) UnmarshalJSON(data []byte) error {
	var temp struct {
		Rrequest *json.RawMessage `json:",omitempty"`
		sessionData
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	s.sessionData = temp.sessionData

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
	s.Request = s.Rrequest.SessionRequest()

	return nil
}

func (s *redisSessionStore) get(t string) *session {
	//TODO: input validation string?
	val, err := s.client.Get(context.TODO(),t).Result()
	if err != nil {
		fmt.Println(err)
	}

	return s.clientGet(val)
}

func (s *redisSessionStore) clientGet(t string) *session {
	fmt.Println("############ redisSessionStore wants to GET")

	val, err := s.client.Get(context.TODO(),t).Result()
	if err != nil {
		fmt.Printf("unable to get data from redis: %s \n", err)
	}

	fmt.Println("ClientToken redis GET jsonObject:", val)
	var session session
	session.Conf = s.conf
	session.Sessions = s
	if err := session.UnmarshalJSON([]byte(val)); err != nil {
		// return with error?
		fmt.Printf("unable to unmarshal data into the new example struct due to: %s \n", err)
	}

	return &session
}

func (s *redisSessionStore) add(session *session) {
	fmt.Println("############ redisSessionStore wants to ADD")

	sessionJSON, err := session.MarshalJSON()
	if err != nil {
		fmt.Printf("unable to marshal data to json due to: %s \n", err)
	}

	//TODO: use different key naming: 1 for token, 1 for clientToken (https://redislabs.com/blog/5-key-takeaways-for-developing-with-redis/)
	//TODO: use expiration time
	err1 := s.client.Set(context.TODO(),session.sessionData.Token, session.sessionData.ClientToken, 0).Err()
	err2 := s.client.Set(context.TODO(),session.sessionData.ClientToken, sessionJSON, 0).Err()
	fmt.Println("errors:", err, err1, err2)
	fmt.Println("session.Token, session.ClientToken")
	fmt.Println(session.sessionData.Token, session.sessionData.ClientToken)
}

func (s *redisSessionStore) update(session *session) {
	fmt.Println("############ redisSessionStore wants to UPDATE")
	s.add(session)
	//TODO: remove?
	session.onUpdate()
}

func (s *redisSessionStore) stop() {
	fmt.Println("redisSessionStore wants to stop")
}

func (s *redisSessionStore) deleteExpired() {
	fmt.Println("redisSessionStore wants to deleteExpired")
	//TODO: use redis expiration instead? explicit delete needed?
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
		Sessions:    s.sessions,
		sse:         s.serverSentEvents,
		Conf:        s.conf,
		Request:     request.SessionRequest(),
	}

	s.conf.Logger.WithFields(logrus.Fields{"session": ses.Token}).Debug("New session started")
	nonce, _ := gabi.GenerateNonce()
	base.Nonce = nonce
	base.Context = one
	s.sessions.add(ses)

	return ses
}
