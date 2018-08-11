package irmarequestor

import (
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irmaserver"
	"github.com/privacybydesign/irmago/irmaserver/backend"
)

type SessionHandler func(*irmaserver.SessionResult)

type SessionStore interface {
	Get(token string) *irmaserver.SessionResult
	Add(token string, result *irmaserver.SessionResult)
	GetHandler(token string) SessionHandler
	SetHandler(token string, handler SessionHandler)
	SupportHandlers() bool
}

var Sessions SessionStore = &MemorySessionStore{
	m: make(map[string]*irmaserver.SessionResult),
	h: make(map[string]SessionHandler),
}

type MemorySessionStore struct {
	sync.RWMutex
	m map[string]*irmaserver.SessionResult
	h map[string]SessionHandler
}

func Initialize(configuration *irmaserver.Configuration) error {
	return backend.Initialize(configuration)
}

func StartSession(request irma.SessionRequest, handler SessionHandler) (*irma.Qr, string, error) {
	if handler != nil && !Sessions.SupportHandlers() {
		panic("Handlers not supported")
	}
	qr, token, err := backend.StartSession(request)
	if err != nil {
		return nil, "", err
	}
	if handler != nil {
		Sessions.SetHandler(token, handler)
	}
	return qr, token, nil
}

func HttpHandlerFunc(prefix string) http.HandlerFunc {
	if len(prefix) != 0 && prefix[0] != '/' {
		prefix = "/" + prefix
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var message []byte
		message, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		path := r.URL.Path[len(prefix):]
		status, response, result := backend.HandleProtocolMessage(path, r.Method, r.Header, message)
		w.WriteHeader(status)
		w.Write(response)
		if result != nil {
			Sessions.Add(result.Token, result)
			if handler := Sessions.GetHandler(result.Token); handler != nil {
				go handler(result)
			}
		}
	}
}

func (s MemorySessionStore) Get(token string) *irmaserver.SessionResult {
	s.RLock()
	defer s.RUnlock()
	return s.m[token]
}

func (s MemorySessionStore) Add(token string, result *irmaserver.SessionResult) {
	s.Lock()
	defer s.Unlock()
	if _, contains := s.m[token]; contains {
		return
	}
	s.m[token] = result
}

func (s MemorySessionStore) GetHandler(token string) SessionHandler {
	s.RLock()
	defer s.RUnlock()
	return s.h[token]
}

func (s MemorySessionStore) SetHandler(token string, handler SessionHandler) {
	s.Lock()
	defer s.Unlock()
	s.h[token] = handler
}

func (s MemorySessionStore) SupportHandlers() bool { return true }
