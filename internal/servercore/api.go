// Package servercore is the core of the IRMA server library, allowing IRMA verifiers, issuers
// or attribute-based signature applications to perform IRMA sessions with irmaclient instances
// (i.e. the IRMA app). It exposes a small interface to expose to other programming languages
// through cgo. It is used by the irmaserver package but otherwise not meant for use in Go.
package servercore

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/jasonlvhit/gocron"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
)

type Server struct {
	conf          *server.Configuration
	sessions      sessionStore
	scheduler     *gocron.Scheduler
	stopScheduler chan bool
}

func New(conf *server.Configuration) (*Server, error) {
	if err := conf.Check(); err != nil {
		return nil, err
	}

	s := &Server{
		conf:      conf,
		scheduler: gocron.NewScheduler(),
		sessions: &memorySessionStore{
			requestor: make(map[string]*session),
			client:    make(map[string]*session),
			conf:      conf,
		},
	}
	s.scheduler.Every(10).Seconds().Do(func() {
		s.sessions.deleteExpired()
	})

	s.scheduler.Every(5).Minutes().Do(func() {
		for credid, credtype := range s.conf.IrmaConfiguration.CredentialTypes {
			if !credtype.SupportsRevocation() {
				continue
			}
			if _, ours := conf.RevocationServers[credid]; ours {
				// TODO rethink this condition
				continue
			}
			if err := s.conf.IrmaConfiguration.RevocationStorage.UpdateDB(credid); err != nil {
				s.conf.Logger.Error("failed to update revocation database for %s:", credid.String())
				_ = server.LogError(err)
			}
		}
	})

	s.stopScheduler = s.scheduler.Start()

	return s, nil
}

func (s *Server) Stop() {
	if err := s.conf.IrmaConfiguration.RevocationStorage.Close(); err != nil {
		_ = server.LogWarning(err)
	}
	s.stopScheduler <- true
	s.sessions.stop()
}

func (s *Server) validateRequest(request irma.SessionRequest) error {
	if _, err := s.conf.IrmaConfiguration.Download(request); err != nil {
		return err
	}
	return request.Disclosure().Disclose.Validate(s.conf.IrmaConfiguration)
}

func (s *Server) StartSession(req interface{}) (*irma.Qr, string, error) {
	rrequest, err := server.ParseSessionRequest(req)
	if err != nil {
		return nil, "", err
	}

	request := rrequest.SessionRequest()
	action := request.Action()

	if err := s.validateRequest(request); err != nil {
		return nil, "", err
	}

	if action == irma.ActionIssuing {
		if err := s.validateIssuanceRequest(request.(*irma.IssuanceRequest)); err != nil {
			return nil, "", err
		}
	}

	session := s.newSession(action, rrequest)
	s.conf.Logger.WithFields(logrus.Fields{"action": action, "session": session.token}).Infof("Session started")
	if s.conf.Logger.IsLevelEnabled(logrus.DebugLevel) {
		s.conf.Logger.WithFields(logrus.Fields{"session": session.token}).Info("Session request: ", server.ToJson(rrequest))
	} else {
		s.conf.Logger.WithFields(logrus.Fields{"session": session.token}).Info("Session request (purged of attribute values): ", server.ToJson(purgeRequest(rrequest)))
	}
	return &irma.Qr{
		Type: action,
		URL:  s.conf.URL + "session/" + session.clientToken,
	}, session.token, nil
}

func (s *Server) GetSessionResult(token string) *server.SessionResult {
	session := s.sessions.get(token)
	if session == nil {
		s.conf.Logger.Warn("Session result requested of unknown session ", token)
		return nil
	}
	return session.result
}

func (s *Server) GetRequest(token string) irma.RequestorRequest {
	session := s.sessions.get(token)
	if session == nil {
		s.conf.Logger.Warn("Session request requested of unknown session ", token)
		return nil
	}
	return session.rrequest
}

func (s *Server) CancelSession(token string) error {
	session := s.sessions.get(token)
	if session == nil {
		return server.LogError(errors.Errorf("can't cancel unknown session %s", token))
	}
	session.handleDelete()
	return nil
}

func (s *Server) Revoke(credid irma.CredentialTypeIdentifier, key string) error {
	return s.conf.IrmaConfiguration.RevocationStorage.Revoke(credid, key)
}

func ParsePath(path string) (token, noun string, arg []string, err error) {
	rev := regexp.MustCompile("-/revocation/(records|issuancerecord)/?(.*)$")
	matches := rev.FindStringSubmatch(path)
	if len(matches) == 3 {
		args := strings.Split(matches[2], "/")
		return "", matches[1], args, nil
	}

	client := regexp.MustCompile("session/(\\w+)/?(|commitments|proofs|status|statusevents)$")
	matches = client.FindStringSubmatch(path)
	if len(matches) == 3 {
		return matches[1], matches[2], nil, nil
	}

	return "", "", nil, server.LogWarning(errors.Errorf("Invalid URL: %s", path))
}

func (s *Server) SubscribeServerSentEvents(w http.ResponseWriter, r *http.Request, token string, requestor bool) error {
	if !s.conf.EnableSSE {
		return errors.New("Server sent events disabled")
	}

	var session *session
	if requestor {
		session = s.sessions.get(token)
	} else {
		session = s.sessions.clientGet(token)
	}
	if session == nil {
		return server.LogError(errors.Errorf("can't subscribe to server sent events of unknown session %s", token))
	}
	if session.status.Finished() {
		return server.LogError(errors.Errorf("can't subscribe to server sent events of finished session %s", token))
	}

	session.Lock()
	defer session.Unlock()

	// The EventSource.onopen Javascript callback is not consistently called across browsers (Chrome yes, Firefox+Safari no).
	// However, when the SSE connection has been opened the webclient needs some signal so that it can early detect SSE failures.
	// So we manually send an "open" event. Unfortunately:
	// - we need to give the webclient that connected just now some time, otherwise it will miss the "open" event
	// - the "open" event also goes to all other webclients currently listening, as we have no way to send this
	//   event to just the webclient currently listening. (Thus the handler of this "open" event must be idempotent.)
	evtSource := session.eventSource()
	go func() {
		time.Sleep(200 * time.Millisecond)
		evtSource.SendEventMessage("", "open", "")
	}()
	evtSource.ServeHTTP(w, r)
	return nil
}

func (s *Server) HandleProtocolMessage(
	path string,
	method string,
	headers map[string][]string,
	message []byte,
) (int, []byte, *server.SessionResult) {
	var start time.Time
	if s.conf.Verbose >= 2 {
		start = time.Now()
		server.LogRequest("client", method, path, "", http.Header(headers), message)
	}

	status, output, result := s.handleProtocolMessage(path, method, headers, message)

	if s.conf.Verbose >= 2 {
		server.LogResponse(status, time.Now().Sub(start), output)
	}

	return status, output, result
}

func (s *Server) handleProtocolMessage(
	path string,
	method string,
	headers map[string][]string,
	message []byte,
) (status int, output []byte, result *server.SessionResult) {
	// Parse path into session and action
	if len(path) > 0 { // Remove any starting and trailing slash
		if path[0] == '/' {
			path = path[1:]
		}
		if path[len(path)-1] == '/' {
			path = path[:len(path)-1]
		}
	}

	token, noun, args, err := ParsePath(path)
	if err != nil {
		status, output = server.JsonResponse(nil, server.RemoteError(server.ErrorUnsupported, ""))
	}

	if token != "" {
		status, output, result = s.handleClientMessage(token, noun, method, headers, message)
	} else {
		status, output = s.handleRevocationMessage(noun, method, args, headers, message)
	}
	return
}

func (s *Server) handleClientMessage(
	token, noun, method string, headers map[string][]string, message []byte,
) (status int, output []byte, result *server.SessionResult) {
	// Fetch the session
	session := s.sessions.clientGet(token)
	if session == nil {
		s.conf.Logger.WithField("clientToken", token).Warn("Session not found")
		status, output = server.JsonResponse(nil, server.RemoteError(server.ErrorSessionUnknown, ""))
		return
	}
	session.Lock()
	defer session.Unlock()

	// However we return, if the session status has been updated
	// then we should inform the user by returning a SessionResult
	defer func() {
		if session.status != session.prevStatus {
			session.prevStatus = session.status
			result = session.result
		}
	}()

	// Route to handler
	switch len(noun) {
	case 0:
		if method == http.MethodDelete {
			session.handleDelete()
			status = http.StatusOK
			return
		}
		if method == http.MethodGet {
			status, output = session.checkCache(message, server.StatusConnected)
			if len(output) != 0 {
				return
			}
			h := http.Header(headers)
			min := &irma.ProtocolVersion{}
			max := &irma.ProtocolVersion{}
			if err := json.Unmarshal([]byte(h.Get(irma.MinVersionHeader)), min); err != nil {
				status, output = server.JsonResponse(nil, session.fail(server.ErrorMalformedInput, err.Error()))
				return
			}
			if err := json.Unmarshal([]byte(h.Get(irma.MaxVersionHeader)), max); err != nil {
				status, output = server.JsonResponse(nil, session.fail(server.ErrorMalformedInput, err.Error()))
				return
			}
			status, output = server.JsonResponse(session.handleGetRequest(min, max))
			session.responseCache = responseCache{message: message, response: output, status: status, sessionStatus: server.StatusConnected}
			return
		}
		status, output = server.JsonResponse(nil, session.fail(server.ErrorInvalidRequest, ""))
		return

	default:
		if noun == "statusevents" {
			err := server.RemoteError(server.ErrorInvalidRequest, "server sent events not supported by this server")
			status, output = server.JsonResponse(nil, err)
			return
		}

		if method == http.MethodGet && noun == "status" {
			status, output = server.JsonResponse(session.handleGetStatus())
			return
		}

		// Below are only POST enpoints
		if method != http.MethodPost {
			status, output = server.JsonResponse(nil, session.fail(server.ErrorInvalidRequest, ""))
			return
		}

		if noun == "commitments" && session.action == irma.ActionIssuing {
			status, output = session.checkCache(message, server.StatusDone)
			if len(output) != 0 {
				return
			}
			commitments := &irma.IssueCommitmentMessage{}
			if err = irma.UnmarshalValidate(message, commitments); err != nil {
				status, output = server.JsonResponse(nil, session.fail(server.ErrorMalformedInput, err.Error()))
				return
			}
			status, output = server.JsonResponse(session.handlePostCommitments(commitments))
			session.responseCache = responseCache{message: message, response: output, status: status, sessionStatus: server.StatusDone}
			return
		}

		if noun == "proofs" && session.action == irma.ActionDisclosing {
			status, output = session.checkCache(message, server.StatusDone)
			if len(output) != 0 {
				return
			}
			disclosure := &irma.Disclosure{}
			if err = irma.UnmarshalValidate(message, disclosure); err != nil {
				status, output = server.JsonResponse(nil, session.fail(server.ErrorMalformedInput, err.Error()))
				return
			}
			status, output = server.JsonResponse(session.handlePostDisclosure(disclosure))
			session.responseCache = responseCache{message: message, response: output, status: status, sessionStatus: server.StatusDone}
			return
		}

		if noun == "proofs" && session.action == irma.ActionSigning {
			status, output = session.checkCache(message, server.StatusDone)
			if len(output) != 0 {
				return
			}
			signature := &irma.SignedMessage{}
			if err = irma.UnmarshalValidate(message, signature); err != nil {
				status, output = server.JsonResponse(nil, session.fail(server.ErrorMalformedInput, err.Error()))
				return
			}
			status, output = server.JsonResponse(session.handlePostSignature(signature))
			session.responseCache = responseCache{message: message, response: output, status: status, sessionStatus: server.StatusDone}
			return
		}

		status, output = server.JsonResponse(nil, session.fail(server.ErrorInvalidRequest, ""))
		return
	}
}

func (s *Server) handleRevocationMessage(
	noun, method string, args []string, headers map[string][]string, message []byte,
) (int, []byte) {
	if noun == "records" && method == http.MethodGet {
		if len(args) != 2 {
			return server.JsonResponse(nil, server.RemoteError(server.ErrorInvalidRequest, "GET records expects 2 url arguments"))
		}
		index, err := strconv.Atoi(args[1])
		if err != nil {
			return server.JsonResponse(nil, server.RemoteError(server.ErrorMalformedInput, err.Error()))
		}
		cred := irma.NewCredentialTypeIdentifier(args[0])
		return server.JsonResponse(s.handleGetRevocationRecords(cred, index))
	}
	if noun == "records" && method == http.MethodPost {
		if len(args) != 1 {
			return server.JsonResponse(nil, server.RemoteError(server.ErrorInvalidRequest, "POST records expects 1 url arguments"))
		}
		cred := irma.NewCredentialTypeIdentifier(args[0])
		var records []*irma.RevocationRecord
		if err := json.Unmarshal(message, &records); err != nil {
			return server.JsonResponse(nil, server.RemoteError(server.ErrorMalformedInput, err.Error()))
		}
		return server.JsonResponse(s.handlePostRevocationRecords(cred, records))
	}
	if noun == "issuancerecord" && method == http.MethodPost {
		if len(args) != 2 {
			return server.JsonResponse(nil, server.RemoteError(server.ErrorInvalidRequest, "POST issuancercord expects 2 url arguments"))
		}
		cred := irma.NewCredentialTypeIdentifier(args[0])
		counter, err := strconv.Atoi(args[1])
		if err != nil {
			return server.JsonResponse(nil, server.RemoteError(server.ErrorMalformedInput, err.Error()))
		}
		return server.JsonResponse(s.handlePostIssuanceRecord(cred, counter, message))
	}

	return server.JsonResponse(nil, server.RemoteError(server.ErrorInvalidRequest, ""))
}
