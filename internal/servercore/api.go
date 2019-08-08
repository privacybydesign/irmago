// Package servercore is the core of the IRMA server library, allowing IRMA verifiers, issuers
// or attribute-based signature applications to perform IRMA sessions with irmaclient instances
// (i.e. the IRMA app). It exposes a small interface to expose to other programming languages
// through cgo. It is used by the irmaserver package but otherwise not meant for use in Go.
package servercore

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/jasonlvhit/gocron"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/revocation"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
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
	s.stopScheduler = s.scheduler.Start()

	return s, s.verifyConfiguration(s.conf)
}

func (s *Server) Stop() {
	if err := s.conf.IrmaConfiguration.Close(); err != nil {
		_ = server.LogWarning(err)
	}
	s.stopScheduler <- true
	s.sessions.stop()
}

func (s *Server) verifyIrmaConf(configuration *server.Configuration) error {
	if s.conf.IrmaConfiguration == nil {
		var (
			err    error
			exists bool
		)
		if s.conf.SchemesPath == "" {
			s.conf.SchemesPath = irma.DefaultSchemesPath() // Returns an existing path
		}
		if exists, err = fs.PathExists(s.conf.SchemesPath); err != nil {
			return server.LogError(err)
		}
		if !exists {
			return server.LogError(errors.Errorf("Nonexisting schemes_path provided: %s", s.conf.SchemesPath))
		}
		s.conf.Logger.WithField("schemes_path", s.conf.SchemesPath).Info("Determined schemes path")
		if s.conf.SchemesAssetsPath == "" {
			s.conf.IrmaConfiguration, err = irma.NewConfiguration(s.conf.SchemesPath)
		} else {
			s.conf.IrmaConfiguration, err = irma.NewConfigurationFromAssets(s.conf.SchemesPath, s.conf.SchemesAssetsPath)
		}
		if err != nil {
			return server.LogError(err)
		}
		if err = s.conf.IrmaConfiguration.ParseFolder(); err != nil {
			return server.LogError(err)
		}
		if err = fs.EnsureDirectoryExists(s.conf.RevocationPath); err != nil {
			return server.LogError(err)
		}
		s.conf.IrmaConfiguration.RevocationPath = s.conf.RevocationPath
	}

	if len(s.conf.IrmaConfiguration.SchemeManagers) == 0 {
		s.conf.Logger.Infof("No schemes found in %s, downloading default (irma-demo and pbdf)", s.conf.SchemesPath)
		if err := s.conf.IrmaConfiguration.DownloadDefaultSchemes(); err != nil {
			return server.LogError(err)
		}
	}

	if !s.conf.DisableSchemesUpdate {
		if s.conf.SchemesUpdateInterval == 0 {
			s.conf.SchemesUpdateInterval = 60
		}
		s.conf.IrmaConfiguration.AutoUpdateSchemes(uint(s.conf.SchemesUpdateInterval))
	} else {
		s.conf.SchemesUpdateInterval = 0
	}

	return nil
}

func (s *Server) verifyPrivateKeys(configuration *server.Configuration) error {
	if s.conf.IssuerPrivateKeys == nil {
		s.conf.IssuerPrivateKeys = make(map[irma.IssuerIdentifier]*gabi.PrivateKey)
	}
	if s.conf.IssuerPrivateKeysPath != "" {
		files, err := ioutil.ReadDir(s.conf.IssuerPrivateKeysPath)
		if err != nil {
			return server.LogError(err)
		}
		for _, file := range files {
			filename := file.Name()
			if filepath.Ext(filename) != ".xml" || filename[0] == '.' || strings.Count(filename, ".") != 2 {
				s.conf.Logger.WithField("file", filename).Infof("Skipping non-private key file encountered in private keys path")
				continue
			}
			issid := irma.NewIssuerIdentifier(strings.TrimSuffix(filename, filepath.Ext(filename))) // strip .xml
			if _, ok := s.conf.IrmaConfiguration.Issuers[issid]; !ok {
				return server.LogError(errors.Errorf("Private key %s belongs to an unknown issuer", filename))
			}
			sk, err := gabi.NewPrivateKeyFromFile(filepath.Join(s.conf.IssuerPrivateKeysPath, filename))
			if err != nil {
				return server.LogError(err)
			}
			s.conf.IssuerPrivateKeys[issid] = sk
		}
	}
	for issid, sk := range s.conf.IssuerPrivateKeys {
		pk, err := s.conf.IrmaConfiguration.PublicKey(issid, int(sk.Counter))
		if err != nil {
			return server.LogError(err)
		}
		if pk == nil {
			return server.LogError(errors.Errorf("Missing public key belonging to private key %s-%d", issid.String(), sk.Counter))
		}
		if new(big.Int).Mul(sk.P, sk.Q).Cmp(pk.N) != 0 {
			return server.LogError(errors.Errorf("Private key %s-%d does not belong to corresponding public key", issid.String(), sk.Counter))
		}
	}
	for issid := range s.conf.IrmaConfiguration.Issuers {
		sk, err := s.conf.PrivateKey(issid)
		if err != nil {
			return server.LogError(err)
		}
		if sk == nil || !sk.RevocationSupported() {
			continue
		}
		for credid, credtype := range s.conf.IrmaConfiguration.CredentialTypes {
			if credtype.IssuerIdentifier() != issid || !credtype.SupportsRevocation {
				continue
			}
			db, err := s.conf.IrmaConfiguration.RevocationDB(credid)
			if err != nil {
				return server.LogError(err)
			}
			if !db.Enabled() {
				s.conf.Logger.WithFields(logrus.Fields{"cred": credid}).Warn("revocation supported in scheme but not enabled")
			} else {
				if err = db.LoadCurrent(); err != nil {
					return server.LogError(err)
				}
				s.conf.RevocableCredentials[credid] = struct{}{}
			}
		}
	}

	return nil
}

func (s *Server) verifyURL(configuration *server.Configuration) error {
	if s.conf.URL != "" {
		if !strings.HasSuffix(s.conf.URL, "/") {
			s.conf.URL = s.conf.URL + "/"
		}
		if !strings.HasPrefix(s.conf.URL, "https://") {
			if !s.conf.Production || s.conf.DisableTLS {
				s.conf.DisableTLS = true
				s.conf.Logger.Warnf("TLS is not enabled on the url \"%s\" to which the IRMA app will connect. "+
					"Ensure that attributes are encrypted in transit by either enabling TLS or adding TLS in a reverse proxy.", s.conf.URL)
			} else {
				return server.LogError(errors.Errorf("Running without TLS in production mode is unsafe without a reverse proxy. " +
					"Either use a https:// URL or explicitly disable TLS."))
			}
		}
	} else {
		s.conf.Logger.Warn("No url parameter specified in configuration; unless an url is elsewhere prepended in the QR, the IRMA client will not be able to connect")
	}
	return nil
}

func (s *Server) verifyEmail(configuration *server.Configuration) error {
	if s.conf.Email != "" {
		// Very basic sanity checks
		if !strings.Contains(s.conf.Email, "@") || strings.Contains(s.conf.Email, "\n") {
			return server.LogError(errors.New("Invalid email address specified"))
		}
		t := irma.NewHTTPTransport("https://metrics.privacybydesign.foundation/history")
		t.SetHeader("User-Agent", "irmaserver")
		var x string
		_ = t.Post("email", &x, s.conf.Email)
	}
	return nil
}

func (s *Server) verifyConfiguration(configuration *server.Configuration) error {
	if s.conf.Logger == nil {
		s.conf.Logger = server.NewLogger(s.conf.Verbose, s.conf.Quiet, s.conf.LogJSON)
	}
	server.Logger = s.conf.Logger
	irma.Logger = s.conf.Logger

	// loop to avoid repetetive err != nil line triplets
	for _, f := range []func(*server.Configuration) error{s.verifyIrmaConf, s.verifyPrivateKeys, s.verifyURL, s.verifyEmail} {
		if err := f(configuration); err != nil {
			return err
		}
	}

	return nil
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

func ParsePath(path string) (token, noun string, arg []string, err error) {
	client := regexp.MustCompile("session/(\\w+)/?(|commitments|proofs|status|statusevents)$")
	matches := client.FindStringSubmatch(path)
	if len(matches) == 3 {
		return matches[1], matches[2], nil, nil
	}

	rev := regexp.MustCompile("-/revocation/(records)/?(.*)$")
	matches = rev.FindStringSubmatch(path)
	if len(matches) == 3 {
		args := strings.Split(matches[2], "/")
		return "", matches[1], args, nil
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
		var records []*revocation.Record
		if err := json.Unmarshal(message, &records); err != nil {
			return server.JsonResponse(nil, server.RemoteError(server.ErrorMalformedInput, err.Error()))
		}
		return server.JsonResponse(s.handlePostRevocationRecords(cred, records))
	}

	return server.JsonResponse(nil, server.RemoteError(server.ErrorInvalidRequest, ""))
}

func (s *Server) handlePostRevocationRecords(
	cred irma.CredentialTypeIdentifier, records []*revocation.Record,
) (interface{}, *irma.RemoteError) {
	if _, ok := s.conf.RevocableCredentials[cred]; !ok {
		return nil, server.RemoteError(server.ErrorInvalidRequest, "not supported by this server")
	}
	db, err := s.conf.IrmaConfiguration.RevocationDB(cred)
	if err != nil {
		return nil, server.RemoteError(server.ErrorUnknown, err.Error()) // TODO error type
	}
	for _, r := range records {
		if err = db.Add(r.Message, r.PublicKeyIndex); err != nil {
			return nil, server.RemoteError(server.ErrorUnknown, err.Error()) // TODO error type
		}
	}
	return nil, nil
}

func (s *Server) handleGetRevocationRecords(
	cred irma.CredentialTypeIdentifier, index int,
) ([]revocation.Record, *irma.RemoteError) {
	if _, ok := s.conf.RevocableCredentials[cred]; !ok {
		return nil, server.RemoteError(server.ErrorInvalidRequest, "not supported by this server")
	}
	db, err := s.conf.IrmaConfiguration.RevocationDB(cred)
	if err != nil {
		return nil, server.RemoteError(server.ErrorUnknown, err.Error()) // TODO error type
	}
	records, err := db.RevocationRecords(index)
	if err != nil {
		return nil, server.RemoteError(server.ErrorUnknown, err.Error()) // TODO error type
	}
	return records, nil
}
