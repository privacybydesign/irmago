package irmago

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

// This file contains the client side of the IRMA protocol, as well as the Handler interface
// which is used to communicate session info with the user.

// PermissionHandler is a callback for providing permission for an IRMA session
// and specifying the attributes to be disclosed.
type PermissionHandler func(proceed bool, choice *DisclosureChoice)

type PinHandler func(proceed bool, pin string)

// A Handler contains callbacks for communication to the user.
type Handler interface {
	StatusUpdate(action Action, status Status)
	Success(action Action)
	Cancelled(action Action)
	Failure(action Action, err *SessionError)
	UnsatisfiableRequest(action Action, missing AttributeDisjunctionList)
	MissingKeyshareEnrollment(manager SchemeManagerIdentifier)

	RequestIssuancePermission(request IssuanceRequest, ServerName string, callback PermissionHandler)
	RequestVerificationPermission(request DisclosureRequest, ServerName string, callback PermissionHandler)
	RequestSignaturePermission(request SignatureRequest, ServerName string, callback PermissionHandler)
	RequestSchemeManagerPermission(manager *SchemeManager, callback func(proceed bool))

	RequestPin(remainingAttempts int, callback PinHandler)
}

// A session is an IRMA session.
type session struct {
	Action    Action
	Version   Version
	ServerURL string
	Handler   Handler

	info        *SessionInfo
	credManager *CredentialManager
	jwt         RequestorJwt
	irmaSession IrmaSession
	transport   *HTTPTransport
	choice      *DisclosureChoice
	downloaded  *IrmaIdentifierSet
}

// We implement the handler for the keyshare protocol
var _ keyshareSessionHandler = (*session)(nil)

// Supported protocol versions. Minor version numbers should be reverse sorted.
var supportedVersions = map[int][]int{
	2: {2, 1},
}

func calcVersion(qr *Qr) (string, error) {
	// Parse range supported by server
	var minmajor, minminor, maxmajor, maxminor int
	var err error
	if minmajor, err = strconv.Atoi(string(qr.ProtocolVersion[0])); err != nil {
		return "", err
	}
	if minminor, err = strconv.Atoi(string(qr.ProtocolVersion[2])); err != nil {
		return "", err
	}
	if maxmajor, err = strconv.Atoi(string(qr.ProtocolMaxVersion[0])); err != nil {
		return "", err
	}
	if maxminor, err = strconv.Atoi(string(qr.ProtocolMaxVersion[2])); err != nil {
		return "", err
	}

	// Iterate supportedVersions in reverse sorted order (i.e. biggest major number first)
	keys := make([]int, 0, len(supportedVersions))
	for k := range supportedVersions {
		keys = append(keys, k)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(keys)))
	for _, major := range keys {
		for _, minor := range supportedVersions[major] {
			aboveMinimum := major > minmajor || (major == minmajor && minor >= minminor)
			underMaximum := major < maxmajor || (major == maxmajor && minor <= maxminor)
			if aboveMinimum && underMaximum {
				return fmt.Sprintf("%d.%d", major, minor), nil
			}
		}
	}
	return "", fmt.Errorf("No supported protocol version between %s and %s", qr.ProtocolVersion, qr.ProtocolMaxVersion)
}

// NewSession creates and starts a new IRMA session.
func (cm *CredentialManager) NewSession(qr *Qr, handler Handler) {
	session := &session{
		Action:      Action(qr.Type),
		ServerURL:   qr.URL,
		Handler:     handler,
		transport:   NewHTTPTransport(qr.URL),
		credManager: cm,
	}
	version, err := calcVersion(qr)
	if err != nil {
		session.fail(&SessionError{ErrorType: ErrorProtocolVersionNotSupported, Err: err})
		return
	}
	session.Version = Version(version)

	// Check if the action is one of the supported types
	switch session.Action {
	case ActionDisclosing: // nop
	case ActionSigning: // nop
	case ActionIssuing: // nop
	//case ActionSchemeManager: // nop
	case ActionUnknown:
		fallthrough
	default:
		session.fail(&SessionError{ErrorType: ErrorUnknownAction, Info: string(session.Action)})
		return
	}

	if !strings.HasSuffix(session.ServerURL, "/") {
		session.ServerURL += "/"
	}

	go session.start()

	return
}

func (session *session) fail(err *SessionError) {
	session.transport.Delete()
	err.Err = errors.Wrap(err.Err, 0)
	if session.downloaded != nil && !session.downloaded.Empty() {
		session.credManager.handler.UpdateConfigurationStore(session.downloaded)
	}
	session.Handler.Failure(session.Action, err)
}

func (session *session) cancel() {
	session.transport.Delete()
	if session.downloaded != nil && !session.downloaded.Empty() {
		session.credManager.handler.UpdateConfigurationStore(session.downloaded)
	}
	session.Handler.Cancelled(session.Action)
}

// start retrieves the first message in the IRMA protocol, checks if we can perform
// the request, and informs the user of the outcome.
func (session *session) start() {
	session.Handler.StatusUpdate(session.Action, StatusCommunicating)

	if session.Action == ActionSchemeManager {
		session.managerSession()
		return
	}

	// Get the first IRMA protocol message and parse it
	session.info = &SessionInfo{}
	Err := session.transport.Get("jwt", session.info)
	if Err != nil {
		session.fail(Err.(*SessionError))
		return
	}

	var err error
	session.jwt, err = parseRequestorJwt(session.Action, session.info.Jwt)
	if err != nil {
		session.fail(&SessionError{ErrorType: ErrorInvalidJWT, Err: err})
		return
	}
	session.irmaSession = session.jwt.IrmaSession()
	session.irmaSession.SetContext(session.info.Context)
	session.irmaSession.SetNonce(session.info.Nonce)
	if session.Action == ActionIssuing {
		ir := session.irmaSession.(*IssuanceRequest)
		// Store which public keys the server will use
		for _, credreq := range ir.Credentials {
			credreq.KeyCounter = session.info.Keys[credreq.CredentialTypeID.IssuerIdentifier()]
		}
	}

	// Check if we are enrolled into all involved keyshare servers
	for id := range session.irmaSession.Identifiers().SchemeManagers {
		manager, ok := session.credManager.ConfigurationStore.SchemeManagers[id]
		if !ok {
			session.fail(&SessionError{ErrorType: ErrorUnknownSchemeManager, Info: id.String()})
			return
		}
		distributed := manager.Distributed()
		_, enrolled := session.credManager.keyshareServers[id]
		if distributed && !enrolled {
			session.transport.Delete()
			session.Handler.MissingKeyshareEnrollment(id)
			return
		}
	}

	// Download missing credential types/issuers/public keys from the scheme manager
	if session.downloaded, err = session.credManager.ConfigurationStore.Download(session.irmaSession.Identifiers()); err != nil {
		session.Handler.Failure(
			session.Action,
			&SessionError{ErrorType: ErrorConfigurationStoreDownload, Err: err},
		)
		return
	}

	if session.Action == ActionIssuing {
		ir := session.irmaSession.(*IssuanceRequest)
		for _, credreq := range ir.Credentials {
			info, err := credreq.Info(session.credManager.ConfigurationStore)
			if err != nil {
				session.fail(&SessionError{ErrorType: ErrorUnknownCredentialType, Err: err})
				return
			}
			ir.CredentialInfoList = append(ir.CredentialInfoList, info)
		}
	}

	candidates, missing := session.credManager.CheckSatisfiability(session.irmaSession.ToDisclose())
	if len(missing) > 0 {
		session.Handler.UnsatisfiableRequest(session.Action, missing)
		// TODO: session.transport.Delete() on dialog cancel
		return
	}
	session.irmaSession.SetCandidates(candidates)

	// Ask for permission to execute the session
	callback := PermissionHandler(func(proceed bool, choice *DisclosureChoice) {
		session.choice = choice
		session.irmaSession.SetDisclosureChoice(choice)
		go session.do(proceed)
	})
	session.Handler.StatusUpdate(session.Action, StatusConnected)
	switch session.Action {
	case ActionDisclosing:
		session.Handler.RequestVerificationPermission(
			*session.irmaSession.(*DisclosureRequest), session.jwt.Requestor(), callback)
	case ActionSigning:
		session.Handler.RequestSignaturePermission(
			*session.irmaSession.(*SignatureRequest), session.jwt.Requestor(), callback)
	case ActionIssuing:
		session.Handler.RequestIssuancePermission(
			*session.irmaSession.(*IssuanceRequest), session.jwt.Requestor(), callback)
	default:
		panic("Invalid session type") // does not happen, session.Action has been checked earlier
	}
}

func (session *session) do(proceed bool) {
	if !proceed {
		session.cancel()
		return
	}
	session.Handler.StatusUpdate(session.Action, StatusCommunicating)

	if !session.irmaSession.Identifiers().Distributed(session.credManager.ConfigurationStore) {
		var message interface{}
		var err error
		switch session.Action {
		case ActionSigning:
			message, err = session.credManager.Proofs(session.choice, session.irmaSession, true)
		case ActionDisclosing:
			message, err = session.credManager.Proofs(session.choice, session.irmaSession, false)
		case ActionIssuing:
			message, err = session.credManager.IssueCommitments(session.irmaSession.(*IssuanceRequest))
		}
		if err != nil {
			session.fail(&SessionError{ErrorType: ErrorCrypto, Err: err})
			return
		}
		session.sendResponse(message)
	} else {
		var builders gabi.ProofBuilderList
		var err error
		switch session.Action {
		case ActionSigning:
			fallthrough
		case ActionDisclosing:
			builders, err = session.credManager.ProofBuilders(session.choice)
		case ActionIssuing:
			builders, err = session.credManager.IssuanceProofBuilders(session.irmaSession.(*IssuanceRequest))
		}
		if err != nil {
			session.fail(&SessionError{ErrorType: ErrorCrypto, Err: err})
		}

		startKeyshareSession(
			session,
			session.Handler,
			builders,
			session.irmaSession,
			session.credManager.ConfigurationStore,
			session.credManager.keyshareServers,
		)
	}
}

func (session *session) KeyshareDone(message interface{}) {
	session.sendResponse(message)
}

func (session *session) KeyshareCancelled() {
	session.cancel()
}

func (session *session) KeyshareBlocked(duration int) {
	session.fail(&SessionError{ErrorType: ErrorKeyshareBlocked, Info: strconv.Itoa(duration)})
}

func (session *session) KeyshareError(err error) {
	session.fail(&SessionError{ErrorType: ErrorKeyshare, Err: err})
}

type disclosureResponse string

func (session *session) sendResponse(message interface{}) {
	var log *LogEntry
	var err error

	switch session.Action {
	case ActionSigning:
		fallthrough
	case ActionDisclosing:
		var response disclosureResponse
		if err = session.transport.Post("proofs", &response, message); err != nil {
			session.fail(err.(*SessionError))
			return
		}
		if response != "VALID" {
			session.fail(&SessionError{ErrorType: ErrorRejected, Info: string(response)})
			return
		}
		log, _ = session.createLogEntry(message.(gabi.ProofList)) // TODO err
	case ActionIssuing:
		response := []*gabi.IssueSignatureMessage{}
		if err = session.transport.Post("commitments", &response, message); err != nil {
			session.fail(err.(*SessionError))
			return
		}
		if err = session.credManager.ConstructCredentials(response, session.irmaSession.(*IssuanceRequest)); err != nil {
			session.fail(&SessionError{ErrorType: ErrorCrypto, Err: err})
			return
		}
		log, _ = session.createLogEntry(message) // TODO err
	}

	_ = session.credManager.addLogEntry(log) // TODO err
	if !session.downloaded.Empty() {
		session.credManager.handler.UpdateConfigurationStore(session.downloaded)
	}
	if session.Action == ActionIssuing {
		session.credManager.handler.UpdateAttributes()
	}
	session.Handler.Success(session.Action)
}

func (session *session) managerSession() {
	manager, err := session.credManager.ConfigurationStore.DownloadSchemeManager(session.ServerURL)
	if err != nil {
		session.Handler.Failure(session.Action, &SessionError{Err: err}) // TODO
		return
	}
	session.Handler.RequestSchemeManagerPermission(manager, func(proceed bool) {
		if !proceed {
			session.Handler.Cancelled(session.Action) // No need to DELETE session here
			return
		}
		if err := session.credManager.ConfigurationStore.AddSchemeManager(manager); err != nil {
			session.Handler.Failure(session.Action, &SessionError{})
			return
		}
		if manager.Distributed() {
			session.credManager.UnenrolledKeyshareServers = session.credManager.unenrolledKeyshareServers()
		}
		session.credManager.handler.UpdateConfigurationStore(
			&IrmaIdentifierSet{
				SchemeManagers:  map[SchemeManagerIdentifier]struct{}{manager.Identifier(): {}},
				Issuers:         map[IssuerIdentifier]struct{}{},
				CredentialTypes: map[CredentialTypeIdentifier]struct{}{},
			},
		)
		session.Handler.Success(session.Action)
	})
	return
}
