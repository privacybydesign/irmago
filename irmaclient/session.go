package irmaclient

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"math/big"

	"github.com/credentials/irmago"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

// This file contains the client side of the IRMA protocol, as well as the Handler interface
// which is used to communicate session info with the user.

// PermissionHandler is a callback for providing permission for an IRMA session
// and specifying the attributes to be disclosed.
type PermissionHandler func(proceed bool, choice *irmago.DisclosureChoice)

type PinHandler func(proceed bool, pin string)

// A Handler contains callbacks for communication to the user.
type Handler interface {
	StatusUpdate(action irmago.Action, status irmago.Status)
	Success(action irmago.Action)
	Cancelled(action irmago.Action)
	Failure(action irmago.Action, err *irmago.SessionError)
	UnsatisfiableRequest(action irmago.Action, missing irmago.AttributeDisjunctionList)
	MissingKeyshareEnrollment(manager irmago.SchemeManagerIdentifier)

	RequestIssuancePermission(request irmago.IssuanceRequest, ServerName string, callback PermissionHandler)
	RequestVerificationPermission(request irmago.DisclosureRequest, ServerName string, callback PermissionHandler)
	RequestSignaturePermission(request irmago.SignatureRequest, ServerName string, callback PermissionHandler)
	RequestSchemeManagerPermission(manager *irmago.SchemeManager, callback func(proceed bool))

	RequestPin(remainingAttempts int, callback PinHandler)
}

type SessionDismisser interface {
	Dismiss()
}

// A session is an IRMA session.
type session struct {
	Action    irmago.Action
	Version   irmago.Version
	ServerURL string
	Handler   Handler

	info        *irmago.SessionInfo
	client      *Client
	jwt         irmago.RequestorJwt
	irmaSession irmago.IrmaSession
	transport   *irmago.HTTPTransport
	choice      *irmago.DisclosureChoice
	downloaded  *irmago.IrmaIdentifierSet
	done        bool
}

// We implement the handler for the keyshare protocol
var _ keyshareSessionHandler = (*session)(nil)

// Supported protocol versions. Minor version numbers should be reverse sorted.
var supportedVersions = map[int][]int{
	2: {2, 1},
}

func calcVersion(qr *irmago.Qr) (string, error) {
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
func (client *Client) NewSession(qr *irmago.Qr, handler Handler) SessionDismisser {
	session := &session{
		Action:    irmago.Action(qr.Type),
		ServerURL: qr.URL,
		Handler:   handler,
		transport: irmago.NewHTTPTransport(qr.URL),
		client:    client,
	}
	version, err := calcVersion(qr)
	if err != nil {
		session.fail(&irmago.SessionError{ErrorType: irmago.ErrorProtocolVersionNotSupported, Err: err})
		return nil
	}
	session.Version = irmago.Version(version)

	// Check if the action is one of the supported types
	switch session.Action {
	case irmago.ActionDisclosing: // nop
	case irmago.ActionSigning: // nop
	case irmago.ActionIssuing: // nop
	//case irmago.ActionSchemeManager: // nop
	case irmago.ActionUnknown:
		fallthrough
	default:
		session.fail(&irmago.SessionError{ErrorType: irmago.ErrorUnknownAction, Info: string(session.Action)})
		return nil
	}

	if !strings.HasSuffix(session.ServerURL, "/") {
		session.ServerURL += "/"
	}

	go session.start()

	return session
}

// start retrieves the first message in the IRMA protocol, checks if we can perform
// the request, and informs the user of the outcome.
func (session *session) start() {
	defer func() {
		handlePanic(func(err *irmago.SessionError) {
			if session.Handler != nil {
				session.Handler.Failure(session.Action, err)
			}
		})
	}()

	session.Handler.StatusUpdate(session.Action, irmago.StatusCommunicating)

	if session.Action == irmago.ActionSchemeManager {
		session.managerSession()
		return
	}

	// Get the first IRMA protocol message and parse it
	session.info = &irmago.SessionInfo{}
	Err := session.transport.Get("jwt", session.info)
	if Err != nil {
		session.fail(Err.(*irmago.SessionError))
		return
	}

	var err error
	session.jwt, err = irmago.ParseRequestorJwt(session.Action, session.info.Jwt)
	if err != nil {
		session.fail(&irmago.SessionError{ErrorType: irmago.ErrorInvalidJWT, Err: err})
		return
	}
	session.irmaSession = session.jwt.IrmaSession()
	session.irmaSession.SetContext(session.info.Context)
	session.irmaSession.SetNonce(session.info.Nonce)
	if session.Action == irmago.ActionIssuing {
		ir := session.irmaSession.(*irmago.IssuanceRequest)
		// Store which public keys the server will use
		for _, credreq := range ir.Credentials {
			credreq.KeyCounter = session.info.Keys[credreq.CredentialTypeID.IssuerIdentifier()]
		}
	}

	// Check if we are enrolled into all involved keyshare servers
	for id := range session.irmaSession.Identifiers().SchemeManagers {
		manager, ok := session.client.ConfigurationStore.SchemeManagers[id]
		if !ok {
			session.fail(&irmago.SessionError{ErrorType: irmago.ErrorUnknownSchemeManager, Info: id.String()})
			return
		}
		distributed := manager.Distributed()
		_, enrolled := session.client.keyshareServers[id]
		if distributed && !enrolled {
			session.delete()
			session.Handler.MissingKeyshareEnrollment(id)
			return
		}
	}

	// Download missing credential types/issuers/public keys from the scheme manager
	if session.downloaded, err = session.client.ConfigurationStore.Download(session.irmaSession.Identifiers()); err != nil {
		session.Handler.Failure(
			session.Action,
			&irmago.SessionError{ErrorType: irmago.ErrorConfigurationStoreDownload, Err: err},
		)
		return
	}

	if session.Action == irmago.ActionIssuing {
		ir := session.irmaSession.(*irmago.IssuanceRequest)
		for _, credreq := range ir.Credentials {
			info, err := credreq.Info(session.client.ConfigurationStore)
			if err != nil {
				session.fail(&irmago.SessionError{ErrorType: irmago.ErrorUnknownCredentialType, Err: err})
				return
			}
			ir.CredentialInfoList = append(ir.CredentialInfoList, info)
		}
	}

	candidates, missing := session.client.CheckSatisfiability(session.irmaSession.ToDisclose())
	if len(missing) > 0 {
		session.Handler.UnsatisfiableRequest(session.Action, missing)
		// TODO: session.transport.Delete() on dialog cancel
		return
	}
	session.irmaSession.SetCandidates(candidates)

	// Ask for permission to execute the session
	callback := PermissionHandler(func(proceed bool, choice *irmago.DisclosureChoice) {
		session.choice = choice
		session.irmaSession.SetDisclosureChoice(choice)
		go session.do(proceed)
	})
	session.Handler.StatusUpdate(session.Action, irmago.StatusConnected)
	switch session.Action {
	case irmago.ActionDisclosing:
		session.Handler.RequestVerificationPermission(
			*session.irmaSession.(*irmago.DisclosureRequest), session.jwt.Requestor(), callback)
	case irmago.ActionSigning:
		session.Handler.RequestSignaturePermission(
			*session.irmaSession.(*irmago.SignatureRequest), session.jwt.Requestor(), callback)
	case irmago.ActionIssuing:
		session.Handler.RequestIssuancePermission(
			*session.irmaSession.(*irmago.IssuanceRequest), session.jwt.Requestor(), callback)
	default:
		panic("Invalid session type") // does not happen, session.Action has been checked earlier
	}
}

func (session *session) do(proceed bool) {
	defer func() {
		handlePanic(func(err *irmago.SessionError) {
			if session.Handler != nil {
				session.Handler.Failure(session.Action, err)
			}
		})
	}()

	if !proceed {
		session.cancel()
		return
	}
	session.Handler.StatusUpdate(session.Action, irmago.StatusCommunicating)

	if !session.irmaSession.Identifiers().Distributed(session.client.ConfigurationStore) {
		var message interface{}
		var err error
		switch session.Action {
		case irmago.ActionSigning:
			message, err = session.client.Proofs(session.choice, session.irmaSession, true)
		case irmago.ActionDisclosing:
			message, err = session.client.Proofs(session.choice, session.irmaSession, false)
		case irmago.ActionIssuing:
			message, err = session.client.IssueCommitments(session.irmaSession.(*irmago.IssuanceRequest))
		}
		if err != nil {
			session.fail(&irmago.SessionError{ErrorType: irmago.ErrorCrypto, Err: err})
			return
		}
		session.sendResponse(message)
	} else {
		var builders gabi.ProofBuilderList
		var err error
		switch session.Action {
		case irmago.ActionSigning:
			fallthrough
		case irmago.ActionDisclosing:
			builders, err = session.client.ProofBuilders(session.choice)
		case irmago.ActionIssuing:
			builders, err = session.client.IssuanceProofBuilders(session.irmaSession.(*irmago.IssuanceRequest))
		}
		if err != nil {
			session.fail(&irmago.SessionError{ErrorType: irmago.ErrorCrypto, Err: err})
		}

		startKeyshareSession(
			session,
			session.Handler,
			builders,
			session.irmaSession,
			session.client.ConfigurationStore,
			session.client.keyshareServers,
			session.client.state,
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
	session.fail(&irmago.SessionError{ErrorType: irmago.ErrorKeyshareBlocked, Info: strconv.Itoa(duration)})
}

func (session *session) KeyshareError(err error) {
	session.fail(&irmago.SessionError{ErrorType: irmago.ErrorKeyshare, Err: err})
}

type disclosureResponse string

func (session *session) sendResponse(message interface{}) {
	var log *LogEntry
	var err error

	switch session.Action {
	case irmago.ActionSigning:
		fallthrough
	case irmago.ActionDisclosing:
		var response disclosureResponse
		if err = session.transport.Post("proofs", &response, message); err != nil {
			session.fail(err.(*irmago.SessionError))
			return
		}
		if response != "VALID" {
			session.fail(&irmago.SessionError{ErrorType: irmago.ErrorRejected, Info: string(response)})
			return
		}
		log, _ = session.createLogEntry(message.(gabi.ProofList)) // TODO err
	case irmago.ActionIssuing:
		response := []*gabi.IssueSignatureMessage{}
		if err = session.transport.Post("commitments", &response, message); err != nil {
			session.fail(err.(*irmago.SessionError))
			return
		}
		if err = session.client.ConstructCredentials(response, session.irmaSession.(*irmago.IssuanceRequest)); err != nil {
			session.fail(&irmago.SessionError{ErrorType: irmago.ErrorCrypto, Err: err})
			return
		}
		log, _ = session.createLogEntry(message) // TODO err
	}

	_ = session.client.addLogEntry(log) // TODO err
	if !session.downloaded.Empty() {
		session.client.handler.UpdateConfigurationStore(session.downloaded)
	}
	if session.Action == irmago.ActionIssuing {
		session.client.handler.UpdateAttributes()
	}
	session.done = true
	session.Handler.Success(session.Action)
}

func (session *session) managerSession() {
	manager, err := session.client.ConfigurationStore.DownloadSchemeManager(session.ServerURL)
	if err != nil {
		session.Handler.Failure(session.Action, &irmago.SessionError{Err: err}) // TODO
		return
	}
	session.Handler.RequestSchemeManagerPermission(manager, func(proceed bool) {
		if !proceed {
			session.Handler.Cancelled(session.Action) // No need to DELETE session here
			return
		}
		if err := session.client.ConfigurationStore.AddSchemeManager(manager); err != nil {
			session.Handler.Failure(session.Action, &irmago.SessionError{})
			return
		}
		if manager.Distributed() {
			session.client.UnenrolledSchemeManagers = session.client.unenrolledSchemeManagers()
		}
		session.client.handler.UpdateConfigurationStore(
			&irmago.IrmaIdentifierSet{
				SchemeManagers:  map[irmago.SchemeManagerIdentifier]struct{}{manager.Identifier(): {}},
				Issuers:         map[irmago.IssuerIdentifier]struct{}{},
				CredentialTypes: map[irmago.CredentialTypeIdentifier]struct{}{},
			},
		)
		session.Handler.Success(session.Action)
	})
	return
}

// Session lifetime functions

func handlePanic(callback func(*irmago.SessionError)) {
	if e := recover(); e != nil {
		var info string
		switch x := e.(type) {
		case string:
			info = x
		case error:
			info = x.Error()
		case fmt.Stringer:
			info = x.String()
		default: // nop
		}
		fmt.Printf("Recovered from panic: '%v'\n%s\n", e, info)
		if callback != nil {
			callback(&irmago.SessionError{ErrorType: irmago.ErrorPanic, Info: info})
		}
	}
}

// Idempotently send DELETE to remote server, returning whether or not we did something
func (session *session) delete() bool {
	if !session.done {
		session.transport.Delete()
		session.done = true
		return true
	}
	return false
}

func (session *session) fail(err *irmago.SessionError) {
	if session.delete() {
		err.Err = errors.Wrap(err.Err, 0)
		if session.downloaded != nil && !session.downloaded.Empty() {
			session.client.handler.UpdateConfigurationStore(session.downloaded)
		}
		session.Handler.Failure(session.Action, err)
	}
}

func (session *session) cancel() {
	if session.delete() {
		if session.downloaded != nil && !session.downloaded.Empty() {
			session.client.handler.UpdateConfigurationStore(session.downloaded)
		}
		session.Handler.Cancelled(session.Action)
	}
}

func (session *session) Dismiss() {
	session.cancel()
}

type issuanceState struct {
	nonce2   *big.Int
	builders []*gabi.CredentialBuilder
}

func newIssuanceState() (*issuanceState, error) {
	nonce2, err := gabi.RandomBigInt(gabi.DefaultSystemParameters[4096].Lstatzk)
	if err != nil {
		return nil, err
	}
	return &issuanceState{
		nonce2:   nonce2,
		builders: []*gabi.CredentialBuilder{},
	}, nil
}
