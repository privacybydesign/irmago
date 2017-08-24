package protocol

import (
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"github.com/credentials/irmago"
	"github.com/mhe/gabi"
)

type PermissionHandler func(proceed bool, choice *irmago.DisclosureChoice)

// A Handler contains callbacks for communication to the user.
type Handler interface {
	StatusUpdate(action Action, status Status)
	Success(action Action)
	Cancelled(action Action)
	Failure(action Action, error SessionError, info string)
	UnsatisfiableRequest(action Action, missing irmago.AttributeDisjunctionList)

	AskIssuancePermission(request IssuanceRequest, ServerName string, choice PermissionHandler)
	AskVerificationPermission(request DisclosureRequest, ServerName string, choice PermissionHandler)
	AskSignaturePermission(request SignatureRequest, ServerName string, choice PermissionHandler)
}

// A Session is an IRMA session.
type Session struct {
	Action    Action
	Version   Version
	ServerURL string
	Handler   Handler

	request   irmago.DisjunctionListContainer
	spRequest *ServiceProviderJwt
	ipRequest *IdentityProviderJwt
	ssRequest *SignatureServerJwt

	transport *HTTPTransport
	nonce     *big.Int
	context   *big.Int
}

// NewSession creates and starts a new IRMA session.
func NewSession(qr *Qr, handler Handler) *Session {
	if qr.ProtocolVersion != "2.1" && qr.ProtocolVersion != "2.2" { // TODO version negotiation
		handler.Failure(ActionUnknown, ErrorProtocolVersionNotSupported, qr.ProtocolVersion)
		return nil
	}

	session := &Session{
		Version:   Version(qr.ProtocolVersion),
		Action:    Action(qr.Type),
		ServerURL: qr.URL,
		Handler:   handler,
		transport: NewHTTPTransport(qr.URL),
	}

	// Check if the action is one of the supported types
	switch session.Action {
	case ActionDisclosing: // nop
	case ActionSigning: // nop
	case ActionIssuing: // nop
	case ActionUnknown:
		fallthrough
	default:
		handler.Failure(ActionUnknown, ErrorUnknownAction, string(session.Action))
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
func (session *Session) start() {
	session.Handler.StatusUpdate(session.Action, StatusCommunicating)

	// Get the first IRMA protocol message
	info := &SessionInfo{}
	err := session.transport.Get("jwt", info)
	if err != nil {
		session.Handler.Failure(session.Action, ErrorTransport, err.Error())
		return
	}

	session.nonce = info.Nonce
	session.context = info.Context
	jwtparts := strings.Split(info.Jwt, ".")
	if jwtparts == nil || len(jwtparts) < 2 {
		session.Handler.Failure(session.Action, ErrorInvalidJWT, "")
		return
	}
	var header struct {
		Server string `json:"iss"`
	}
	json.Unmarshal([]byte(jwtparts[0]), &header)
	json.Unmarshal([]byte(jwtparts[1]), session.request)

	switch session.Action {
	case ActionDisclosing:
		session.spRequest = &ServiceProviderJwt{}
		session.request = session.spRequest
	case ActionSigning:
		session.ssRequest = &SignatureServerJwt{}
		session.request = session.ssRequest
	case ActionIssuing:
		session.ipRequest = &IdentityProviderJwt{}
		session.request = session.ipRequest
	default:
		panic("Invalid session type") // does not happen, session.Action has been checked earlier
	}

	if session.Action == ActionIssuing {
		// Store which public keys the server will use
		for _, credreq := range session.request.(*IdentityProviderJwt).Request.Request.Credentials {
			credreq.KeyCounter = info.Keys[credreq.Credential.IssuerIdentifier()]
		}
	}

	missing := irmago.Manager.CheckSatisfiability(session.request)
	if len(missing) > 0 {
		session.Handler.UnsatisfiableRequest(session.Action, missing)
		return
	}

	callback := PermissionHandler(func(proceed bool, choice *irmago.DisclosureChoice) {
		go session.do(proceed, choice)
	})

	session.Handler.StatusUpdate(session.Action, StatusConnected)
	switch session.Action {
	case ActionDisclosing:
		session.Handler.AskVerificationPermission(session.spRequest.Request.Request, header.Server, callback)
	case ActionSigning:
		session.Handler.AskSignaturePermission(session.ssRequest.Request.Request, header.Server, callback)
	case ActionIssuing:
		session.Handler.AskIssuancePermission(session.ipRequest.Request.Request, header.Server, callback)
	default:
		panic("Invalid session type") // does not happen, session.Action has been checked earlier
	}
}

func (session *Session) do(proceed bool, choice *irmago.DisclosureChoice) {
	if !proceed {
		session.Handler.Cancelled(session.Action)
		return
	}
	session.Handler.StatusUpdate(session.Action, StatusCommunicating)

	var proofs gabi.ProofList
	var err error
	switch session.Action {
	case ActionSigning:
		proofs, err = irmago.Manager.Proofs(choice, &session.ssRequest.Request.Request.Message)
	case ActionDisclosing:
		proofs, err = irmago.Manager.Proofs(choice, nil)
	case ActionIssuing:
		err = errors.New("Issuing not yet implemented")
	}
	if err != nil {
		session.Handler.Failure(session.Action, ErrorCrypto, err.Error())
		return
	}

	var response string
	session.transport.Post("proofs", &response, proofs)
	if response != "VALID" {
		session.Handler.Failure(session.Action, ErrorRejected, response)
		return
	}

	session.Handler.Success(session.Action)
}
