package protocol

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"encoding/base64"
	"encoding/json"

	"github.com/credentials/irmago"
	"github.com/mhe/gabi"
)

// PermissionHandler is a callback for providing permission for an IRMA session
// and specifying the attributes to be disclosed.
type PermissionHandler func(proceed bool, choice *irmago.DisclosureChoice)

// A Handler contains callbacks for communication to the user.
type Handler interface {
	StatusUpdate(action Action, status Status)
	Success(action Action)
	Cancelled(action Action)
	Failure(action Action, err *irmago.Error)
	UnsatisfiableRequest(action Action, missing irmago.AttributeDisjunctionList)

	AskIssuancePermission(request irmago.IssuanceRequest, ServerName string, callback PermissionHandler)
	AskVerificationPermission(request irmago.DisclosureRequest, ServerName string, callback PermissionHandler)
	AskSignaturePermission(request irmago.SignatureRequest, ServerName string, callback PermissionHandler)
}

// A session is an IRMA session.
type session struct {
	Action    Action
	Version   Version
	ServerURL string
	Handler   Handler

	jwt         RequestorJwt
	irmaSession irmago.Session
	transport   *irmago.HTTPTransport
}

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
func NewSession(qr *Qr, handler Handler) {
	version, err := calcVersion(qr)
	if err != nil {
		handler.Failure(ActionUnknown, &irmago.Error{ErrorCode: irmago.ErrorProtocolVersionNotSupported, Err: err})
		return
	}

	session := &session{
		Version:   Version(version),
		Action:    Action(qr.Type),
		ServerURL: qr.URL,
		Handler:   handler,
		transport: irmago.NewHTTPTransport(qr.URL),
	}

	// Check if the action is one of the supported types
	switch session.Action {
	case ActionDisclosing: // nop
	case ActionSigning: // nop
	case ActionIssuing: // nop
	case ActionUnknown:
		fallthrough
	default:
		handler.Failure(ActionUnknown, &irmago.Error{ErrorCode: irmago.ErrorUnknownAction, Err: nil, Info: string(session.Action)})
		return
	}

	if !strings.HasSuffix(session.ServerURL, "/") {
		session.ServerURL += "/"
	}

	go session.start()

	return
}

// start retrieves the first message in the IRMA protocol, checks if we can perform
// the request, and informs the user of the outcome.
func (session *session) start() {
	session.Handler.StatusUpdate(session.Action, StatusCommunicating)

	// Get the first IRMA protocol message and parse it
	info := &SessionInfo{}
	Err := session.transport.Get("jwt", info)
	if Err != nil {
		session.Handler.Failure(session.Action, Err.(*irmago.Error))
		return
	}
	jwtparts := strings.Split(info.Jwt, ".")
	if jwtparts == nil || len(jwtparts) < 2 {
		session.Handler.Failure(session.Action, &irmago.Error{ErrorCode: irmago.ErrorInvalidJWT})
		return
	}
	headerbytes, err := base64.RawStdEncoding.DecodeString(jwtparts[0])
	if err != nil {
		session.Handler.Failure(session.Action, &irmago.Error{ErrorCode: irmago.ErrorInvalidJWT, Err: err})
		return
	}
	var header struct {
		Server string `json:"iss"`
	}
	err = json.Unmarshal([]byte(headerbytes), &header)
	if err != nil {
		session.Handler.Failure(session.Action, &irmago.Error{ErrorCode: irmago.ErrorInvalidJWT, Err: err})
		return
	}

	// Deserialize JWT, and set session state
	bodybytes, err := base64.RawStdEncoding.DecodeString(jwtparts[1])
	if err != nil {
		session.Handler.Failure(session.Action, &irmago.Error{ErrorCode: irmago.ErrorInvalidJWT, Err: err})
		return
	}
	switch session.Action {
	case ActionDisclosing:
		jwt := &ServiceProviderJwt{}
		err = json.Unmarshal([]byte(bodybytes), jwt)
		session.jwt = jwt
	case ActionSigning:
		jwt := &SignatureRequestorJwt{}
		err = json.Unmarshal([]byte(bodybytes), jwt)
		session.jwt = jwt
	case ActionIssuing:
		jwt := &IdentityProviderJwt{}
		err = json.Unmarshal([]byte(bodybytes), jwt)
		session.jwt = jwt
	default:
		panic("Invalid session type") // does not happen, session.Action has been checked earlier
	}
	if err != nil {
		session.Handler.Failure(session.Action, &irmago.Error{ErrorCode: irmago.ErrorInvalidJWT, Err: err})
		return
	}
	session.irmaSession = session.jwt.IrmaSession()
	session.irmaSession.SetContext(info.Context)
	session.irmaSession.SetNonce(info.Nonce)
	if session.Action == ActionIssuing {
		// Store which public keys the server will use
		for _, credreq := range session.irmaSession.(*irmago.IssuanceRequest).Credentials {
			credreq.KeyCounter = info.Keys[credreq.Credential.IssuerIdentifier()]
		}
	}

	missing := irmago.Manager.CheckSatisfiability(session.irmaSession.DisjunctionList())
	if len(missing) > 0 {
		session.Handler.UnsatisfiableRequest(session.Action, missing)
		return
	}

	// Ask for permission to execute the session
	callback := PermissionHandler(func(proceed bool, choice *irmago.DisclosureChoice) {
		go session.do(proceed, choice)
	})
	session.Handler.StatusUpdate(session.Action, StatusConnected)
	switch session.Action {
	case ActionDisclosing:
		session.Handler.AskVerificationPermission(*session.irmaSession.(*irmago.DisclosureRequest), header.Server, callback)
	case ActionSigning:
		session.Handler.AskSignaturePermission(*session.irmaSession.(*irmago.SignatureRequest), header.Server, callback)
	case ActionIssuing:
		session.Handler.AskIssuancePermission(*session.irmaSession.(*irmago.IssuanceRequest), header.Server, callback)
	default:
		panic("Invalid session type") // does not happen, session.Action has been checked earlier
	}
}

func (session *session) do(proceed bool, choice *irmago.DisclosureChoice) {
	if !proceed {
		session.Handler.Cancelled(session.Action)
		return
	}
	session.Handler.StatusUpdate(session.Action, StatusCommunicating)

	var message interface{}
	var err error
	switch session.Action {
	case ActionSigning:
		message, err = irmago.Manager.Proofs(choice, session.irmaSession, true)
	case ActionDisclosing:
		message, err = irmago.Manager.Proofs(choice, session.irmaSession, false)
	case ActionIssuing:
		message, err = irmago.Manager.IssueCommitments(choice, session.irmaSession.(*irmago.IssuanceRequest))
	}
	if err != nil {
		session.Handler.Failure(session.Action, &irmago.Error{ErrorCode: irmago.ErrorCrypto, Err: err})
		return
	}

	var Err *irmago.Error
	switch session.Action {
	case ActionSigning:
		fallthrough
	case ActionDisclosing:
		response := ""
		Err = session.transport.Post("proofs", &response, message).(*irmago.Error)
		if Err != nil {
			session.Handler.Failure(session.Action, Err)
			return
		}
		if response != "VALID" {
			session.Handler.Failure(session.Action, &irmago.Error{ErrorCode: irmago.ErrorRejected, Info: response})
			return
		}
	case ActionIssuing:
		response := []*gabi.IssueSignatureMessage{}
		Err = session.transport.Post("commitments", &response, message).(*irmago.Error)
		if Err != nil {
			session.Handler.Failure(session.Action, Err)
			return
		}

		err = irmago.Manager.ConstructCredentials(response, session.irmaSession.(*irmago.IssuanceRequest))
		if err != nil {
			session.Handler.Failure(session.Action, &irmago.Error{Err: err, ErrorCode: irmago.ErrorCrypto})
			return
		}
	}

	session.Handler.Success(session.Action)
}
