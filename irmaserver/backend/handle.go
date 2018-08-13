package backend

import (
	"encoding/json"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irmaserver"
)

var conf *irmaserver.Configuration

func (session *session) handleDelete() {
	if session.finished() {
		return
	}
	session.markAlive()
	// TODO const ProofStatusCancelled = irma.ProofStatus("CANCELLED") ?
	session.result = &irmaserver.SessionResult{Token: session.token}
	session.setStatus(irmaserver.StatusCancelled)
}

func (session *session) handleGetRequest(min, max *irma.ProtocolVersion) (irma.SessionRequest, *irma.RemoteError) {
	if session.status != irmaserver.StatusInitialized {
		return nil, getError(irmaserver.ErrorUnexpectedRequest, "Session already started")
	}
	session.markAlive()

	var err error
	if session.version, err = chooseProtocolVersion(min, max); err != nil {
		return nil, session.fail(irmaserver.ErrorProtocolVersion, "")
	}
	session.request.SetVersion(session.version)

	session.setStatus(irmaserver.StatusConnected)
	return session.request, nil
}

func handleGetStatus(session *session) irmaserver.Status {
	return session.status
}

func (session *session) handlePostSignature(signature *irma.SignedMessage) (*irma.ProofStatus, *irma.RemoteError) {
	if session.status != irmaserver.StatusConnected {
		return nil, getError(irmaserver.ErrorUnexpectedRequest, "Session not yet started or already finished")
	}
	session.markAlive()

	session.result.Signature = signature
	session.result.Disclosed, session.result.Status = signature.Verify(
		conf.IrmaConfiguration, session.request.(*irma.SignatureRequest))
	session.setStatus(irmaserver.StatusDone)
	return &session.result.Status, nil
}

func (session *session) handlePostProofs(proofs gabi.ProofList) (*irma.ProofStatus, *irma.RemoteError) {
	if session.status != irmaserver.StatusConnected {
		return nil, getError(irmaserver.ErrorUnexpectedRequest, "Session not yet started or already finished")
	}
	session.markAlive()

	session.result.Disclosed, session.result.Status = irma.ProofList(proofs).Verify(
		conf.IrmaConfiguration, session.request.(*irma.DisclosureRequest))
	session.setStatus(irmaserver.StatusDone)
	return &session.result.Status, nil
}

// Session helpers

func (session *session) finished() bool {
	return session.status == irmaserver.StatusDone || session.status == irmaserver.StatusCancelled
}

func (session *session) markAlive() {
	session.lastActive = time.Now()
}

func (session *session) setStatus(status irmaserver.Status) {
	session.status = status
}

func (session *session) fail(err irmaserver.Error, message string) *irma.RemoteError {
	rerr := getError(err, message)
	session.setStatus(irmaserver.StatusCancelled)
	session.result = &irmaserver.SessionResult{Err: rerr, Token: session.token}
	return rerr
}

// Output helpers

func getError(err irmaserver.Error, message string) *irma.RemoteError {
	stack := string(debug.Stack())
	conf.Logger.Errorf("Error: %d %s %s\n%s", err.Status, err.Type, message, stack)
	return &irma.RemoteError{
		Status:      err.Status,
		Description: err.Description,
		ErrorName:   string(err.Type),
		Message:     message,
		Stacktrace:  stack,
	}
}

func responseJson(v interface{}, err *irma.RemoteError) (int, []byte) {
	msg := v
	status := http.StatusOK
	if err != nil {
		msg = err
		status = err.Status
	}
	b, e := json.Marshal(msg)
	if e != nil {
		conf.Logger.Error("Failed to serialize response:", e.Error())
		return http.StatusInternalServerError, nil
	}
	return status, b
}
