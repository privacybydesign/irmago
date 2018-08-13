package backend

import (
	"encoding/json"
	"net/http"
	"runtime/debug"

	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irmaserver"
)

var conf *irmaserver.Configuration

func (session *session) handleDelete() {
	if !session.alive() {
		return
	}
	session.result = &irmaserver.SessionResult{Token: session.token} // TODO what to return here?
	session.status = irmaserver.StatusCancelled
}

func (session *session) handleGetSession(min, max *irma.ProtocolVersion) (irma.SessionRequest, *irma.RemoteError) {
	var err error
	session.status = irmaserver.StatusConnected
	if session.version, err = chooseProtocolVersion(min, max); err != nil {
		return nil, session.fail(irmaserver.ErrorProtocolVersion, "")
	}
	session.request.SetVersion(session.version)
	return session.request, nil
}

func handleGetStatus(session *session) irmaserver.Status {
	return session.status
}

func (session *session) handlePostSignature(signature *irma.SignedMessage) (irma.ProofStatus, *irma.RemoteError) {
	session.signature = signature
	session.disclosed, session.proofStatus = signature.Verify(conf.IrmaConfiguration, session.request.(*irma.SignatureRequest))
	session.finish()
	return session.proofStatus, nil
}

func (session *session) handlePostProofs(proofs gabi.ProofList) (irma.ProofStatus, *irma.RemoteError) {
	session.disclosed, session.proofStatus = irma.ProofList(proofs).Verify(conf.IrmaConfiguration, session.request.(*irma.DisclosureRequest))
	session.finish()
	return session.proofStatus, nil
}

// Session helpers

func (session *session) alive() bool {
	return session.status != irmaserver.StatusDone && session.status != irmaserver.StatusCancelled
}

func (session *session) finish() {
	session.status = irmaserver.StatusDone
	session.result = &irmaserver.SessionResult{
		Token:     session.token,
		Status:    session.proofStatus,
		Disclosed: session.disclosed,
		Signature: session.signature,
	}
}

func (session *session) fail(err irmaserver.Error, message string) *irma.RemoteError {
	rerr := getError(err, message)
	session.status = irmaserver.StatusCancelled
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
