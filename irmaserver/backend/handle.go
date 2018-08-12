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

func handleDelete(session *session) (int, []byte, *irmaserver.SessionResult) {
	var res *irmaserver.SessionResult
	if session.alive() {
		res = &irmaserver.SessionResult{Token: session.token} // TODO what to return here?
	}
	session.status = irmaserver.StatusCancelled
	return http.StatusOK, nil, res
}

func handleGetSession(session *session, min, max *irma.ProtocolVersion) (int, []byte, *irmaserver.SessionResult) {
	var err error
	session.status = irmaserver.StatusConnected
	if session.version, err = chooseProtocolVersion(min, max); err != nil {
		return failSession(session, irmaserver.ErrorProtocolVersion, "")
	}
	session.request.SetVersion(session.version)
	s, b := responseJson(session.request)
	return s, b, nil
}

func handleGetStatus(session *session) (int, []byte, *irmaserver.SessionResult) {
	b, _ := json.Marshal(session.status)
	return http.StatusOK, b, nil
}

func handlePostCommitments(session *session, commitments *gabi.IssueCommitmentMessage) (int, []byte, *irmaserver.SessionResult) {
	return session.issue(commitments)
}

func handlePostSignature(session *session, signature *irma.SignedMessage) (int, []byte, *irmaserver.SessionResult) {
	session.signature = signature
	session.disclosed, session.proofStatus = signature.Verify(conf.IrmaConfiguration, session.request.(*irma.SignatureRequest))
	s, b := responseJson(session.proofStatus)
	return s, b, finishSession(session)
}

func handlePostProofs(session *session, proofs gabi.ProofList) (int, []byte, *irmaserver.SessionResult) {
	session.disclosed, session.proofStatus = irma.ProofList(proofs).Verify(conf.IrmaConfiguration, session.request.(*irma.DisclosureRequest))
	s, b := responseJson(session.proofStatus)
	return s, b, finishSession(session)
}

func responseJson(v interface{}) (int, []byte) {
	b, err := json.Marshal(v)
	if err != nil {
		return http.StatusInternalServerError, nil // TODO
	}
	return http.StatusOK, b
}

func (session *session) alive() bool {
	return session.status != irmaserver.StatusDone && session.status != irmaserver.StatusCancelled
}

func finishSession(session *session) *irmaserver.SessionResult {
	session.status = irmaserver.StatusDone
	return &irmaserver.SessionResult{
		Token:     session.token,
		Status:    session.proofStatus,
		Disclosed: session.disclosed,
		Signature: session.signature,
	}
}

func failSession(session *session, err irmaserver.Error, message string) (int, []byte, *irmaserver.SessionResult) {
	rerr := &irma.RemoteError{
		Status:      err.Status,
		Description: err.Description,
		ErrorName:   string(err.Type),
		Message:     message,
		Stacktrace:  string(debug.Stack()),
	}
	conf.Logger.Errorf("Error: %d %s %s\n%s", rerr.Status, rerr.ErrorName, rerr.Message, rerr.Stacktrace)

	var res *irmaserver.SessionResult
	if session != nil {
		if session.alive() {
			res = &irmaserver.SessionResult{Err: rerr, Token: session.token}
		}
		session.status = irmaserver.StatusCancelled
	}
	b, _ := json.Marshal(rerr)
	return err.Status, b, res
}
