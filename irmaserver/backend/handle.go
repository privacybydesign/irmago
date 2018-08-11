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

func handlePostResponse(session *session, message []byte) (int, []byte, *irmaserver.SessionResult) {
	if !session.alive() {
		return failSession(session, irmaserver.ErrorUnexpectedRequest, "")
	}

	switch session.action {

	case irma.ActionSigning:
		sig := &irma.SignedMessage{}
		if err := irma.UnmarshalValidate(message, sig); err != nil {
			return failSession(session, irmaserver.ErrorMalformedInput, "")
		}
		session.signature = sig
		session.disclosed, session.proofStatus = sig.Verify(conf.IrmaConfiguration, session.request.(*irma.SignatureRequest))
		s, b := responseJson(session.proofStatus)
		return s, b, finishSession(session)

	case irma.ActionDisclosing:
		pl := gabi.ProofList{}
		if err := irma.UnmarshalValidate(message, &pl); err != nil {
			return failSession(session, irmaserver.ErrorMalformedInput, "")
		}
		session.disclosed, session.proofStatus = irma.ProofList(pl).Verify(conf.IrmaConfiguration, session.request.(*irma.DisclosureRequest))
		s, b := responseJson(session.proofStatus)
		return s, b, finishSession(session)

	case irma.ActionIssuing:
		commitments := &gabi.IssueCommitmentMessage{}
		if err := irma.UnmarshalValidate(message, commitments); err != nil {
			return failSession(session, irmaserver.ErrorMalformedInput, "")
		}
		return session.issue(commitments)

	}

	return failSession(session, irmaserver.ErrorUnknown, "")
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
