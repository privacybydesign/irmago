package servercore

import (
	"encoding/json"
	"net/http"
	"reflect"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
	"gopkg.in/antage/eventsource.v1"
)

// Session helpers

func (session *session) markAlive() {
	session.lastActive = time.Now()
	session.conf.Logger.WithFields(logrus.Fields{"session": session.token}).Debugf("Session marked active, expiry delayed")
}

func (session *session) setStatus(status server.Status) {
	session.conf.Logger.WithFields(logrus.Fields{"session": session.token, "prevStatus": session.prevStatus, "status": status}).
		Info("Session status updated")
	session.status = status
	session.result.Status = status
	session.sessions.update(session)
}

func (session *session) onUpdate() {
	if session.evtSource != nil {
		session.conf.Logger.WithFields(logrus.Fields{"session": session.token, "status": session.status}).
			Debug("Sending status to SSE listeners")
		session.evtSource.SendEventMessage(string(session.status), "", "")
	}
}

func (session *session) fail(err server.Error, message string) *irma.RemoteError {
	rerr := server.RemoteError(err, message)
	session.setStatus(server.StatusCancelled)
	session.result = &server.SessionResult{Err: rerr, Token: session.token, Status: server.StatusCancelled}
	return rerr
}

// Issuance helpers

func (s *Server) validateIssuanceRequest(request *irma.IssuanceRequest) error {
	for _, cred := range request.Credentials {
		// Check that we have the appropriate private key
		iss := cred.CredentialTypeID.IssuerIdentifier()
		privatekey, err := s.conf.PrivateKey(iss)
		if err != nil {
			return err
		}
		if privatekey == nil {
			return errors.Errorf("missing private key of issuer %s", iss.String())
		}
		pubkey, err := s.conf.IrmaConfiguration.PublicKey(iss, int(privatekey.Counter))
		if err != nil {
			return err
		}
		if pubkey == nil {
			return errors.Errorf("missing public key of issuer %s", iss.String())
		}
		cred.KeyCounter = int(privatekey.Counter)

		// Check that the credential is consistent with irma_configuration
		if err := cred.Validate(s.conf.IrmaConfiguration); err != nil {
			return err
		}

		// Ensure the credential has an expiry date
		defaultValidity := irma.Timestamp(time.Now().AddDate(0, 6, 0))
		if cred.Validity == nil {
			cred.Validity = &defaultValidity
		}
		if cred.Validity.Before(irma.Timestamp(time.Now())) {
			return errors.New("cannot issue expired credentials")
		}
	}

	return nil
}

func (session *session) getProofP(commitments *irma.IssueCommitmentMessage, scheme irma.SchemeManagerIdentifier) (*gabi.ProofP, error) {
	if session.kssProofs == nil {
		session.kssProofs = make(map[irma.SchemeManagerIdentifier]*gabi.ProofP)
	}

	if _, contains := session.kssProofs[scheme]; !contains {
		str, contains := commitments.ProofPjwts[scheme.Name()]
		if !contains {
			return nil, errors.Errorf("no keyshare proof included for scheme %s", scheme.Name())
		}
		session.conf.Logger.Debug("Parsing keyshare ProofP JWT: ", str)
		claims := &struct {
			jwt.StandardClaims
			ProofP *gabi.ProofP
		}{}
		token, err := jwt.ParseWithClaims(str, claims, session.conf.IrmaConfiguration.KeyshareServerKeyFunc(scheme))
		if err != nil {
			return nil, err
		}
		if !token.Valid {
			return nil, errors.Errorf("invalid keyshare proof included for scheme %s", scheme.Name())
		}
		session.kssProofs[scheme] = claims.ProofP
	}

	return session.kssProofs[scheme], nil
}

var eventHeaders = [][]byte{[]byte("Access-Control-Allow-Origin: *")}

func (session *session) eventSource() eventsource.EventSource {
	if session.evtSource != nil {
		return session.evtSource
	}

	session.conf.Logger.WithFields(logrus.Fields{"session": session.token}).Debug("Making server sent event source")
	session.evtSource = eventsource.New(nil, func(_ *http.Request) [][]byte { return eventHeaders })
	return session.evtSource
}

// Other

func chooseProtocolVersion(min, max *irma.ProtocolVersion) (*irma.ProtocolVersion, error) {
	if min.AboveVersion(maxProtocolVersion) || max.BelowVersion(minProtocolVersion) || max.BelowVersion(min) {
		return nil, server.LogWarning(errors.Errorf("Protocol version negotiation failed, min=%s max=%s", min.String(), max.String()))
	}
	if max.AboveVersion(maxProtocolVersion) {
		return maxProtocolVersion, nil
	} else {
		return max, nil
	}
}

// purgeRequest logs the request excluding any attribute values.
func purgeRequest(request irma.RequestorRequest) irma.RequestorRequest {
	// We want to log as much as possible of the request, but no attribute values.
	// We cannot just remove them from the request parameter as that would break the calling code.
	// So we create a deep copy of the request from which we can then safely remove whatever we want to.
	// Ugly hack alert: the easiest way to do this seems to be to convert it to JSON and then back.
	// As we do not know the precise type of request, we use reflection to create a new instance
	// of the same type as request, into which we then unmarshal our copy.
	cpy := reflect.New(reflect.TypeOf(request).Elem()).Interface()
	bts, _ := json.Marshal(request)
	_ = json.Unmarshal(bts, cpy)

	// Remove required attribute values from any attributes to be disclosed
	attrs := cpy.(irma.RequestorRequest).SessionRequest().ToDisclose()
	for _, disjunction := range attrs {
		disjunction.Values = nil
	}
	// Remove attribute values from attributes to be issued
	if isreq, ok := cpy.(*irma.IdentityProviderRequest); ok {
		for _, cred := range isreq.Request.Credentials {
			cred.Attributes = nil
		}
	}

	return cpy.(irma.RequestorRequest)
}
