package servercore

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
		// We send JSON like the other APIs, so quote
		session.evtSource.SendEventMessage(fmt.Sprintf(`"%s"`, session.status), "", "")
	}
}

func (session *session) fail(err server.Error, message string) *irma.RemoteError {
	rerr := server.RemoteError(err, message)
	session.setStatus(server.StatusCancelled)
	session.result = &server.SessionResult{Err: rerr, Token: session.token, Status: server.StatusCancelled, Type: session.action}
	return rerr
}

const retryTimeLimit = 5 * time.Second

// checkCache returns a previously cached response, for replaying against multiple requests from
// irmago's retryablehttp client, if:
// - the same was POSTed as last time
// - last time was not more than 5 seconds ago (retryablehttp client gives up before this)
// - the status is now done (which it should be if this is the second time we receive this message).
func (session *session) checkCache(message []byte, expectedStatus server.Status) (int, []byte) {
	if len(session.responseCache.response) > 0 {
		if session.responseCache.sessionStatus != expectedStatus {
			// don't replay a cache value that was set in a previous session state
			session.responseCache = responseCache{}
			return 0, nil
		}
		if sha256.Sum256(session.responseCache.message) != sha256.Sum256(message) ||
			session.lastActive.Before(time.Now().Add(-retryTimeLimit)) ||
			session.status != expectedStatus {
			return server.JsonResponse(nil, session.fail(server.ErrorUnexpectedRequest, ""))
		}
		return session.responseCache.status, session.responseCache.response
	}
	return 0, nil
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

func (session *session) chooseProtocolVersion(minClient, maxClient *irma.ProtocolVersion) (*irma.ProtocolVersion, error) {
	// Set our minimum supported version to 2.5 if condiscon compatibility is required
	minServer := minProtocolVersion
	if !session.legacyCompatible {
		minServer = &irma.ProtocolVersion{2, 5}
	}

	if minClient.AboveVersion(maxProtocolVersion) || maxClient.BelowVersion(minServer) || maxClient.BelowVersion(minClient) {
		return nil, server.LogWarning(errors.Errorf("Protocol version negotiation failed, min=%s max=%s minServer=%s maxServer=%s", minClient.String(), maxClient.String(), minServer.String(), maxProtocolVersion.String()))
	}
	if maxClient.AboveVersion(maxProtocolVersion) {
		return maxProtocolVersion, nil
	} else {
		return maxClient, nil
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
	_ = cpy.(irma.RequestorRequest).SessionRequest().Disclosure().Disclose.Iterate(
		func(attr *irma.AttributeRequest) error {
			attr.Value = nil
			return nil
		},
	)

	// Remove attribute values from attributes to be issued
	if isreq, ok := cpy.(*irma.IdentityProviderRequest); ok {
		for _, cred := range isreq.Request.Credentials {
			cred.Attributes = nil
		}
	}

	return cpy.(irma.RequestorRequest)
}
