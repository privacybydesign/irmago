package core

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
)

// Session helpers

func (session *session) finished() bool {
	return session.status == server.StatusDone ||
		session.status == server.StatusCancelled ||
		session.status == server.StatusTimeout
}

func (session *session) markAlive() {
	session.lastActive = time.Now()
	conf.Logger.Debugf("session %s marked active at %s", session.token, session.lastActive.String())
}

func (session *session) setStatus(status server.Status) {
	conf.Logger.Debugf("Status of session %s updated to %s", session.token, status)
	session.status = status
	session.result.Status = status
}

func (session *session) fail(err server.Error, message string) *irma.RemoteError {
	rerr := server.RemoteError(err, message)
	session.setStatus(server.StatusCancelled)
	session.result = &server.SessionResult{Err: rerr, Token: session.token, Status: server.StatusCancelled}
	return rerr
}

// Issuance helpers

func validateIssuanceRequest(request *irma.IssuanceRequest) error {
	for _, cred := range request.Credentials {
		// Check that we have the appropriate private key
		iss := cred.CredentialTypeID.IssuerIdentifier()
		privatekey, err := privatekey(iss)
		if err != nil {
			return err
		}
		if privatekey == nil {
			return errors.Errorf("missing private key of issuer %s", iss.String())
		}
		pubkey, err := conf.IrmaConfiguration.PublicKey(iss, int(privatekey.Counter))
		if err != nil {
			return err
		}
		if pubkey == nil {
			return errors.Errorf("missing public key of issuer %s", iss.String())
		}
		cred.KeyCounter = int(privatekey.Counter)

		// Check that the credential is consistent with irma_configuration
		if err := cred.Validate(conf.IrmaConfiguration); err != nil {
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

func privatekey(id irma.IssuerIdentifier) (sk *gabi.PrivateKey, err error) {
	sk = conf.IssuerPrivateKeys[id]
	if sk == nil {
		if sk, err = conf.IrmaConfiguration.PrivateKey(id); err != nil {
			return nil, err
		}
	}
	return sk, nil
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
		conf.Logger.Trace("Parsing keyshare ProofP JWT: ", str)
		claims := &struct {
			jwt.StandardClaims
			ProofP *gabi.ProofP
		}{}
		token, err := jwt.ParseWithClaims(str, claims, conf.IrmaConfiguration.KeyshareServerKeyFunc(scheme))
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

// logPurgedRequest logs the request excluding any attribute values.
func logPurgedRequest(request irma.RequestorRequest) {
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
	// Convert back to JSON to log
	conf.Logger.Info("Session request (purged of attribute values): ", server.ToJson(cpy))
}
