package backend

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irmaserver"
)

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

// Issuance helpers

func validateIssuanceRequest(request *irma.IssuanceRequest) error {
	for _, cred := range request.Credentials {
		// Check that we have the appropriate private key
		iss := cred.CredentialTypeID.IssuerIdentifier()
		privatekey, havekey := conf.PrivateKeys[iss]
		if !havekey {
			return fmt.Errorf("missing private key of issuer %s", iss.String())
		}
		pubkey, err := conf.IrmaConfiguration.PublicKey(iss, int(privatekey.Counter))
		if err != nil {
			return err
		}
		if pubkey == nil {
			return fmt.Errorf("missing public key of issuer %s", iss.String())
		}
		cred.KeyCounter = int(privatekey.Counter)

		// Check that the credential is consistent with irma_configuration
		if err := cred.Validate(conf.IrmaConfiguration); err != nil {
			return err
		}

		// Ensure the credential has an expiry date
		defaultValidity := irma.Timestamp(time.Now().Add(6 * time.Hour))
		if cred.Validity == nil {
			cred.Validity = &defaultValidity
		}
		if cred.Validity.Before(irma.Timestamp(time.Now())) {
			return errors.New("cannot issue expired credentials")
		}
	}

	return nil
}

func (session *session) getProofP(commitments *gabi.IssueCommitmentMessage, scheme irma.SchemeManagerIdentifier) (*gabi.ProofP, error) {
	if session.kssProofs == nil {
		session.kssProofs = make(map[irma.SchemeManagerIdentifier]*gabi.ProofP)
	}

	if _, contains := session.kssProofs[scheme]; !contains {
		str, contains := commitments.ProofPjwts[scheme.Name()]
		if !contains {
			return nil, errors.Errorf("no keyshare proof included for scheme %s", scheme.Name())
		}
		claims := &struct {
			jwt.StandardClaims
			ProofP *gabi.ProofP
		}{}
		token, err := jwt.ParseWithClaims(str, claims, func(t *jwt.Token) (interface{}, error) {
			var kid int
			if kidstr, ok := t.Header["kid"].(string); ok {
				var err error
				if kid, err = strconv.Atoi(kidstr); err != nil {
					return nil, err
				}
			}
			return conf.IrmaConfiguration.KeyshareServerPublicKey(scheme, kid)
		})
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
	if min.AboveVersion(minProtocolVersion) || max.BelowVersion(min) {
		return nil, errors.Errorf("Protocol version negotiation failed, min=%s max=%s", min.String(), max.String())
	}
	if max.AboveVersion(maxProtocolVersion) {
		return maxProtocolVersion, nil
	} else {
		return max, nil
	}
}
