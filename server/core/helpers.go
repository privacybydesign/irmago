package core

import (
	"strconv"
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
}

func (session *session) setStatus(status server.Status) {
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
	if min.AboveVersion(maxProtocolVersion) || max.BelowVersion(minProtocolVersion) || max.BelowVersion(min) {
		return nil, errors.Errorf("Protocol version negotiation failed, min=%s max=%s", min.String(), max.String())
	}
	if max.AboveVersion(maxProtocolVersion) {
		return maxProtocolVersion, nil
	} else {
		return max, nil
	}
}
