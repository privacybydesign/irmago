package irmaserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"time"

	"github.com/alexandrevicenzi/go-sse"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/revocation"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
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
	if session.sse == nil {
		return
	}
	session.sse.SendMessage("session/"+session.clientToken,
		sse.SimpleMessage(fmt.Sprintf(`"%s"`, session.status)),
	)
	session.sse.SendMessage("session/"+session.token,
		sse.SimpleMessage(fmt.Sprintf(`"%s"`, session.status)),
	)
}

func (session *session) fail(err server.Error, message string) *irma.RemoteError {
	rerr := server.RemoteError(err, message)
	session.setStatus(server.StatusCancelled)
	session.result = &server.SessionResult{Err: rerr, Token: session.token, Status: server.StatusCancelled, Type: session.action}
	return rerr
}

func (session *session) chooseProtocolVersion(minClient, maxClient *irma.ProtocolVersion) (*irma.ProtocolVersion, error) {
	// Set minimum supported version to 2.5 if condiscon compatibility is required
	minServer := minProtocolVersion
	if !session.legacyCompatible {
		minServer = &irma.ProtocolVersion{2, 5}
	}
	// Set minimum to 2.6 if nonrevocation is required
	if len(session.request.Base().Revocation) > 0 {
		minServer = &irma.ProtocolVersion{2, 6}
	}

	if minClient.AboveVersion(maxProtocolVersion) || maxClient.BelowVersion(minServer) || maxClient.BelowVersion(minClient) {
		err := errors.Errorf("Protocol version negotiation failed, min=%s max=%s minServer=%s maxServer=%s", minClient.String(), maxClient.String(), minServer.String(), maxProtocolVersion.String())
		server.LogWarning(err)
		return nil, err
	}
	if maxClient.AboveVersion(maxProtocolVersion) {
		return maxProtocolVersion, nil
	} else {
		return maxClient, nil
	}
}

const retryTimeLimit = 10 * time.Second

// checkCache returns a previously cached response, for replaying against multiple requests from
// irmago's retryablehttp client, if:
// - the same was POSTed as last time
// - last time was not more than 10 seconds ago (retryablehttp client gives up before this)
// - the session status is what it is expected to be when receiving the request for a second time.
func (session *session) checkCache(message []byte) (int, []byte) {
	if len(session.responseCache.response) == 0 ||
		session.responseCache.sessionStatus != session.status ||
		session.lastActive.Before(time.Now().Add(-retryTimeLimit)) ||
		sha256.Sum256(session.responseCache.message) != sha256.Sum256(message) {
		session.responseCache = responseCache{}
		return 0, nil
	}
	return session.responseCache.status, session.responseCache.response
}

// Issuance helpers

func (session *session) computeWitness(sk *gabi.PrivateKey, cred *irma.CredentialRequest) (*revocation.Witness, error) {
	id := cred.CredentialTypeID
	credtyp := session.conf.IrmaConfiguration.CredentialTypes[id]
	if !credtyp.RevocationSupported() || !session.request.Base().RevocationSupported() {
		return nil, nil
	}

	// ensure the client always gets an up to date nonrevocation witness
	rs := session.conf.IrmaConfiguration.Revocation
	if err := rs.SyncDB(id); err != nil {
		return nil, err
	}

	// Fetch latest revocation record, and then extract the current value of the accumulator
	// from it to generate the witness from
	updates, err := rs.UpdateLatest(id, 0, &cred.KeyCounter)
	if err != nil {
		return nil, err
	}
	u := updates[cred.KeyCounter]
	if u == nil {
		return nil, errors.Errorf("no revocation updates found for key %d", cred.KeyCounter)
	}
	sig := u.SignedAccumulator
	pk, err := rs.Keys.PublicKey(id.IssuerIdentifier(), sig.PKCounter)
	if err != nil {
		return nil, err
	}
	acc, err := sig.UnmarshalVerify(pk)
	if err != nil {
		return nil, err
	}

	witness, err := sk.RevocationGenerateWitness(acc)
	if err != nil {
		return nil, err
	}
	witness.SignedAccumulator = sig // attach previously selected reocation record to the witness for the client

	return witness, nil
}

func (session *session) computeAttributes(
	sk *gabi.PrivateKey, cred *irma.CredentialRequest,
) ([]*big.Int, *revocation.Witness, error) {
	id := cred.CredentialTypeID
	witness, err := session.computeWitness(sk, cred)
	if err != nil {
		return nil, nil, err
	}
	var nonrevAttr *big.Int
	if witness != nil {
		nonrevAttr = witness.E
	}

	issuedAt := time.Now()
	attributes, err := cred.AttributeList(session.conf.IrmaConfiguration, 0x03, nonrevAttr, issuedAt)
	if err != nil {
		return nil, nil, err
	}

	issrecord := &irma.IssuanceRecord{
		CredType:   id,
		PKCounter:  &sk.Counter,
		Key:        cred.RevocationKey,
		Attr:       (*irma.RevocationAttribute)(nonrevAttr),
		Issued:     attributes.SigningDate().UnixNano(),
		ValidUntil: attributes.Expiry().UnixNano(),
	}
	if witness != nil {
		err = session.conf.IrmaConfiguration.Revocation.SaveIssuanceRecord(id, issrecord, sk)
		if err != nil {
			return nil, nil, err
		}
	}

	return attributes.Ints, witness, nil
}

func (s *Server) validateIssuanceRequest(request *irma.IssuanceRequest) error {
	for _, cred := range request.Credentials {
		// Check that we have the appropriate private key
		iss := cred.CredentialTypeID.IssuerIdentifier()
		privatekey, err := s.conf.IrmaConfiguration.PrivateKeyLatest(iss)
		if err != nil {
			return err
		}
		if privatekey == nil {
			return errors.Errorf("missing private key of issuer %s", iss.String())
		}
		pubkey, err := s.conf.IrmaConfiguration.PublicKey(iss, privatekey.Counter)
		if err != nil {
			return err
		}
		if pubkey == nil {
			return errors.Errorf("missing public key of issuer %s", iss.String())
		}
		cred.KeyCounter = privatekey.Counter

		if s.conf.IrmaConfiguration.CredentialTypes[cred.CredentialTypeID].RevocationSupported() {
			settings := s.conf.RevocationSettings[cred.CredentialTypeID]
			if settings == nil || (settings.RevocationServerURL == "" && !settings.Server) {
				return errors.Errorf("revocation enabled for %s but no revocation server configured", cred.CredentialTypeID)
			}
			if cred.RevocationKey == "" {
				return errors.Errorf("revocation enabled for %s but no revocationKey specified", cred.CredentialTypeID)
			}
		}

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

// Other

func (s *Server) doResultCallback(result *server.SessionResult) {
	url := s.GetRequest(result.Token).Base().CallbackURL
	if url == "" {
		return
	}
	server.DoResultCallback(url,
		result,
		s.conf.JwtIssuer,
		s.GetRequest(result.Token).Base().ResultJwtValidity,
		s.conf.JwtRSAPrivateKey,
	)
}

func (s *Server) validateRequest(request irma.SessionRequest) error {
	if _, err := s.conf.IrmaConfiguration.Download(request); err != nil {
		return err
	}
	if err := request.Base().Validate(s.conf.IrmaConfiguration); err != nil {
		return err
	}
	return request.Disclosure().Disclose.Validate(s.conf.IrmaConfiguration)
}

func copyObject(i interface{}) (interface{}, error) {
	cpy := reflect.New(reflect.TypeOf(i).Elem()).Interface()
	bts, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(bts, cpy); err != nil {
		return nil, err
	}
	return cpy, nil
}

// purgeRequest logs the request excluding any attribute values.
func purgeRequest(request irma.RequestorRequest) irma.RequestorRequest {
	// We want to log as much as possible of the request, but no attribute values.
	// We cannot just remove them from the request parameter as that would break the calling code.
	// So we create a deep copy of the request from which we can then safely remove whatever we want to.
	// Ugly hack alert: the easiest way to do this seems to be to convert it to JSON and then back.
	// As we do not know the precise type of request, we use reflection to create a new instance
	// of the same type as request, into which we then unmarshal our copy.
	cpy, err := copyObject(request)
	if err != nil {
		panic(err)
	}

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

func eventServer(conf *server.Configuration) *sse.Server {
	return sse.NewServer(&sse.Options{
		ChannelNameFunc: func(r *http.Request) string {
			ssectx := r.Context().Value("sse")
			if ssectx == nil {
				return ""
			}
			switch ssectx.(common.SSECtx).Component {
			case server.ComponentSession:
				return "session/" + ssectx.(common.SSECtx).Arg
			case server.ComponentRevocation:
				return "revocation/" + ssectx.(common.SSECtx).Arg
			default:
				return ""
			}
		},
		Headers: map[string]string{
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, OPTIONS",
			"Access-Control-Allow-Headers": "Keep-Alive,X-Requested-With,Cache-Control,Content-Type,Last-Event-ID",
		},
		Logger: log.New(conf.Logger.WithField("type", "sse").WriterLevel(logrus.DebugLevel), "", 0),
	})
}

func errorWriter(err *irma.RemoteError, writer func(w http.ResponseWriter, object interface{}, rerr *irma.RemoteError)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writer(w, nil, err)
	}
}

func (s *Server) cacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := r.Context().Value("session").(*session)

		// Read r.Body, and then replace with a fresh ReadCloser for the next handler
		var message []byte
		var err error
		if message, err = ioutil.ReadAll(r.Body); err != nil {
			message = []byte("<failed to read body: " + err.Error() + ">")
		}
		_ = r.Body.Close()
		r.Body = ioutil.NopCloser(bytes.NewBuffer(message))

		// if a cache is set and applicable, return it
		status, output := session.checkCache(message)
		if status > 0 && len(output) > 0 {
			w.WriteHeader(status)
			_, _ = w.Write(output)
			return
		}

		// no cache set; perform request and record output
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		buf := new(bytes.Buffer)
		ww.Tee(buf)
		next.ServeHTTP(ww, r)

		session.responseCache = responseCache{
			message:       message,
			response:      buf.Bytes(),
			status:        ww.Status(),
			sessionStatus: session.status,
		}
	})
}

func (s *Server) sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := chi.URLParam(r, "token")
		session := s.sessions.clientGet(token)
		if session == nil {
			server.WriteError(w, server.ErrorSessionUnknown, "")
			return
		}

		ctx := r.Context()
		session.Lock()
		session.locked = true
		defer func() {
			if session.prevStatus != session.status {
				session.prevStatus = session.status
				result := session.result
				r := ctx.Value("sessionresult")
				if r != nil {
					*r.(*server.SessionResult) = *result
				}
				if session.status.Finished() {
					if handler := s.handlers[result.Token]; handler != nil {
						go handler(result)
						delete(s.handlers, token)
					}
				}
			}
			if session.locked {
				session.locked = false
				session.Unlock()
			}
		}()

		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, "session", session)))
	})
}
