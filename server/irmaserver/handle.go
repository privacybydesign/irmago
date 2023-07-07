package irmaserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/signed"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"

	"github.com/go-chi/chi/v5"
	"github.com/go-errors/errors"
	"github.com/sirupsen/logrus"
)

// This file contains the handler functions for the protocol messages.
// Maintaining the session state is done here, as well as checking whether the session is in the
// appropriate status before handling the request.

func (session *session) handleDelete() {
	if session.Status.Finished() {
		return
	}
	session.markAlive()

	session.Result = &server.SessionResult{Token: session.RequestorToken, Status: irma.ServerStatusCancelled, Type: session.Action}
	session.setStatus(irma.ServerStatusCancelled)
}

func (session *session) handleGetClientRequest(min, max *irma.ProtocolVersion, clientAuth irma.ClientAuthorization) (
	interface{}, *irma.RemoteError) {

	if session.Status != irma.ServerStatusInitialized {
		return nil, server.RemoteError(server.ErrorUnexpectedRequest, "Session already started")
	}

	session.markAlive()
	logger := session.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken})

	var err error
	if session.Version, err = session.chooseProtocolVersion(min, max); err != nil {
		return nil, session.fail(server.ErrorProtocolVersion, "")
	}

	// Protocol versions below 2.8 don't include an authorization header. Therefore skip the authorization
	// header presence check if a lower version is used.
	if clientAuth == "" && session.Version.Above(2, 7) {
		return nil, session.fail(server.ErrorIrmaUnauthorized, "No authorization header provided")
	}
	session.ClientAuth = clientAuth

	// we include the latest revocation updates for the client here, as opposed to when the session
	// was started, so that the client always gets the very latest revocation records
	if err = session.conf.IrmaConfiguration.Revocation.SetRevocationUpdates(session.request.Base()); err != nil {
		return nil, session.fail(server.ErrorRevocation, err.Error())
	}

	// Handle legacy clients that do not support condiscon, by attempting to convert the condiscon
	// session request to the legacy session request format
	legacy, legacyErr := session.request.Legacy()
	session.LegacyCompatible = legacyErr == nil
	if legacyErr != nil {
		logger.Info("Using condiscon: backwards compatibility with legacy IRMA apps is disabled")
	}

	logger.WithFields(logrus.Fields{"version": session.Version.String()}).Debugf("Protocol version negotiated")
	session.request.Base().ProtocolVersion = session.Version

	if session.Options.PairingMethod != irma.PairingMethodNone && session.Version.Above(2, 7) {
		session.setStatus(irma.ServerStatusPairing)
	} else {
		session.setStatus(irma.ServerStatusConnected)
	}

	if session.Version.Below(2, 5) {
		logger.Info("Returning legacy session format")
		legacy.Base().ProtocolVersion = session.Version
		return legacy, nil
	}

	if session.Version.Below(2, 8) {
		// These versions do not support the ClientSessionRequest format, so send the SessionRequest.
		request, err := session.getRequest()
		if err != nil {
			return nil, session.fail(server.ErrorRevocation, err.Error())
		}
		return request, nil
	}
	info, err := session.getClientRequest()
	if err != nil {
		return nil, session.fail(server.ErrorRevocation, err.Error())
	}
	return info, nil
}

func (session *session) handleGetStatus() (irma.ServerStatus, *irma.RemoteError) {
	return session.Status, nil
}

func (session *session) handlePostSignature(signature *irma.SignedMessage) (*irma.ServerSessionResponse, *irma.RemoteError) {
	session.markAlive()

	var err error
	var rerr *irma.RemoteError
	session.Result.Signature = signature

	// In case of chained sessions, we also expect attributes from previous sessions to be disclosed again.
	request := session.request.(*irma.SignatureRequest)
	request.Disclose = append(request.Disclose, session.ImplicitDisclosure...)

	session.Result.Disclosed, session.Result.ProofStatus, err = signature.Verify(session.conf.IrmaConfiguration, request)
	if err != nil && err == irma.ErrMissingPublicKey {
		rerr = session.fail(server.ErrorUnknownPublicKey, err.Error())
	} else if err != nil {
		rerr = session.fail(server.ErrorUnknown, err.Error())
	}

	return &irma.ServerSessionResponse{
		SessionType:     irma.ActionSigning,
		ProtocolVersion: session.Version,
		ProofStatus:     session.Result.ProofStatus,
	}, rerr
}

func (session *session) handlePostDisclosure(disclosure *irma.Disclosure) (*irma.ServerSessionResponse, *irma.RemoteError) {
	session.markAlive()

	var err error
	var rerr *irma.RemoteError

	// In case of chained sessions, we also expect attributes from previous sessions to be disclosed again.
	request := session.request.(*irma.DisclosureRequest)
	request.Disclose = append(request.Disclose, session.ImplicitDisclosure...)

	session.Result.Disclosed, session.Result.ProofStatus, err = disclosure.Verify(session.conf.IrmaConfiguration, request)
	if err != nil && err == irma.ErrMissingPublicKey {
		rerr = session.fail(server.ErrorUnknownPublicKey, err.Error())
	} else if err != nil {
		rerr = session.fail(server.ErrorUnknown, err.Error())
	}

	return &irma.ServerSessionResponse{
		SessionType:     irma.ActionDisclosing,
		ProtocolVersion: session.Version,
		ProofStatus:     session.Result.ProofStatus,
	}, rerr
}

func (session *session) handlePostCommitments(commitments *irma.IssueCommitmentMessage) (*irma.ServerSessionResponse, *irma.RemoteError) {
	session.markAlive()
	request := session.request.(*irma.IssuanceRequest)

	discloseCount := len(commitments.Proofs) - len(request.Credentials)
	if discloseCount < 0 {
		return nil, session.fail(server.ErrorMalformedInput, "Received insufficient proofs")
	}

	// Compute list of public keys against which to verify the received proofs
	disclosureproofs := irma.ProofList(commitments.Proofs[:discloseCount])
	pubkeys, err := disclosureproofs.ExtractPublicKeys(session.conf.IrmaConfiguration)
	if err != nil {
		return nil, session.fail(server.ErrorMalformedInput, err.Error())
	}
	for _, cred := range request.Credentials {
		iss := cred.CredentialTypeID.IssuerIdentifier()
		pubkey, _ := session.conf.IrmaConfiguration.PublicKey(iss, cred.KeyCounter) // No error, already checked earlier
		pubkeys = append(pubkeys, pubkey)
	}

	// Verify and merge keyshare server proofs, if any
	for i, proof := range commitments.Proofs {
		pubkey := pubkeys[i]
		schemeid := irma.NewIssuerIdentifier(pubkey.Issuer).SchemeManagerIdentifier()
		if session.conf.IrmaConfiguration.SchemeManagers[schemeid].Distributed() {
			proofP, err := session.getProofP(commitments, schemeid)
			if err != nil {
				return nil, session.fail(server.ErrorKeyshareProofMissing, err.Error())
			}
			proof.MergeProofP(proofP, pubkey)
		}
	}

	// Verify all proofs and check disclosed attributes, if any, against request
	now := time.Now()
	request.Disclose = append(request.Disclose, session.ImplicitDisclosure...)
	session.Result.Disclosed, session.Result.ProofStatus, err = commitments.Disclosure().VerifyAgainstRequest(
		session.conf.IrmaConfiguration, request, request.GetContext(), request.GetNonce(nil), pubkeys, &now, false,
	)
	if err != nil {
		if err == irma.ErrMissingPublicKey {
			return nil, session.fail(server.ErrorUnknownPublicKey, "")
		} else {
			return nil, session.fail(server.ErrorUnknown, "")
		}
	}
	if session.Result.ProofStatus == irma.ProofStatusExpired {
		return nil, session.fail(server.ErrorAttributesExpired, "")
	}
	if session.Result.ProofStatus != irma.ProofStatusValid {
		return nil, session.fail(server.ErrorInvalidProofs, "")
	}

	// Compute CL signatures
	var sigs []*gabi.IssueSignatureMessage
	for i, cred := range request.Credentials {
		id := cred.CredentialTypeID.IssuerIdentifier()
		pk, _ := session.conf.IrmaConfiguration.PublicKey(id, cred.KeyCounter)
		sk, _ := session.conf.IrmaConfiguration.PrivateKeys.Latest(id)
		issuer := gabi.NewIssuer(sk, pk, one)
		proof, ok := commitments.Proofs[i+discloseCount].(*gabi.ProofU)
		if !ok {
			return nil, session.fail(server.ErrorMalformedInput, "Received invalid issuance commitment")
		}
		attrs, witness, err := session.computeAttributes(sk, cred)
		if err != nil {
			return nil, session.fail(server.ErrorIssuanceFailed, err.Error())
		}
		rb := session.conf.IrmaConfiguration.CredentialTypes[cred.CredentialTypeID].RandomBlindAttributeIndices()
		sig, err := issuer.IssueSignature(proof.U, attrs, witness, commitments.Nonce2, rb)
		if err != nil {
			return nil, session.fail(server.ErrorIssuanceFailed, err.Error())
		}
		sigs = append(sigs, sig)
	}

	return &irma.ServerSessionResponse{
		SessionType:     irma.ActionIssuing,
		ProtocolVersion: session.Version,
		ProofStatus:     session.Result.ProofStatus,
		IssueSignatures: sigs,
	}, nil
}

func (session *session) nextSession() (irma.RequestorRequest, irma.AttributeConDisCon, error) {
	base := session.Rrequest.Base()
	if base.NextSession == nil {
		return nil, nil, nil
	}
	url := base.NextSession.URL

	// Status is changed to DONE as soon as the next session URL is retrieved,
	// so right now the status must be CONNECTED
	if session.Result.Status != irma.ServerStatusConnected ||
		session.Result.ProofStatus != irma.ProofStatusValid ||
		session.Result.Err != nil {
		return nil, nil, errors.New("session in invalid state")
	}

	var res interface{}
	var err error
	if session.conf.JwtRSAPrivateKey != nil {
		res, err = server.ResultJwt(
			session.Result,
			session.conf.JwtIssuer,
			base.ResultJwtValidity,
			session.conf.JwtRSAPrivateKey,
		)
		if err != nil {
			return nil, nil, err
		}
	} else {
		res = session.Result
	}

	var reqbts json.RawMessage
	err = irma.NewHTTPTransport("", false).Post(url, &reqbts, res)
	if err != nil {
		if sessErr, ok := err.(*irma.SessionError); ok && sessErr.RemoteStatus == http.StatusNoContent {
			// 204 instead of a new sessionRequest means no next session is coming
			return nil, nil, nil
		}
		return nil, nil, err
	}
	req, err := server.ParseSessionRequest([]byte(reqbts))
	if err != nil {
		return nil, nil, err
	}

	// Build list of attributes and values that were disclosed in this session
	// that need to be disclosed again in the next session(s)
	var disclosed irma.AttributeConDisCon
	for _, attrlist := range session.Result.Disclosed {
		var con irma.AttributeCon
		for _, attr := range attrlist {
			con = append(con, irma.AttributeRequest{
				Type:  attr.Identifier,
				Value: attr.RawValue,
			})
		}
		disclosed = append(disclosed, irma.AttributeDisCon{con})
	}

	return req, disclosed, nil
}

func (s *Server) startNext(session *session, res *irma.ServerSessionResponse) error {
	next, disclosed, err := session.nextSession()
	if err != nil {
		return err
	}
	if next == nil {
		return nil
	}
	// All attributes that were disclosed in the previous session, as well as any attributes
	// from sessions before that, need to be disclosed in the new session as well.
	// Therefore pass them as parameters to startNextSession
	qr, token, _, err := s.startNextSession(next, nil, disclosed, session.FrontendAuth)
	if err != nil {
		return err
	}
	session.Result.NextSession = token
	session.Next = qr

	res.NextSession = qr

	return nil
}

func (s *Server) handleSessionCommitments(w http.ResponseWriter, r *http.Request) {
	defer common.Close(r.Body)
	commitments := &irma.IssueCommitmentMessage{}
	bts, err := io.ReadAll(r.Body)
	if err != nil {
		server.WriteError(w, server.ErrorMalformedInput, err.Error())
		return
	}
	if err := irma.UnmarshalValidate(bts, commitments); err != nil {
		server.WriteError(w, server.ErrorMalformedInput, err.Error())
		return
	}
	session := r.Context().Value("session").(*session)
	res, rerr := session.handlePostCommitments(commitments)
	if rerr != nil {
		server.WriteResponse(w, nil, rerr)
		return
	}
	if err = s.startNext(session, res); err != nil {
		server.WriteError(w, server.ErrorNextSession, err.Error())
		return
	}
	session.setStatus(irma.ServerStatusDone)
	server.WriteResponse(w, res, nil)
}

func (s *Server) handleSessionProofs(w http.ResponseWriter, r *http.Request) {
	defer common.Close(r.Body)
	bts, err := io.ReadAll(r.Body)
	if err != nil {
		server.WriteError(w, server.ErrorMalformedInput, err.Error())
		return
	}
	session := r.Context().Value("session").(*session)
	var res *irma.ServerSessionResponse
	var rerr *irma.RemoteError
	switch session.Action {
	case irma.ActionDisclosing:
		disclosure := &irma.Disclosure{}
		if err := irma.UnmarshalValidate(bts, disclosure); err != nil {
			server.WriteError(w, server.ErrorMalformedInput, err.Error())
			return
		}
		res, rerr = session.handlePostDisclosure(disclosure)
	case irma.ActionSigning:
		signature := &irma.SignedMessage{}
		if err := irma.UnmarshalValidate(bts, signature); err != nil {
			server.WriteError(w, server.ErrorMalformedInput, err.Error())
			return
		}
		res, rerr = session.handlePostSignature(signature)
	default:
		rerr = server.RemoteError(server.ErrorInvalidRequest, "")
	}
	if rerr != nil {
		server.WriteResponse(w, nil, rerr)
		return
	}
	if err = s.startNext(session, res); err != nil {
		server.WriteError(w, server.ErrorNextSession, err.Error())
		return
	}
	session.setStatus(irma.ServerStatusDone)
	server.WriteResponse(w, res, nil)
}

func (s *Server) handleSessionStatus(w http.ResponseWriter, r *http.Request) {
	res, err := r.Context().Value("session").(*session).handleGetStatus()
	server.WriteResponse(w, res, err)
}

func (s *Server) handleSessionStatusEvents(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*session)
	// Unlock session, so SSE will not block the session.
	session.sessions.unlock(session)

	r = r.WithContext(context.WithValue(r.Context(), "sse", common.SSECtx{
		Component: server.ComponentSession,
		Arg:       string(session.ClientToken),
	}))
	if err := s.subscribeServerSentEvents(w, r, session, false); err != nil {
		server.WriteError(w, server.ErrorUnknown, err.Error())
		return
	}
}

func (s *Server) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*session)
	session.handleDelete()
	w.WriteHeader(200)
}

func (s *Server) handleSessionGet(w http.ResponseWriter, r *http.Request) {
	var min, max irma.ProtocolVersion
	if err := json.Unmarshal([]byte(r.Header.Get(irma.MinVersionHeader)), &min); err != nil {
		server.WriteError(w, server.ErrorMalformedInput, err.Error())
		return
	}
	if err := json.Unmarshal([]byte(r.Header.Get(irma.MaxVersionHeader)), &max); err != nil {
		server.WriteError(w, server.ErrorMalformedInput, err.Error())
		return
	}
	session := r.Context().Value("session").(*session)
	clientAuth := irma.ClientAuthorization(r.Header.Get(irma.AuthorizationHeader))
	res, err := session.handleGetClientRequest(&min, &max, clientAuth)
	server.WriteResponse(w, res, err)
}

func (s *Server) handleSessionGetRequest(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*session)
	if session.Version.Below(2, 8) {
		server.WriteError(w, server.ErrorUnexpectedRequest, "Endpoint is not support in used protocol version")
		return
	}
	var rerr *irma.RemoteError
	request, err := session.getRequest()
	if err != nil {
		rerr = session.fail(server.ErrorRevocation, err.Error())
	}
	server.WriteResponse(w, request, rerr)
}

func (s *Server) handleFrontendStatus(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*session)
	status := irma.FrontendSessionStatus{Status: session.Status, NextSession: session.Next}
	server.WriteResponse(w, status, nil)
}

func (s *Server) handleFrontendStatusEvents(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*session)
	// Unlock session, so frontend status events will not block the session.
	session.sessions.unlock(session)

	r = r.WithContext(context.WithValue(r.Context(), "sse", common.SSECtx{
		Component: server.ComponentFrontendSession,
		Arg:       string(session.ClientToken),
	}))
	if err := s.subscribeServerSentEvents(w, r, session, false); err != nil {
		server.WriteError(w, server.ErrorUnknown, err.Error())
		return
	}
}

func (s *Server) handleFrontendOptionsPost(w http.ResponseWriter, r *http.Request) {
	defer common.Close(r.Body)
	optionsRequest := &irma.FrontendOptionsRequest{}
	bts, err := io.ReadAll(r.Body)
	if err != nil {
		server.WriteError(w, server.ErrorMalformedInput, err.Error())
		return
	}
	err = irma.UnmarshalValidate(bts, optionsRequest)
	if err != nil {
		server.WriteError(w, server.ErrorMalformedInput, err.Error())
		return
	}

	session := r.Context().Value("session").(*session)
	res, err := session.updateFrontendOptions(optionsRequest)
	if err != nil {
		server.WriteError(w, server.ErrorUnexpectedRequest, err.Error())
		return
	}
	server.WriteResponse(w, res, nil)
}

func (s *Server) handleFrontendPairingCompleted(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*session)
	if err := session.pairingCompleted(); err != nil {
		server.WriteError(w, server.ErrorUnexpectedRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStaticMessage(w http.ResponseWriter, r *http.Request) {
	rrequest := s.conf.StaticSessionRequests[chi.URLParam(r, "name")]
	if rrequest == nil {
		server.WriteResponse(w, nil, server.RemoteError(server.ErrorInvalidRequest, "unknown static session"))
		return
	}
	qr, _, _, err := s.StartSession(rrequest, nil)
	if err != nil {
		server.WriteResponse(w, nil, server.RemoteError(server.ErrorMalformedInput, err.Error()))
		return
	}
	server.WriteResponse(w, qr, nil)
}

// GET revocation/events/{credtype}/{pkcounter}/{min}/{max}
func (s *Server) handleRevocationGetEvents(w http.ResponseWriter, r *http.Request) {
	cred := irma.NewCredentialTypeIdentifier(chi.URLParam(r, "id"))
	pkcounter, _ := strconv.ParseUint(chi.URLParam(r, "counter"), 10, 32)
	min, _ := strconv.ParseUint(chi.URLParam(r, "min"), 10, 64)
	max, _ := strconv.ParseUint(chi.URLParam(r, "max"), 10, 64)

	if settings := s.conf.RevocationSettings[cred]; settings == nil || !settings.Server {
		server.WriteBinaryResponse(w, nil, server.RemoteError(server.ErrorInvalidRequest, "not supported by this server"))
		return
	}
	events, err := s.conf.IrmaConfiguration.Revocation.Events(cred, uint(pkcounter), min, max)
	if err != nil {
		server.WriteBinaryResponse(w, nil, server.RemoteError(server.ErrorRevocation, err.Error()))
		return
	}
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", irma.RevocationParameters.EventsCacheMaxAge))
	server.WriteBinaryResponse(w, events, nil)
}

func (s *Server) handleRevocationUpdateEvents(w http.ResponseWriter, r *http.Request) {
	if !s.conf.EnableSSE {
		server.WriteBinaryResponse(w, nil, server.RemoteError(server.ErrorInvalidRequest, "not supported by this server"))
		return
	}
	id := chi.URLParam(r, "id")
	if id != "" {
		r = r.WithContext(context.WithValue(r.Context(), "sse", common.SSECtx{
			Component: server.ComponentRevocation,
			Arg:       id,
		}))
	}
	s.serverSentEvents.ServeHTTP(w, r)
}

// GET revocation/update/{credtype}/{count}[/{pkcounter}]
func (s *Server) handleRevocationGetUpdateLatest(w http.ResponseWriter, r *http.Request) {
	cred := irma.NewCredentialTypeIdentifier(chi.URLParam(r, "id")) // id
	count, _ := strconv.ParseUint(chi.URLParam(r, "count"), 10, 64) // count
	c := chi.URLParam(r, "counter")
	var counter *uint
	if c != "" {
		j, _ := strconv.ParseUint(chi.URLParam(r, "counter"), 10, 32) // counter
		k := uint(j)
		counter = &k
	}

	if settings := s.conf.RevocationSettings[cred]; settings == nil || !settings.Server {
		server.WriteBinaryResponse(w, nil, server.RemoteError(server.ErrorInvalidRequest, "not supported by this server"))
		return
	}
	updates, err := s.conf.IrmaConfiguration.Revocation.LatestUpdates(cred, count, counter)
	if err != nil {
		server.WriteBinaryResponse(w, nil, server.RemoteError(server.ErrorRevocation, err.Error()))
		return
	}
	var mintime int64
	for _, u := range updates {
		if u.SignedAccumulator.Accumulator.Time < mintime || mintime == 0 {
			mintime = u.SignedAccumulator.Accumulator.Time
		}
	}
	maxage := mintime + int64(irma.RevocationParameters.AccumulatorUpdateInterval) - time.Now().Unix()
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", maxage))
	if counter == nil {
		server.WriteBinaryResponse(w, updates, nil)
	} else {
		server.WriteBinaryResponse(w, updates[*counter], nil)
	}
}

// POST revocation/issuancerecord/{credtype}/{counter}
func (s *Server) handleRevocationPostIssuanceRecord(w http.ResponseWriter, r *http.Request) {
	defer common.Close(r.Body)
	cred := irma.NewCredentialTypeIdentifier(chi.URLParam(r, "id"))
	counter, _ := strconv.ParseUint(chi.URLParam(r, "counter"), 10, 32)

	if settings := s.conf.RevocationSettings[cred]; settings == nil || !settings.Authority {
		server.WriteBinaryResponse(w, nil, server.RemoteError(server.ErrorInvalidRequest, "not supported by this server"))
		return
	}

	// Grab the counter-th issuer public key, with which the message should be signed,
	// and verify and unmarshal the issuance record
	pk, err := s.conf.IrmaConfiguration.Revocation.Keys.PublicKey(cred.IssuerIdentifier(), uint(counter))
	if err != nil {
		server.WriteBinaryResponse(w, nil, server.RemoteError(server.ErrorRevocation, err.Error()))
		return
	}
	var rec irma.IssuanceRecord
	message, err := io.ReadAll(r.Body)
	if err != nil {
		server.WriteBinaryResponse(w, nil, server.RemoteError(server.ErrorInvalidRequest, err.Error()))
		return
	}
	if err := signed.UnmarshalVerify(pk.ECDSA, message, &rec); err != nil {
		server.WriteBinaryResponse(w, nil, server.RemoteError(server.ErrorUnauthorized, err.Error()))
		return
	}
	if rec.CredType != cred {
		server.WriteBinaryResponse(w, nil, server.RemoteError(server.ErrorInvalidRequest, "issuance record of wrong credential type"))
		return
	}

	if err = s.conf.IrmaConfiguration.Revocation.AddIssuanceRecord(&rec); err != nil {
		server.WriteBinaryResponse(w, nil, server.RemoteError(server.ErrorRevocation, err.Error()))
	}
	w.WriteHeader(200)
	return
}
