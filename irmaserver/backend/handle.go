package backend

import (
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irmaserver"
)

// This file contains the handler functions for the protocol messages, receiving and returning normally
// Go-typed messages here (JSON (un)marshalling is handled by the router).
// Maintaining the session state is done here, as well as checking whether the session is in the
// appropriate status before handling the request.

var conf *irmaserver.Configuration

func (session *session) handleDelete() {
	if session.finished() {
		return
	}
	session.markAlive()

	session.result = &irmaserver.SessionResult{Token: session.token, Status: irmaserver.StatusCancelled}
	session.setStatus(irmaserver.StatusCancelled)
}

func (session *session) handleGetRequest(min, max *irma.ProtocolVersion) (irma.SessionRequest, *irma.RemoteError) {
	if session.status != irmaserver.StatusInitialized {
		return nil, getError(irmaserver.ErrorUnexpectedRequest, "Session already started")
	}
	session.markAlive()

	var err error
	if session.version, err = chooseProtocolVersion(min, max); err != nil {
		return nil, session.fail(irmaserver.ErrorProtocolVersion, "")
	}
	session.request.SetVersion(session.version)

	session.setStatus(irmaserver.StatusConnected)
	return session.request, nil
}

func (session *session) handlePostSignature(signature *irma.SignedMessage) (*irma.ProofStatus, *irma.RemoteError) {
	if session.status != irmaserver.StatusConnected {
		return nil, getError(irmaserver.ErrorUnexpectedRequest, "Session not yet started or already finished")
	}
	session.markAlive()

	var err error
	var rerr *irma.RemoteError
	session.result.Signature = signature
	session.result.Disclosed, session.result.ProofStatus, err = signature.Verify(
		conf.IrmaConfiguration, session.request.(*irma.SignatureRequest))
	if err == nil {
		session.setStatus(irmaserver.StatusDone)
	} else {
		session.setStatus(irmaserver.StatusCancelled)
		if err == irma.ErrorMissingPublicKey {
			rerr = session.fail(irmaserver.ErrorUnknownPublicKey, err.Error())
		} else {
			rerr = session.fail(irmaserver.ErrorUnknown, err.Error())
		}
	}
	return &session.result.ProofStatus, rerr
}

func (session *session) handlePostProofs(proofs gabi.ProofList) (*irma.ProofStatus, *irma.RemoteError) {
	if session.status != irmaserver.StatusConnected {
		return nil, getError(irmaserver.ErrorUnexpectedRequest, "Session not yet started or already finished")
	}
	session.markAlive()

	var err error
	var rerr *irma.RemoteError
	session.result.Disclosed, session.result.ProofStatus, err = irma.ProofList(proofs).Verify(
		conf.IrmaConfiguration, session.request.(*irma.DisclosureRequest))
	if err == nil {
		session.setStatus(irmaserver.StatusDone)
	} else {
		session.setStatus(irmaserver.StatusCancelled)
		if err == irma.ErrorMissingPublicKey {
			rerr = session.fail(irmaserver.ErrorUnknownPublicKey, err.Error())
		} else {
			rerr = session.fail(irmaserver.ErrorUnknown, err.Error())
		}
	}
	return &session.result.ProofStatus, rerr
}

func (session *session) handlePostCommitments(commitments *gabi.IssueCommitmentMessage) ([]*gabi.IssueSignatureMessage, *irma.RemoteError) {
	if session.status != irmaserver.StatusConnected {
		return nil, getError(irmaserver.ErrorUnexpectedRequest, "Session not yet started or already finished")
	}
	session.markAlive()

	request := session.request.(*irma.IssuanceRequest)
	discloseCount := len(request.Disclose)
	if len(commitments.Proofs) != len(request.Credentials)+discloseCount {
		return nil, session.fail(irmaserver.ErrorAttributesMissing, "")
	}

	// Compute list of public keys against which to verify the received proofs
	disclosureproofs := irma.ProofList(commitments.Proofs[:discloseCount])
	pubkeys, err := disclosureproofs.ExtractPublicKeys(conf.IrmaConfiguration)
	if err != nil {
		return nil, session.fail(irmaserver.ErrorInvalidProofs, err.Error())
	}
	for _, cred := range request.Credentials {
		iss := cred.CredentialTypeID.IssuerIdentifier()
		pubkey, _ := conf.IrmaConfiguration.PublicKey(iss, cred.KeyCounter) // No error, already checked earlier
		pubkeys = append(pubkeys, pubkey)
	}

	// Verify and merge keyshare server proofs, if any
	for i, proof := range commitments.Proofs {
		pubkey := pubkeys[i]
		schemeid := irma.NewIssuerIdentifier(pubkey.Issuer).SchemeManagerIdentifier()
		if conf.IrmaConfiguration.SchemeManagers[schemeid].Distributed() {
			proofP, err := session.getProofP(commitments, schemeid)
			if err != nil {
				return nil, session.fail(irmaserver.ErrorKeyshareProofMissing, err.Error())
			}
			proof.MergeProofP(proofP, pubkey)
		}
	}

	// Verify all proofs and check disclosed attributes, if any, against request
	session.result.Disclosed, session.result.ProofStatus, err = irma.ProofList(commitments.Proofs).VerifyAgainstDisjunctions(
		conf.IrmaConfiguration, request.Disclose, request.Context, request.Nonce, pubkeys, false)
	if err != nil {
		if err == irma.ErrorMissingPublicKey {
			return nil, session.fail(irmaserver.ErrorUnknownPublicKey, "")
		} else {
			return nil, session.fail(irmaserver.ErrorUnknown, "")
		}
	}
	if session.result.ProofStatus == irma.ProofStatusExpired {
		return nil, session.fail(irmaserver.ErrorAttributesExpired, "")
	}
	if session.result.ProofStatus != irma.ProofStatusValid {
		return nil, session.fail(irmaserver.ErrorInvalidProofs, "")
	}

	// Compute CL signatures
	var sigs []*gabi.IssueSignatureMessage
	for i, cred := range request.Credentials {
		id := cred.CredentialTypeID.IssuerIdentifier()
		pk, _ := conf.IrmaConfiguration.PublicKey(id, cred.KeyCounter)
		issuer := gabi.NewIssuer(conf.PrivateKeys[id], pk, one)
		proof := commitments.Proofs[i+discloseCount].(*gabi.ProofU)
		attributes, err := cred.AttributeList(conf.IrmaConfiguration, 0x03)
		if err != nil {
			return nil, session.fail(irmaserver.ErrorUnknown, err.Error())
		}
		sig, err := issuer.IssueSignature(proof.U, attributes.Ints, commitments.Nonce2)
		if err != nil {
			return nil, session.fail(irmaserver.ErrorUnknown, err.Error())
		}
		sigs = append(sigs, sig)
	}

	session.setStatus(irmaserver.StatusDone)
	return sigs, nil
}
