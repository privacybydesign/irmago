package backend

import (
	"fmt"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irmaserver"
)

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
	session.result.Disclosed, session.result.Status = irma.ProofList(commitments.Proofs).VerifyAgainstDisjunctions(
		conf.IrmaConfiguration, request.Disclose, request.Context, request.Nonce, pubkeys, false)
	if session.result.Status != irma.ProofStatusValid {
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
