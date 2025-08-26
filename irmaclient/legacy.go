package irmaclient

import (
	"github.com/privacybydesign/gabi"
	irma "github.com/privacybydesign/irmago"
)

// registerPublicKey registers our public key used in the ECDSA challenge-response
// sub-protocol part of the keyshare protocol at the keyshare server.
func (kss *keyshareServer) registerPublicKey(client *Client, transport *irma.HTTPTransport, pin string) (*irma.KeysharePinStatus, error) {
	keyname := challengeResponseKeyName(kss.SchemeManagerIdentifier)

	pk, err := client.signer.PublicKey(keyname)
	if err != nil {
		return nil, err
	}
	jwtt, err := SignerCreateJWT(client.signer, keyname, irma.KeyshareKeyRegistrationClaims{
		KeyshareKeyRegistrationData: irma.KeyshareKeyRegistrationData{
			Username:  kss.Username,
			Pin:       kss.HashedPin(pin),
			PublicKey: pk,
		},
	})
	if err != nil {
		err = irma.WrapErrorPrefix(err, "failed to sign public key registration JWT")
		return nil, err
	}

	result := &irma.KeysharePinStatus{}
	err = transport.Post("api/v1/users/register_publickey", result, irma.KeyshareKeyRegistration{PublicKeyRegistrationJWT: jwtt})
	if err != nil {
		err = irma.WrapErrorPrefix(err, "failed to register public key")
		return nil, err
	}

	if result.Status == kssPinSuccess {
		// We leave dealing with any other case up to the calling code
		kss.ChallengeResponse = true
		err = client.storage.StoreKeyshareServers(client.keyshareServers)
		if err != nil {
			err = irma.WrapErrorPrefix(err, "failed to store updated keyshare server")
			return nil, err
		}
	}

	return result, nil
}

// removeKeysharePsFromProofUs fixes a difference in gabi between the old keyshare protocol and
// the new one. In the old one, during issuance the client sends a proof of knowledge only of its
// own keyshare to the issuer. In the new one, it sends a proof of knowledge of the full secret.
// Therefore, the proofU contains a PoK over the full secret, while in case of the old keyshare
// protocol, the issuer expects a PoK only of the user's keyshare. This method removes the
// keyshare server's contribution for use in the old keyshare protocol.
func (ks *keyshareSessionImpl) removeKeysharePsFromProofUs(proofs gabi.ProofList) {
	for i, proof := range proofs {
		if proofU, ok := proof.(*gabi.ProofU); ok {
			proofU.RemoveKeyshareP(ks.builders[i].(*gabi.CredentialBuilder))
		}
	}
}
