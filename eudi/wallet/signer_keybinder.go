package wallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

// signerKeyBinder implements sdjwtvc.KeyBinder on top of a HolderSigner, so the
// KB-JWT signed at OpenID4VP presentation time is produced by whatever backs the
// HolderSigner (software keys, or a WSCA/HSM). It replaces DefaultKeyBinder,
// which requires a raw *ecdsa.PrivateKey pulled from storage.
//
// The KB-JWT compact serialization is assembled by hand (header.payload.sig)
// rather than via a JWT library, because the signature comes from an external
// signer that only exposes "sign these bytes" — never a private key the library
// could consume.
type signerKeyBinder struct {
	signer HolderSigner
	clock  jwt.Clock
}

// newSignerKeyBinder returns a sdjwtvc.KeyBinder backed by the given HolderSigner.
func newSignerKeyBinder(signer HolderSigner) sdjwtvc.KeyBinder {
	return &signerKeyBinder{signer: signer, clock: eudi_jwt.NewSystemClock()}
}

func (b *signerKeyBinder) CreateKeyPairs(num uint) ([]jwk.Key, error) {
	_, pubs, err := b.signer.GenerateKeys(num)
	if err != nil {
		return nil, err
	}
	keys := make([]jwk.Key, len(pubs))
	for i, pub := range pubs {
		k, err := jwk.Import(pub)
		if err != nil {
			return nil, fmt.Errorf("wallet: failed to import holder public key: %w", err)
		}
		pubJwk, err := k.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("wallet: failed to derive public jwk: %w", err)
		}
		keys[i] = pubJwk
	}
	return keys, nil
}

func (b *signerKeyBinder) CreateKeyBindingJwt(hash string, holderKey jwk.Key, nonce string, audience string) (sdjwtvc.KeyBindingJwt, error) {
	ref, err := b.signer.Reference(holderKey)
	if err != nil {
		return "", fmt.Errorf("wallet: failed to resolve holder key reference: %w", err)
	}

	header := map[string]any{
		"typ": sdjwtvc.KbJwtTyp,
		"alg": "ES256",
	}
	payload := sdjwtvc.KeyBindingJwtPayload{
		IssuerSignedJwtHash: hash,
		Nonce:               nonce,
		IssuedAt:            b.clock.Now().Unix(),
		Audience:            audience,
	}

	signingInput, err := jwsSigningInput(header, payload)
	if err != nil {
		return "", err
	}
	sig, err := b.signer.SignES256(ref, signingInput)
	if err != nil {
		return "", fmt.Errorf("wallet: failed to sign key binding jwt: %w", err)
	}
	jws := append(signingInput, '.')
	jws = append(jws, []byte(base64.RawURLEncoding.EncodeToString(sig))...)
	return sdjwtvc.KeyBindingJwt(jws), nil
}

func (b *signerKeyBinder) RemovePrivateKeys(pubKeys []jwk.Key) error {
	refs := make([]string, 0, len(pubKeys))
	for _, k := range pubKeys {
		ref, err := b.signer.Reference(k)
		if err != nil {
			return err
		}
		refs = append(refs, ref)
	}
	return b.signer.Remove(refs)
}

func (b *signerKeyBinder) RemoveAllPrivateKeys() error {
	// The POC HolderSigner has no enumerate-all primitive; callers that need a
	// full wipe use Wallet.Reset (storage) plus the signer's own lifecycle.
	return nil
}

var _ sdjwtvc.KeyBinder = (*signerKeyBinder)(nil)

// jwsSigningInput returns the ASCII "base64url(header).base64url(payload)"
// signing input for a compact JWS.
func jwsSigningInput(header map[string]any, payload any) ([]byte, error) {
	hdrBytes, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("wallet: failed to marshal jws header: %w", err)
	}
	plBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("wallet: failed to marshal jws payload: %w", err)
	}
	enc := base64.RawURLEncoding
	out := make([]byte, 0, enc.EncodedLen(len(hdrBytes))+1+enc.EncodedLen(len(plBytes)))
	out = append(out, []byte(enc.EncodeToString(hdrBytes))...)
	out = append(out, '.')
	out = append(out, []byte(enc.EncodeToString(plBytes))...)
	return out, nil
}
