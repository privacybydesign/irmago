package holderkeys

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
)

// signerKeyBinder implements sdjwt.KeyBinder on top of a HolderSigner, so the
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

// NewSignerKeyBinder returns a sdjwt.KeyBinder backed by the given HolderSigner.
func NewSignerKeyBinder(signer HolderSigner) sdjwt.KeyBinder {
	return &signerKeyBinder{signer: signer, clock: eudi_jwt.NewSystemClock()}
}

func (b *signerKeyBinder) CreateKeyPairs(num uint) ([]jwk.Key, error) {
	_, pubs, err := b.signer.GenerateKeys(num)
	if err != nil {
		return nil, err
	}
	keys := make([]jwk.Key, len(pubs))
	for i, pub := range pubs {
		k, err := jwk.Import[jwk.Key](pub)
		if err != nil {
			return nil, fmt.Errorf("holderkeys: failed to import holder public key: %w", err)
		}
		pubJwk, err := k.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("holderkeys: failed to derive public jwk: %w", err)
		}
		keys[i] = pubJwk
	}
	return keys, nil
}

func (b *signerKeyBinder) CreateKeyBindingJwt(hash string, holderKey jwk.Key, nonce string, audience string) (sdjwt.KeyBindingJwt, error) {
	ref, err := b.signer.Reference(holderKey)
	if err != nil {
		return "", fmt.Errorf("holderkeys: failed to resolve holder key reference: %w", err)
	}

	header := map[string]any{
		"typ": sdjwt.KbJwtTyp,
		"alg": "ES256",
	}
	payload := sdjwt.KeyBindingJwtPayload{
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
		return "", fmt.Errorf("holderkeys: failed to sign key binding jwt: %w", err)
	}
	jws := append(signingInput, '.')
	jws = append(jws, []byte(base64.RawURLEncoding.EncodeToString(sig))...)
	return sdjwt.KeyBindingJwt(jws), nil
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
	// HolderSigner has no enumerate-all primitive — only Remove(refs) — so this
	// cannot wipe keys it was never told about. A full wipe therefore runs
	// through client.Client.RemoveStorage, which clears the wallet's own
	// storage; disposing of the signer's key material is the signer's
	// responsibility, and for a WSCA-backed one it happens outside irmago.
	return nil
}

var _ sdjwt.KeyBinder = (*signerKeyBinder)(nil)

// jwsSigningInput returns the ASCII "base64url(header).base64url(payload)"
// signing input for a compact JWS.
func jwsSigningInput(header map[string]any, payload any) ([]byte, error) {
	hdrBytes, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("holderkeys: failed to marshal jws header: %w", err)
	}
	plBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("holderkeys: failed to marshal jws payload: %w", err)
	}
	enc := base64.RawURLEncoding
	out := make([]byte, 0, enc.EncodedLen(len(hdrBytes))+1+enc.EncodedLen(len(plBytes)))
	out = append(out, []byte(enc.EncodeToString(hdrBytes))...)
	out = append(out, '.')
	out = append(out, []byte(enc.EncodeToString(plBytes))...)
	return out, nil
}
