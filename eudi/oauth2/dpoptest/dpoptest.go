// Package dpoptest checks DPoP proofs (RFC 9449) the way a strict
// authorization or resource server would, for tests of the wallet's client.
package dpoptest

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// MaxAge is how old a proof's iat may be.
const MaxAge = time.Minute

// Proof is what a verified DPoP proof established.
type Proof struct {
	// Thumbprint is the base64url JWK SHA-256 thumbprint of the proof's key, to
	// bind a token to (cnf.jkt) or compare against dpop_jkt.
	Thumbprint string
	JwtID      string
	Nonce      string
}

// Verify checks the DPoP proof of r: exactly one DPoP header; typ dpop+jwt,
// alg ES256 and a public jwk in the header; a signature by that jwk; htm and
// htu matching r (htu without query and fragment); a recent iat; a jti; the
// nonce when wantNonce is non-empty; and, when accessToken is non-empty, an
// ath over it.
func Verify(r *http.Request, accessToken, wantNonce string) (*Proof, error) {
	values := r.Header.Values("DPoP")
	if len(values) != 1 {
		return nil, fmt.Errorf("want exactly one DPoP header, got %d", len(values))
	}
	raw := []byte(values[0])

	msg, err := jws.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("proof is not a JWS: %w", err)
	}
	if len(msg.Signatures()) != 1 {
		return nil, errors.New("proof must have exactly one signature")
	}
	headers := msg.Signatures()[0].ProtectedHeaders()
	if typ, _ := headers.Type(); typ != "dpop+jwt" {
		return nil, fmt.Errorf("typ is %q, want dpop+jwt", typ)
	}
	if alg, _ := headers.Algorithm(); alg != jwa.ES256() {
		return nil, fmt.Errorf("alg is %v, want ES256", alg)
	}
	key, ok := headers.JWK()
	if !ok {
		return nil, errors.New("proof has no jwk header")
	}
	if _, private := key.(jwk.ECDSAPrivateKey); private {
		return nil, errors.New("jwk header holds a private key")
	}

	token, err := jwt.Parse(raw, jwt.WithKey(jwa.ES256(), key), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("proof signature: %w", err)
	}

	claim := func(name string) string {
		v, _ := jwt.Get[string](token, name)
		return v
	}
	htm, htu, nonce, ath := claim("htm"), claim("htu"), claim("nonce"), claim("ath")
	jti, _ := token.JwtID()
	iat, ok := token.IssuedAt()

	if htm != r.Method {
		return nil, fmt.Errorf("htm is %q, want %q", htm, r.Method)
	}
	if want := targetURI(r); htu != want {
		return nil, fmt.Errorf("htu is %q, want %q", htu, want)
	}
	if !ok || time.Since(iat) > MaxAge || time.Until(iat) > MaxAge {
		return nil, fmt.Errorf("iat %v is missing or not recent", iat)
	}
	if jti == "" {
		return nil, errors.New("proof has no jti")
	}
	if wantNonce != "" && nonce != wantNonce {
		return nil, fmt.Errorf("nonce is %q, want %q", nonce, wantNonce)
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if want := base64.RawURLEncoding.EncodeToString(sum[:]); ath != want {
			return nil, fmt.Errorf("ath is %q, want %q", ath, want)
		}
	} else if ath != "" {
		return nil, errors.New("proof has an ath but no access token was presented")
	}

	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &Proof{Thumbprint: base64.RawURLEncoding.EncodeToString(tp), JwtID: jti, Nonce: nonce}, nil
}

// targetURI is the URI a request was sent to, as the client saw it, without
// query and fragment.
func targetURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	u := url.URL{Scheme: scheme, Host: r.Host, Path: r.URL.Path}
	return u.String()
}
