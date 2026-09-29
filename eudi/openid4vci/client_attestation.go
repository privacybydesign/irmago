package openid4vci

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/privacybydesign/irmago/eudi/oauth2"
)

// ClientAttester gets the wallet instance attestations (WIA) the wallet
// authenticates to an authorization server with, as an OAuth client
// (draft-ietf-oauth-attestation-based-client-auth). The protocol does not know
// where they come from; the wallet's implementation asks its wallet provider.
type ClientAttester interface {
	// Available reports, from local state only, whether a WIA can be had: the
	// wallet has an active wallet unit. The provider can still refuse Attest.
	Available(ctx context.Context) bool
	// Attest returns a WIA (an oauth-client-attestation+jwt) binding key.
	Attest(ctx context.Context, key *ecdsa.PublicKey) (string, error)
}

const (
	// authMethodAttestJwtClientAuth is the token endpoint authentication
	// method of attestation-based client authentication.
	authMethodAttestJwtClientAuth = "attest_jwt_client_auth"

	headerClientAttestation          = "OAuth-Client-Attestation"
	headerClientAttestationPoP       = "OAuth-Client-Attestation-PoP"
	headerClientAttestationChallenge = "OAuth-Client-Attestation-Challenge"

	errorUseAttestationChallenge = "use_attestation_challenge"
)

// configureClientAttestation decides, before the user is asked anything,
// whether the session authenticates with a WIA: when the authorization server
// lists attest_jwt_client_auth and the wallet can get one. When the server
// accepts nothing else and the wallet cannot, the session fails here, before
// consent, rather than at the PAR or token request.
func (s *session) configureClientAttestation() error {
	as := s.issuerSettings.authorizationServerMetadata
	methods := as.TokenEndpointAuthMethodsSupported
	if !slices.Contains(methods, authMethodAttestJwtClientAuth) {
		return nil
	}
	if algs := as.ClientAttestationPopSigningAlgValuesSupported; len(algs) > 0 && !slices.Contains(algs, "ES256") {
		return s.withoutClientAttestation(methods, "the authorization server does not accept ES256 client attestation PoPs")
	}
	if s.clientAttester == nil || !s.clientAttester.Available(s.ctx) {
		return s.withoutClientAttestation(methods, "this wallet has no active wallet unit to get a wallet instance attestation from")
	}
	s.issuerSettings.useClientAttestation = true
	return nil
}

// withoutClientAttestation continues as a public client when the
// authorization server also accepts one, and fails otherwise.
func (s *session) withoutClientAttestation(methods []string, reason string) error {
	if slices.Contains(methods, "none") || slices.Contains(methods, "public") {
		return nil
	}
	return fmt.Errorf("the authorization server requires a wallet instance attestation: %s", reason)
}

// clientAttestation is the session's WIA and the key it binds.
type clientAttestation struct {
	wia      string
	key      *ecdsa.PrivateKey
	clientID string
	// audience is the authorization server's issuer identifier, the PoP's aud.
	audience string
	now      func() time.Time

	mu sync.Mutex
	// challenge is the latest one the authorization server handed out, from
	// its challenge endpoint or an OAuth-Client-Attestation-Challenge header.
	challenge string
}

// ensureClientAttestation gets the session's WIA the first time the session
// needs it, and returns nil when the session does not use client attestation.
func (s *session) ensureClientAttestation() (*clientAttestation, error) {
	if !s.issuerSettings.useClientAttestation {
		return nil, nil
	}
	if s.clientAttestation != nil {
		return s.clientAttestation, nil
	}

	// The key the WIA binds is a fresh software key per issuance session, held
	// by this session only and never stored. It is deliberately not:
	//   - the possession key U, which is the same for every issuer and would
	//     make every WIA a tracker across issuers, and whose job is proving the
	//     wallet unit to its provider, not signing OAuth PoPs;
	//   - an HSM key through the wallet provider, since every PoP would then
	//     need an unlock, putting the PIN before PAR, before the browser step of
	//     the authorization code flow;
	//   - a key the provider holds and signs the PoPs with (as the NL Wallet
	//     does), since the provider would then see the audience of every PoP,
	//     and so learn which issuers the wallet uses.
	// A fresh key per session also meets HAIP: a WIA is never reused across
	// issuers and carries nothing unique to the wallet instance. What vouches
	// for the key is the provider only issuing a WIA after the wallet unit
	// proved its possession key. Moving the key into the phone's secure
	// hardware later changes who holds it, not the WIA or the protocol.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate the client attestation key: %w", err)
	}
	wia, err := s.clientAttester.Attest(s.ctx, &key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get a wallet instance attestation: %w", err)
	}
	sub, err := attestationSubject(wia)
	if err != nil {
		return nil, fmt.Errorf("invalid wallet instance attestation: %w", err)
	}
	audience := s.issuerSettings.authorizationServerMetadata.Issuer
	if audience == "" {
		audience = s.issuerSettings.authorizationServer
	}
	s.clientAttestation = &clientAttestation{wia: wia, key: key, clientID: sub, audience: audience, now: time.Now}
	return s.clientAttestation, nil
}

// attestationSubject reads the sub of a WIA, which the wallet uses as its
// client_id. The WIA is the provider's, so it is not verified here; the
// authorization server does.
func attestationSubject(wia string) (string, error) {
	parts := strings.Split(wia, ".")
	if len(parts) != 3 {
		return "", errors.New("not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	if claims.Sub == "" {
		return "", errors.New("no sub")
	}
	return claims.Sub, nil
}

// pop returns a fresh Client Attestation PoP JWT: aud, jti, iat and the
// current challenge, signed with the WIA's key. It also carries iss, the
// client_id, which the current draft dropped but authorization servers built
// on its earlier drafts (such as the EUDI reference AS) still require, and the
// current draft ignores.
func (c *clientAttestation) pop() (string, error) {
	c.mu.Lock()
	challenge := c.challenge
	c.mu.Unlock()

	builder := jwt.NewBuilder().
		Issuer(c.clientID).
		Audience([]string{c.audience}).
		JwtID(uuid.NewString()).
		IssuedAt(c.now())
	if challenge != "" {
		builder = builder.Claim("challenge", challenge)
	}
	token, err := builder.Build()
	if err != nil {
		return "", err
	}
	token.Options().Enable(jwt.FlattenAudience)
	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, "oauth-client-attestation-pop+jwt"); err != nil {
		return "", err
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), c.key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("failed to sign the client attestation PoP: %w", err)
	}
	return string(signed), nil
}

func (c *clientAttestation) addHeaders(req *http.Request) error {
	pop, err := c.pop()
	if err != nil {
		return err
	}
	req.Header.Set(headerClientAttestation, c.wia)
	req.Header.Set(headerClientAttestationPoP, pop)
	return nil
}

// observe remembers a challenge the authorization server handed out.
func (c *clientAttestation) observe(resp *http.Response) {
	if challenge := resp.Header.Get(headerClientAttestationChallenge); challenge != "" {
		c.mu.Lock()
		c.challenge = challenge
		c.mu.Unlock()
	}
}

// fetchChallenge gets a fresh challenge from the authorization server's
// challenge endpoint.
func (c *clientAttestation) fetchChallenge(client *http.Client, endpoint string) error {
	resp, err := client.Post(endpoint, "application/x-www-form-urlencoded", nil)
	if err != nil {
		return fmt.Errorf("failed to request a client attestation challenge: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("client attestation challenge request returned %s", resp.Status)
	}
	var body struct {
		Challenge string `json:"attestation_challenge"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.Challenge == "" {
		return errors.New("client attestation challenge response holds no attestation_challenge")
	}
	c.mu.Lock()
	c.challenge = body.Challenge
	c.mu.Unlock()
	return nil
}

// demandsChallenge reports whether a response refuses the request for lacking
// a fresh challenge, which it then hands out (draft §6.1). A body it reads is
// put back.
func demandsChallenge(resp *http.Response) bool {
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	if resp.Header.Get(headerClientAttestationChallenge) == "" {
		return false
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false
	}
	var e oauth2.ErrorResponse
	return json.Unmarshal(body, &e) == nil && e.Error == errorUseAttestationChallenge
}

// postToAuthorizationServer sends a form POST to an endpoint of the
// authorization server (PAR, token), authenticated with the session's WIA
// when it has one and with a DPoP proof when it uses DPoP. A demand for a
// fresh attestation challenge is answered with one retry, as the DPoP state
// answers a demand for a nonce.
func postToAuthorizationServer(client *http.Client, dpop *oauth2.DPoP, ca *clientAttestation, challengeEndpoint *string, endpoint string, values url.Values) (*http.Response, error) {
	if ca != nil {
		values.Set("client_id", ca.clientID)
		if challengeEndpoint != nil && *challengeEndpoint != "" {
			if err := ca.fetchChallenge(client, *challengeEndpoint); err != nil {
				return nil, err
			}
		}
	}
	for attempt := 0; ; attempt++ {
		resp, err := dpop.Do(client, "", func() (*http.Request, error) {
			req, err := newFormRequest(endpoint, values)
			if err != nil {
				return nil, err
			}
			if ca != nil {
				if err := ca.addHeaders(req); err != nil {
					return nil, err
				}
			}
			return req, nil
		})
		if err != nil || ca == nil {
			return resp, err
		}
		ca.observe(resp)
		if attempt > 0 || !demandsChallenge(resp) {
			return resp, nil
		}
		resp.Body.Close()
	}
}
