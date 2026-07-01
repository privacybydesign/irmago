package openid4vci

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/vcdm"
)

type credentialFormatAdapter interface {
	VerifyCredentialInstances(credentials []CredentialInstance) (*credentialVerificationResult, error)
}

type credentialVerificationResult struct {
	VerifiedSdJwtVcs []*sdjwtvc.VerifiedSdJwtVc
	Envelopes        []*vcdm.CredentialEnvelope
}

type credentialFormatAdapterFactory func(s *session) credentialFormatAdapter

var credentialFormatAdapterFactories = map[metadata.CredentialFormatIdentifier]credentialFormatAdapterFactory{
	metadata.CredentialFormatIdentifier_SdJwtVc: func(s *session) credentialFormatAdapter {
		return &sdJwtCredentialFormatAdapter{holderVerifier: s.holderVerifier}
	},
	metadata.CredentialFormatIdentifier_W3CVC: func(s *session) credentialFormatAdapter {
		return &jwtVcJsonCredentialFormatAdapter{
			strictSignatureVerification: s.issuerSettings.strictJwtVcJsonVerification,
			x509VerificationContext:     s.issuerSettings.jwtVcJsonX509VerificationContext,
			temporalClockSkew:           s.issuerSettings.jwtVcJsonTemporalClockSkew,
		}
	},
	metadata.CredentialFormatIdentifier_SdJwtVc_Legacy: func(s *session) credentialFormatAdapter {
		return &sdJwtCredentialFormatAdapter{holderVerifier: s.holderVerifier}
	},
}

func isRuntimeSupportedCredentialFormat(format metadata.CredentialFormatIdentifier) bool {
	_, ok := credentialFormatAdapterFactories[format]
	return ok
}

func getCredentialFormatAdapter(s *session, format metadata.CredentialFormatIdentifier) (credentialFormatAdapter, error) {
	factory, ok := credentialFormatAdapterFactories[format]
	if !ok {
		return nil, fmt.Errorf("unsupported credential format %q", format)
	}

	return factory(s), nil
}

type sdJwtCredentialFormatAdapter struct {
	holderVerifier *sdjwtvc.HolderVerificationProcessor
}

type jwtVcJsonCredentialFormatAdapter struct {
	strictSignatureVerification bool
	x509VerificationContext     eudi_jwt.X509VerificationContext
	temporalClockSkew           time.Duration
}

func (a *sdJwtCredentialFormatAdapter) VerifyCredentialInstances(credentials []CredentialInstance) (*credentialVerificationResult, error) {
	if a.holderVerifier == nil {
		return nil, fmt.Errorf("holder verifier is not configured")
	}

	verifiedSdJwtVcs := make([]*sdjwtvc.VerifiedSdJwtVc, len(credentials))
	envelopes := make([]*vcdm.CredentialEnvelope, len(credentials))
	for i, cred := range credentials {
		// Useful for debugging, but can be very verbose if there are many credentials.
		// if i == 0 {
		// 	log.Printf("First credential: %s", cred.Credential)
		// }

		verifiedSdJwt, err := a.holderVerifier.ParseAndVerifySdJwtVc(sdjwtvc.SdJwtVcKb(cred.Credential))
		if err != nil {
			return nil, fmt.Errorf("failed to verify credential: %v", err)
		}
		verifiedSdJwtVcs[i] = verifiedSdJwt
		envelopes[i] = sdJwtToEnvelope(verifiedSdJwt)
	}

	if err := sdjwtvc.CheckKeyBindingConfirmationUniqueness(verifiedSdJwtVcs); err != nil {
		return nil, fmt.Errorf("key binding confirmation uniqueness check failed: %v", err)
	}

	return &credentialVerificationResult{
		VerifiedSdJwtVcs: verifiedSdJwtVcs,
		Envelopes:        envelopes,
	}, nil
}

func (a *jwtVcJsonCredentialFormatAdapter) VerifyCredentialInstances(credentials []CredentialInstance) (*credentialVerificationResult, error) {
	envelopes := make([]*vcdm.CredentialEnvelope, len(credentials))
	for i, cred := range credentials {
		envelope, err := jwtVcJsonToEnvelope(cred.Credential, a.strictSignatureVerification, a.temporalClockSkew, a.x509VerificationContext)
		if err != nil {
			return nil, fmt.Errorf("failed to parse jwt_vc_json credential: %v", err)
		}
		envelopes[i] = envelope
	}

	return &credentialVerificationResult{Envelopes: envelopes}, nil
}

func sdJwtToEnvelope(vc *sdjwtvc.VerifiedSdJwtVc) *vcdm.CredentialEnvelope {
	jwtPayload := vc.IssuerSignedJwtPayload
	proofs := []vcdm.Proof{}
	types := []string{"VerifiableCredential"}
	if jwtPayload.VerifiableCredentialType != "" {
		types = append(types, jwtPayload.VerifiableCredentialType)
	}

	var status *vcdm.CredentialStatus
	if jwtPayload.Status != nil && *jwtPayload.Status != "" {
		status = &vcdm.CredentialStatus{ID: *jwtPayload.Status}
	}

	rawCredential := string(vc.GetRawSdJwtVc())

	return &vcdm.CredentialEnvelope{
		ID:             buildEnvelopeID(rawCredential),
		Types:          types,
		Issuer:         jwtPayload.Issuer,
		SubjectID:      jwtPayload.Subject,
		IssuanceDate:   unixPtrToTime(jwtPayload.IssuedAt),
		ExpirationDate: unixPtrToTime(jwtPayload.Expiry),
		ValidFrom:      unixPtrToTime(jwtPayload.NotBefore),
		Proofs:         proofs,
		Status:         status,
		Claims:         map[string]any(vc.ProcessedSdJwtPayload),
		Format:         string(metadata.CredentialFormatIdentifier_SdJwtVc),
		RawCredential:  rawCredential,
	}
}

func buildEnvelopeID(rawCredential string) string {
	if rawCredential == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(rawCredential))
	return "urn:sha256:" + hex.EncodeToString(hash[:])
}

func jwtVcJsonToEnvelope(raw string, strictSignatureVerification bool, temporalClockSkew time.Duration, x509VerificationContext eudi_jwt.X509VerificationContext) (*vcdm.CredentialEnvelope, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid compact JWT format")
	}

	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT header encoding")
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid JWT header JSON")
	}

	alg, _ := header["alg"].(string)
	if alg == "" {
		return nil, fmt.Errorf("missing JWT alg header")
	}
	if strings.EqualFold(alg, "none") {
		return nil, fmt.Errorf("JWT alg \"none\" is not allowed")
	}

	payloadBytes, err := decodeJWTPart(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload encoding")
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid JWT payload JSON")
	}

	issuer, _ := payload["iss"].(string)
	if issuer == "" {
		return nil, fmt.Errorf("missing issuer claim \"iss\"")
	}

	if err := verifyJwtVcJsonSignature(raw, header, alg, issuer, strictSignatureVerification, x509VerificationContext); err != nil {
		return nil, err
	}

	subject, _ := payload["sub"].(string)
	types := []string{"VerifiableCredential"}
	contexts := []string{}
	var status *vcdm.CredentialStatus

	if vcClaim, ok := payload["vc"].(map[string]any); ok {
		contexts = toStringSlice(vcClaim["@context"])
		types = appendUniqueStrings(types, toStringSlice(vcClaim["type"])...)

		if cs, ok := vcClaim["credentialStatus"].(map[string]any); ok {
			status = &vcdm.CredentialStatus{
				ID:   stringValue(cs["id"]),
				Type: stringValue(cs["type"]),
			}
		}
	}

	if len(types) == 1 {
		types = appendUniqueStrings(types, toStringSlice(payload["type"])...)
	}

	iat, err := parseTemporalClaim(payload, "iat")
	if err != nil {
		return nil, err
	}
	nbf, err := parseTemporalClaim(payload, "nbf")
	if err != nil {
		return nil, err
	}
	exp, err := parseTemporalClaim(payload, "exp")
	if err != nil {
		return nil, err
	}

	if err := validateTemporalClaims(iat, nbf, exp, strictSignatureVerification, temporalClockSkew); err != nil {
		return nil, err
	}

	id := stringValue(payload["jti"])
	if id == "" {
		id = buildEnvelopeID(raw)
	}

	proofs := jwtToProofs(raw, header, alg)

	return &vcdm.CredentialEnvelope{
		ID:             id,
		Contexts:       contexts,
		Types:          types,
		Issuer:         issuer,
		SubjectID:      subject,
		IssuanceDate:   iat,
		ExpirationDate: exp,
		ValidFrom:      nbf,
		Proofs:         proofs,
		Status:         status,
		Claims:         payload,
		Format:         string(metadata.CredentialFormatIdentifier_W3CVC),
		RawCredential:  raw,
	}, nil
}

func jwtToProofs(raw string, header map[string]any, alg string) []vcdm.Proof {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[2] == "" {
		return nil
	}

	proof := vcdm.Proof{
		Type:         "JsonWebSignature2020",
		Cryptosuite:  alg,
		ProofPurpose: "assertionMethod",
		ProofValue:   parts[2],
	}

	if kid, _ := header["kid"].(string); kid != "" {
		proof.VerificationMethod = kid
	}

	return []vcdm.Proof{proof}
}

func verifyJwtVcJsonSignature(raw string, header map[string]any, alg string, issuer string, strictSignatureVerification bool, x509VerificationContext eudi_jwt.X509VerificationContext) error {
	rawX5c, hasX5c := header["x5c"]
	if !hasX5c {
		if strictSignatureVerification {
			return fmt.Errorf("missing JWT key material (x5c)")
		}
		// Keep backward-compatible parser behavior for jwt_vc_json tokens without verifiable key material.
		return nil
	}

	x5cEntries, ok := rawX5c.([]any)
	if !ok || len(x5cEntries) == 0 {
		return fmt.Errorf("invalid JWT x5c header")
	}

	x5cCerts := make([]*x509.Certificate, 0, len(x5cEntries))
	for _, entry := range x5cEntries {
		certB64, ok := entry.(string)
		if !ok || certB64 == "" {
			return fmt.Errorf("invalid JWT x5c header")
		}

		certDER, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return fmt.Errorf("invalid JWT x5c certificate encoding")
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("invalid JWT x5c certificate")
		}

		x5cCerts = append(x5cCerts, cert)
	}

	if err := validateX5cChainOrdering(x5cCerts); err != nil {
		return err
	}

	sigAlg, found := jwa.LookupSignatureAlgorithm(alg)
	if !found {
		return fmt.Errorf("unsupported JWT alg %q", alg)
	}
	if !isAllowedX5cSignatureAlgorithm(sigAlg) {
		return fmt.Errorf("JWT alg %q is not allowed with x5c", alg)
	}

	if _, err := jws.Verify([]byte(raw), jws.WithKey(sigAlg, x5cCerts[0].PublicKey)); err != nil {
		return fmt.Errorf("invalid JWT signature")
	}

	if strictSignatureVerification {
		if x509VerificationContext == nil {
			return fmt.Errorf("missing JWT trust configuration")
		}

		hostname, err := issuerHostname(issuer)
		if err != nil {
			return fmt.Errorf("invalid issuer URI for JWT x5c validation")
		}

		verifyOpts := x509VerificationContext.GetVerificationOptionsTemplate()
		if verifyOpts.Intermediates == nil {
			verifyOpts.Intermediates = x509.NewCertPool()
		} else {
			verifyOpts.Intermediates = verifyOpts.Intermediates.Clone()
		}
		for _, cert := range x5cCerts[1:] {
			verifyOpts.Intermediates.AddCert(cert)
		}

		strictTrustCtx := &eudi_jwt.StaticVerificationContext{
			VerifyOpts:      verifyOpts,
			RevocationLists: x509VerificationContext.GetRevocationLists(),
		}
		if err := eudi_jwt.VerifyCertificate(strictTrustCtx, x5cCerts[0], &hostname); err != nil {
			return fmt.Errorf("JWT x5c certificate is not trusted")
		}
	}

	return nil
}

func issuerHostname(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", err
	}
	hostname := u.Hostname()
	if hostname == "" {
		return "", fmt.Errorf("missing issuer hostname")
	}
	return hostname, nil
}

func isAllowedX5cSignatureAlgorithm(alg jwa.SignatureAlgorithm) bool {
	switch alg {
	case jwa.ES256(), jwa.ES384(), jwa.ES512(),
		jwa.RS256(), jwa.RS384(), jwa.RS512(),
		jwa.PS256(), jwa.PS384(), jwa.PS512(),
		jwa.EdDSA():
		return true
	default:
		return false
	}
}

func validateX5cChainOrdering(certs []*x509.Certificate) error {
	if len(certs) <= 1 {
		return nil
	}

	for i := 0; i < len(certs)-1; i++ {
		child := certs[i]
		parent := certs[i+1]
		if err := child.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("invalid JWT x5c chain")
		}
	}

	return nil
}

func decodeJWTPart(part string) ([]byte, error) {
	if part == "" {
		return nil, fmt.Errorf("empty JWT segment")
	}
	return base64.RawURLEncoding.DecodeString(part)
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		result := make([]string, 0, len(t))
		for _, entry := range t {
			if s, ok := entry.(string); ok && s != "" {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

func appendUniqueStrings(base []string, values ...string) []string {
	seen := make(map[string]struct{}, len(base))
	for _, v := range base {
		seen[v] = struct{}{}
	}

	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		base = append(base, v)
		seen[v] = struct{}{}
	}

	return base
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

func anyToUnixTimePtr(v any) *time.Time {
	var unix int64
	switch t := v.(type) {
	case float64:
		unix = int64(t)
	case int64:
		unix = t
	case int:
		unix = int64(t)
	case json.Number:
		parsed, err := t.Int64()
		if err != nil {
			return nil
		}
		unix = parsed
	default:
		return nil
	}

	tm := time.Unix(unix, 0)
	return &tm
}

func parseTemporalClaim(payload map[string]any, key string) (*time.Time, error) {
	v, ok := payload[key]
	if !ok {
		return nil, nil
	}

	tm := anyToUnixTimePtr(v)
	if tm == nil {
		return nil, fmt.Errorf("invalid temporal claim %q", key)
	}

	return tm, nil
}

func validateTemporalClaims(iat *time.Time, nbf *time.Time, exp *time.Time, strictTemporalValidation bool, temporalClockSkew time.Duration) error {
	if exp != nil && nbf != nil && exp.Before(*nbf) {
		return fmt.Errorf("invalid temporal claims: exp is before nbf")
	}

	if exp != nil && iat != nil && exp.Before(*iat) {
		return fmt.Errorf("invalid temporal claims: exp is before iat")
	}

	if strictTemporalValidation {
		if temporalClockSkew < 0 {
			return fmt.Errorf("invalid temporal clock skew: must be non-negative")
		}

		now := time.Now()

		if exp != nil && exp.Add(temporalClockSkew).Before(now) {
			return fmt.Errorf("invalid temporal claims: credential is expired")
		}

		if nbf != nil && nbf.Add(-temporalClockSkew).After(now) {
			return fmt.Errorf("invalid temporal claims: credential is not yet valid")
		}

		if iat != nil && iat.Add(-temporalClockSkew).After(now) {
			return fmt.Errorf("invalid temporal claims: iat is in the future")
		}
	}

	return nil
}

func unixPtrToTime(unix *int64) *time.Time {
	if unix == nil {
		return nil
	}
	t := time.Unix(*unix, 0)
	return &t
}
