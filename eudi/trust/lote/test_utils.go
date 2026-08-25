package lote

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/cert"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/jades"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/stretchr/testify/require"
)

// Not a _test.go file: session tests in internal/sessiontest need a LoTE they
// control, and Go does not export test-only code across packages. Same shape as
// the statuslist package's test utilities.

// TestLoteSigner is a fixture for publishing signed LoTEs in tests. Two-level,
// like the real list signer, so that chain building is exercised at all.
type TestLoteSigner struct {
	RootKey  *ecdsa.PrivateKey
	RootCert *x509.Certificate
	PrivKey  *ecdsa.PrivateKey
	Cert     *x509.Certificate
	DERBytes []byte
}

func NewTestLoteSigner(t *testing.T) *TestLoteSigner {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "lote-test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDer, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDer)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		// Country and Organization match NewTestList's, since SignList goes through
		// clause 6.8.0.
		Subject: pkix.Name{
			CommonName:   "lote-test-signer",
			Country:      []string{"NL"},
			Organization: []string{"Yivi Test"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	leafDer, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, leafKey.Public(), rootKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDer)
	require.NoError(t, err)

	return &TestLoteSigner{
		RootKey:  rootKey,
		RootCert: rootCert,
		PrivKey:  leafKey,
		Cert:     leafCert,
		DERBytes: leafDer,
	}
}

// X509VerificationContext is a trust store anchoring this signer's root, standing
// in for the pinned Yivi anchors.
func (s *TestLoteSigner) X509VerificationContext() eudi_jwt.X509VerificationContext {
	pool := x509.NewCertPool()
	pool.AddCert(s.RootCert)
	return &eudi_jwt.StaticVerificationContext{
		VerifyOpts: x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
	}
}

// SignList signs through Sign, the same path the publisher takes, so a positive
// fixture cannot pass while the real signer is broken. The list therefore has to
// satisfy clause 6.8.0 and clause 6.6.5; one that deliberately does not wants
// SignListRaw.
func (s *TestLoteSigner) SignList(t *testing.T, list List) Signed {
	t.Helper()

	signed, err := Sign(Document{LoTE: list}, []*x509.Certificate{s.Cert}, s.PrivKey, time.Now())
	require.NoError(t, err, "the test signer must be able to sign the way the publisher does")
	return signed
}

// SignListRaw signs a document Sign would refuse, with the headers Sign would have
// produced. For fixtures whose point is a document no publisher could emit.
func (s *TestLoteSigner) SignListRaw(t *testing.T, list List) Signed {
	t.Helper()
	return s.SignListWithTyp(t, list, LoteTyp)
}

// SignListWithTyp is SignListRaw with the `typ` header overridden, for negative-path
// tests.
func (s *TestLoteSigner) SignListWithTyp(t *testing.T, list List, typ string) Signed {
	t.Helper()
	return s.SignListWithHeaders(t, list, typ, nil)
}

// SignListWithHeaders assembles a signature by hand, with the `typ` header
// overridden and arbitrary extra protected headers. It deliberately bypasses Sign:
// producing what Sign refuses is how the rejections get tested. Keep its header set
// in step with jades.SignBaselineB.
func (s *TestLoteSigner) SignListWithHeaders(
	t *testing.T,
	list List,
	typ string,
	extra map[string]any,
) Signed {
	t.Helper()

	payload, err := json.Marshal(Document{LoTE: list})
	require.NoError(t, err)

	chain := &cert.Chain{}
	require.NoError(t, chain.Add([]byte(base64.StdEncoding.EncodeToString(s.DERBytes))))

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, typ))
	require.NoError(t, headers.Set(jws.X509CertChainKey, chain))
	require.NoError(t, headers.Set(jades.IatHeader, time.Now().Unix()))
	for name, value := range extra {
		require.NoError(t, headers.Set(name, value))
	}

	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), s.PrivKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return signed
}

// NewTestPartyCertificate returns an end-entity certificate under this signer's
// root for a party a test wants to list, carrying organizationIdentifier when one
// is given and always a subject key identifier, so an entry can key on either.
func (s *TestLoteSigner) NewTestPartyCertificate(t *testing.T, commonName, organizationIdentifier string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	subject := pkix.Name{CommonName: commonName}
	if organizationIdentifier != "" {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{{
			Type:  organizationIdentifierOID,
			Value: organizationIdentifier,
		}}
	}

	// A predictable SKI so a test can key an entry on it. RFC 5280 §4.2.1.2 method
	// (1) prescribes SHA-1, but any stable value works.
	pubDer, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	var pubInfo struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(pubDer, &pubInfo)
	require.NoError(t, err)
	ski := sha256.Sum256(pubInfo.PublicKey.Bytes)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: ski[:20],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.RootCert, key.Public(), s.RootKey)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return parsed
}

// NewTestList builds a list with a NextUpdate a day out and every field Annex A
// makes mandatory filled with a workable default, so a test that cares about
// entities need not invent a postal address to get a conformant document. listId
// becomes the English SchemeName, the identity the wallet pins.
//
// The suite's listIds are not in clause 6.3.6's prescribed `CC:name` form: the
// wallet does not police the format, and validating it is the publisher's job.
func NewTestList(listId string, sequenceNumber uint64, entities ...Entity) List {
	now := time.Now().UTC()
	return List{
		SchemeInformation: SchemeInformation{
			LoTEVersionIdentifier: LoTEVersion,
			SequenceNumber:        sequenceNumber,
			LoTEType:              LoTETypeRecognizedParties,
			SchemeOperatorName:    MultiLang{"en": "Yivi Test"},
			SchemeOperatorAddress: SchemeOperatorAddress{
				PostalAddress: []PostalAddress{{
					Lang:          "en",
					StreetAddress: "Test Lane 1",
					Locality:      "Utrecht",
					PostalCode:    "3512 AA",
					Country:       "NL",
				}},
				ElectronicAddress: []MultiLangURIEntry{{
					Lang: "en", URIValue: "mailto:trustlist@yivi.test",
				}},
			},
			SchemeName:                  MultiLang{"en": listId},
			SchemeInformationURI:        MultiLangURI{"en": "https://yivi.test/trustlist"},
			StatusDeterminationApproach: StatusDeterminationApproachYivi,
			SchemeTypeCommunityRules:    MultiLangURI{"en": SchemeTypeCommunityRulesYivi},
			SchemeTerritory:             "NL",
			PolicyOrLegalNotice: []PolicyOrLegalNotice{{
				LoTEPolicy: &MultiLangURIEntry{
					Lang: "en", URIValue: "https://yivi.test/trustlist/policy",
				},
			}},
			ListIssueDateTime: now,
			NextUpdate:        now.Add(24 * time.Hour),
		},
		Entities: entities,
	}
}

// NewTestEntity builds a granted entity with the given services, filling the
// mandatory TEAddress and TEInformationURI with defaults. A service that names
// itself keeps its own name; one that does not inherits the entity's, as the
// publisher does, which keeps the service-level name an override.
func NewTestEntity(name, organizationIdentifier string, services ...Service) Entity {
	info := EntityInformation{
		Name: MultiLang{"en": name, "nl": name},
		Address: TEAddress{
			PostalAddress: []PostalAddress{{
				Lang:          "en",
				StreetAddress: "Example Street 1",
				Locality:      "Utrecht",
				PostalCode:    "3512 AA",
				Country:       "NL",
			}},
			ElectronicAddress: []MultiLangURIEntry{{
				Lang: "en", URIValue: "mailto:info@example.test",
			}},
		},
		InformationURI: MultiLangURI{"en": "https://example.test/about"},
	}
	if organizationIdentifier != "" {
		info.Extensions = append(info.Extensions, YiviExtension{
			OrganizationIdentifier: organizationIdentifier,
		})
	}

	// Copied: the variadic slice may be the caller's own.
	owned := make([]Service, len(services))
	copy(owned, services)
	for i := range owned {
		if len(owned[i].Information.Name) == 0 {
			owned[i].Information.Name = MultiLang{"en": name, "nl": name}
		}
	}

	return Entity{Information: info, Services: owned}
}

func NewTestCertificateService(serviceType trust.Role, partyCert *x509.Certificate, markings ...string) Service {
	return newTestService(serviceType, DigitalIdentity{
		X509Certificates: []PKIObject{{Val: partyCert.Raw}},
	}, markings...)
}

func NewTestSkiService(serviceType trust.Role, partyCert *x509.Certificate, markings ...string) Service {
	return newTestService(serviceType, DigitalIdentity{
		X509SKIs: [][]byte{partyCert.SubjectKeyId},
	}, markings...)
}

func NewTestDidService(serviceType trust.Role, did string, markings ...string) Service {
	return newTestService(serviceType, DigitalIdentity{OtherIds: []string{did}}, markings...)
}

// newTestService builds a granted service, leaving ServiceName unset so
// NewTestEntity can fill it from the entity. ServiceStatus is left unset too —
// absent means granted, which is the shape Yivi publishes; a test that wants a
// withdrawal sets Status explicitly.
func newTestService(serviceType trust.Role, identity DigitalIdentity, markings ...string) Service {
	info := ServiceInformation{
		DigitalIdentity: identity,
		Type:            ServiceTypeForRole(serviceType),
	}
	for _, marking := range markings {
		info.Extensions = append(info.Extensions, YiviExtension{Marking: marking})
	}
	return Service{Information: info}
}

// TestLoteServer is a mutable httptest server publishing one LoTE, so a single
// test can walk a list through a re-issue, a tampered copy, or an outage.
type TestLoteServer struct {
	server     *httptest.Server
	bodyBytes  atomic.Pointer[[]byte]
	statusCode atomic.Int64
	hits       atomic.Int64
}

func NewTestLoteServer(t *testing.T) *TestLoteServer {
	t.Helper()
	s := &TestLoteServer{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r
		s.hits.Add(1)
		if code := s.statusCode.Load(); code != 0 {
			w.WriteHeader(int(code))
			return
		}
		w.Header().Set("Content-Type", "application/jose")
		if bp := s.bodyBytes.Load(); bp != nil {
			_, _ = w.Write(*bp)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *TestLoteServer) URL() string { return s.server.URL }

// Source returns a Source pointing at this server for the given list identifier,
// conferring the given level — high for a fixture standing in for Yivi's own list,
// medium for any other. LoTEType is pinned to what NewTestList emits, so every
// test going through this server exercises the type check.
func (s *TestLoteServer) Source(listId string, confers clientmodels.TrustLevel) Source {
	return Source{
		Key:      listId,
		LoTEType: LoTETypeRecognizedParties,
		URL:      s.URL(),
		Confers:  confers,
	}
}

func (s *TestLoteServer) Serve(t *testing.T, signer *TestLoteSigner, list List) {
	t.Helper()
	s.SetBody(signer.SignList(t, list))
}

// ServeRaw publishes a document Sign would refuse, an expired one say: the
// signature is well-formed, only the document is one no publisher should emit.
func (s *TestLoteServer) ServeRaw(t *testing.T, signer *TestLoteSigner, list List) {
	t.Helper()
	s.SetBody(signer.SignListRaw(t, list))
}

func (s *TestLoteServer) SetBody(body []byte) {
	s.statusCode.Store(0)
	s.bodyBytes.Store(&body)
}

// SetStatus makes subsequent requests fail with the given status; 0 restores the
// body.
func (s *TestLoteServer) SetStatus(code int) { s.statusCode.Store(int64(code)) }

// Close is the unreachable-endpoint case.
func (s *TestLoteServer) Close() { s.server.Close() }

func (s *TestLoteServer) Hits() int64 { return s.hits.Load() }
