package services

// W3C Bitstring Status List checking for SD-JWT-secured VCDM credentials.
//
// No issuer in the e2e stack puts a W3C credentialStatus on a vc+sd-jwt
// credential (veramo only writes the IETF status claim), so this mechanism is
// pinned here, against an in-process status list server. The IETF mechanism on
// VCDM is pinned end to end in internal/sessiontest.
//
// The test environment (newVcdmTestEnv) checks status like the wallet does. The
// status list credential is signed by the same test issuer as the credential
// itself, so trusting that issuer is enough to verify it.
//
// The expectations mirror SD-JWT VC's Token Status List: issuance refuses a
// credential whose status is not valid or cannot be verified, and a stored
// credential with a status reference supports revocation.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/credentials/bitstringstatus"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt/sdjwttest"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

// testStatusListIndex is the index every test credential gets on the list.
const testStatusListIndex = 5

// bitstringStatusListServer serves one JWT-secured BitstringStatusListCredential.
type bitstringStatusListServer struct {
	server *httptest.Server
	body   []byte
	status int
}

func newBitstringStatusListServer(t *testing.T) *bitstringStatusListServer {
	t.Helper()
	s := &bitstringStatusListServer{status: http.StatusOK}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.status != http.StatusOK {
			w.WriteHeader(s.status)
			return
		}
		w.Header().Set("Content-Type", "application/vc+jwt")
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *bitstringStatusListServer) url() string { return s.server.URL + "/lists/1" }

// serve signs a status list with the test issuer key, with the bit at
// testStatusListIndex set or clear.
func (s *bitstringStatusListServer) serve(t *testing.T, revoked bool) {
	t.Helper()
	s.body = signBitstringStatusList(t, sdjwttest.NewEcdsaJwtCreatorWithIssuerTestKey(), s.url(), revoked, true)
}

// signBitstringStatusList builds a BitstringStatusListCredential secured as
// vc+jwt (VC-JOSE-COSE §3.1.1). withX5c attaches the test issuer's chain, which
// is what makes the list verifiable.
func signBitstringStatusList(t *testing.T, signer sdjwt.JwtCreator, listURL string, revoked bool, withX5c bool) []byte {
	t.Helper()

	// The W3C minimum list size: 16 KB, 131,072 entries. Bits are MSB-first.
	bits := make([]byte, 16*1024)
	if revoked {
		bits[testStatusListIndex/8] |= 0x80 >> (testStatusListIndex % 8)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write(bits)
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	payload, err := json.Marshal(map[string]any{
		vcdm.ContextKey:   []any{vcdm.ContextV2},
		vcdm.IDKey:        listURL,
		vcdm.TypeKey:      []any{vcdm.TypeVerifiableCredential, "BitstringStatusListCredential"},
		vcdm.IssuerKey:    testVcdmIssuer,
		vcdm.ValidFromKey: "2020-01-01T00:00:00Z",
		vcdm.CredentialSubjectKey: map[string]any{
			"id":            listURL + "#list",
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   "u" + base64.RawURLEncoding.EncodeToString(buf.Bytes()),
		},
	})
	require.NoError(t, err)

	header := map[string]any{"typ": "vc+jwt"}
	if withX5c {
		x5c, err := utils.ParsePemCertificateChainToX5cFormat(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
		require.NoError(t, err)
		header["x5c"] = x5c
	}
	jwt, err := signer.CreateSignedJwt(header, string(payload))
	require.NoError(t, err)
	return []byte(jwt)
}

// newRawVcdmWithStatus is newRawVcdm with a revocation BitstringStatusListEntry
// pointing at testStatusListIndex of the list at listURL.
func newRawVcdmWithStatus(t *testing.T, listURL string) string {
	t.Helper()
	x5c, err := utils.ParsePemCertificateChainToX5cFormat(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	require.NoError(t, err)
	cnf, err := sdjwt.HolderKeyClaim(testdata.ParseHolderPubJwk())
	require.NoError(t, err)

	claims := []*sdjwt.ClaimElement{
		sdjwt.Array(vcdm.ContextKey, sdjwt.Item(vcdm.ContextV2)),
		sdjwt.Array(vcdm.TypeKey, sdjwt.Item(vcdm.TypeVerifiableCredential), sdjwt.Item("ExampleCredential")),
		sdjwt.Claim(vcdm.IssuerKey, testVcdmIssuer),
		sdjwt.Claim(vcdm.ValidFromKey, "2020-01-01T00:00:00Z"),
		sdjwt.Claim(vcdm.ValidUntilKey, "2035-01-01T00:00:00Z"),
		sdjwt.Object(vcdm.CredentialSubjectKey,
			sdjwt.Claim("id", "did:example:holder"),
			sdjwt.SdClaim("given_name", "Alice"),
		),
		sdjwt.Object(vcdm.CredentialStatusKey,
			sdjwt.Claim("id", listURL+"#"+strconv.Itoa(testStatusListIndex)),
			sdjwt.Claim("type", "BitstringStatusListEntry"),
			sdjwt.Claim("statusPurpose", "revocation"),
			sdjwt.Claim("statusListIndex", strconv.Itoa(testStatusListIndex)),
			sdjwt.Claim("statusListCredential", listURL),
		),
		cnf,
	}

	built, err := sdjwt.NewBuilder().
		WithPayload(claims...).
		WithIssuerCertificateChain(x5c).
		WithTyp(vcdmsdjwt.MediaTypeVcSdJwt).
		Build(sdjwttest.NewEcdsaJwtCreatorWithIssuerTestKey())
	require.NoError(t, err)
	return string(built)
}

func (e *vcdmTestEnv) parseErr(raw string) error {
	_, err := e.parser.ParseAndVerify(raw, testVcdmIssuer, false)
	return err
}

func TestVcdmBitstringStatus_IssuanceAcceptsValid(t *testing.T) {
	env := newVcdmTestEnv(t)
	server := newBitstringStatusListServer(t)
	server.serve(t, false)

	require.NoError(t, env.parseErr(newRawVcdmWithStatus(t, server.url())))
}

func TestVcdmBitstringStatus_IssuanceRefusesRevoked(t *testing.T) {
	env := newVcdmTestEnv(t)
	server := newBitstringStatusListServer(t)
	server.serve(t, true)

	require.Error(t, env.parseErr(newRawVcdmWithStatus(t, server.url())),
		"a credential the issuer already revoked must not be stored")
}

func TestVcdmBitstringStatus_IssuanceRefusesUnreachableList(t *testing.T) {
	env := newVcdmTestEnv(t)
	server := newBitstringStatusListServer(t)
	server.status = http.StatusNotFound

	require.Error(t, env.parseErr(newRawVcdmWithStatus(t, server.url())),
		"a status that cannot be read is not a valid status")
}

func TestVcdmBitstringStatus_IssuanceRefusesUntrustedList(t *testing.T) {
	env := newVcdmTestEnv(t)
	server := newBitstringStatusListServer(t)

	// A valid-looking list signed by a key the wallet does not trust: the bit
	// says valid, but nothing vouches for it.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	server.body = signBitstringStatusList(t, sdjwt.NewJwtCreator(key), server.url(), false, false)

	require.Error(t, env.parseErr(newRawVcdmWithStatus(t, server.url())),
		"a status list must verify before its bit is believed")
}

func TestVcdmBitstringStatus_StoredCredentialSupportsRevocation(t *testing.T) {
	env := newVcdmTestEnv(t)
	server := newBitstringStatusListServer(t)
	server.serve(t, false)

	parsed := env.parse(t, newRawVcdmWithStatus(t, server.url()))
	require.NoError(t, env.service.Store([]*ParsedCredential{parsed}, "config-id", env.issuerMetadata(), false, nil))

	list, err := env.service.List()
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.True(t, list[0].RevocationSupported, "a credential carrying a status reference supports revocation")
	require.False(t, list[0].Revoked)
}

// TestVcdmBitstringStatus_FixtureReadsAsSigned guards the fixtures above, so a
// red test means a missing status check and not a malformed list: the entry
// and the list resolve through the bitstringstatus package to the bit served.
func TestVcdmBitstringStatus_FixtureReadsAsSigned(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		server := newBitstringStatusListServer(t)
		server.serve(t, revoked)

		var list vcdm.Document
		parts := bytes.Split(server.body, []byte("."))
		require.Len(t, parts, 3)
		payload, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(payload, &list))
		require.NoError(t, list.Validate())
		subject, err := bitstringstatus.ParseListCredentialSubject(list[vcdm.CredentialSubjectKey].(map[string]any))
		require.NoError(t, err)

		// Parsed without a status check: a revoked credential is refused otherwise.
		parser := NewSdJwtVcdmCredentialFormatParser(vcdmsdjwt.NewHolderVerificationProcessor(
			vcdmsdjwt.CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)))
		credential, err := parser.ParseAndVerify(newRawVcdmWithStatus(t, server.url()), testVcdmIssuer, false)
		require.NoError(t, err)
		entries, err := bitstringstatus.ParseEntries(credential.SdJwtVcdm.Document[vcdm.CredentialStatusKey])
		require.NoError(t, err)
		require.Len(t, entries, 1)

		value, err := bitstringstatus.Check(entries[0], subject)
		require.NoError(t, err)
		require.Equal(t, map[bool]uint{false: 0, true: 1}[revoked], value)
	}
}

// storeVcdmWithStatus issues a credential on the server's list into env and
// returns a revocation service over env's store and a W3C checker.
func storeVcdmWithStatus(t *testing.T, env *vcdmTestEnv, server *bitstringStatusListServer) *RevocationService {
	t.Helper()
	parsed := env.parse(t, newRawVcdmWithStatus(t, server.url()))
	require.NoError(t, env.service.Store([]*ParsedCredential{parsed}, "config-id", env.issuerMetadata(), false, nil))

	ctx := vcdmsdjwt.CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	checker := bitstringstatus.NewChecker(bitstringstatus.VerificationContext{X509Context: ctx.X509VerificationContext})
	return NewRevocationService(nil, env.store).WithBitstringStatus(checker, env.store)
}

func requireVcdmRevoked(t *testing.T, env *vcdmTestEnv, want bool) {
	t.Helper()
	list, err := env.service.List()
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, want, list[0].Revoked)
}

func TestRevocationService_BitstringRefreshFindsRevocationOnce(t *testing.T) {
	env := newVcdmTestEnv(t)
	server := newBitstringStatusListServer(t)
	server.serve(t, false)
	revocation := storeVcdmWithStatus(t, env, server)

	changed, err := revocation.RefreshStatuses(context.Background())
	require.NoError(t, err)
	require.Zero(t, changed, "issuance already recorded the valid status")

	server.serve(t, true)
	changed, err = revocation.RefreshStatuses(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, changed)
	requireVcdmRevoked(t, env, true)

	changed, err = revocation.RefreshStatuses(context.Background())
	require.NoError(t, err)
	require.Zero(t, changed, "a known revocation is not re-reported")
}

func TestRevocationService_BitstringUnreachableListKeepsStatus(t *testing.T) {
	env := newVcdmTestEnv(t)
	server := newBitstringStatusListServer(t)
	server.serve(t, false)
	revocation := storeVcdmWithStatus(t, env, server)

	server.status = http.StatusServiceUnavailable
	changed, err := revocation.RefreshStatuses(context.Background())
	require.NoError(t, err, "a failing list is logged, not fatal")
	require.Zero(t, changed)
	requireVcdmRevoked(t, env, false)
}

func TestBitstringChecker_RejectsListServedUnderAnotherURL(t *testing.T) {
	server := newBitstringStatusListServer(t)
	// A genuine, trusted list, but for another URL: substituting it must not
	// work, or one valid list could vouch for every credential.
	server.body = signBitstringStatusList(t, sdjwttest.NewEcdsaJwtCreatorWithIssuerTestKey(), "https://issuer.example/lists/other", false, true)

	ctx := vcdmsdjwt.CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	checker := bitstringstatus.NewChecker(bitstringstatus.VerificationContext{X509Context: ctx.X509VerificationContext})
	_, err := checker.Fetch(context.Background(), server.url())
	require.ErrorIs(t, err, bitstringstatus.ErrUnauthorized)
	require.ErrorContains(t, err, "does not match status list url")
}

// TestVcdmStore_BitstringInstancesAreSweptOnce pins the split between the two
// sweeps: an instance with Bitstring entries is the Bitstring sweep's, which
// checks all of its references, and the Token Status List sweep leaves it alone.
func TestVcdmStore_BitstringInstancesAreSweptOnce(t *testing.T) {
	env := newVcdmTestEnv(t)
	server := newBitstringStatusListServer(t)
	server.serve(t, false)
	storeVcdmWithStatus(t, env, server)

	tokenStatusList, err := env.store.ListInstancesWithStatusReference()
	require.NoError(t, err)
	require.Empty(t, tokenStatusList)

	bitstring, err := env.store.ListInstancesWithBitstringStatus()
	require.NoError(t, err)
	require.Len(t, bitstring, 1)

	referenced, err := env.store.ListStatusReferencedInstanceStatuses()
	require.NoError(t, err)
	require.Len(t, referenced, 1, "the credential list still sees the instance as revocable")
}

// recordingBitstringStore is a BitstringStatusStore over fixed instances that
// records the status written to each.
type recordingBitstringStore struct {
	instances []db.BitstringStatusInstance
	written   map[datatypes.UUID]uint8
}

func (s *recordingBitstringStore) ListInstancesWithBitstringStatus() ([]db.BitstringStatusInstance, error) {
	return s.instances, nil
}

func (s *recordingBitstringStore) UpdateInstanceStatus(instanceID datatypes.UUID, status uint8, _ time.Time) error {
	s.written[instanceID] = status
	return nil
}

// Disclosure reads the stored status of the instance it sends, so a sweep that
// finds a batch revoked must record that on every instance of the batch, not
// only on the one it checked.
func TestRevocationService_BitstringRefreshWritesEveryInstanceOfABatch(t *testing.T) {
	server := newBitstringStatusListServer(t)
	server.serve(t, true)

	entries, err := json.Marshal([]bitstringstatus.Entry{{
		StatusPurpose:        bitstringstatus.PurposeRevocation,
		StatusListIndex:      testStatusListIndex,
		StatusListCredential: server.url(),
		StatusSize:           1,
	}})
	require.NoError(t, err)
	batchID := datatypes.NewUUIDv4()
	valid := uint8(statuslist.StatusValid)
	store := &recordingBitstringStore{
		instances: []db.BitstringStatusInstance{
			{InstanceID: datatypes.NewUUIDv4(), BatchID: batchID, LastKnownStatus: valid, Entries: entries},
			{InstanceID: datatypes.NewUUIDv4(), BatchID: batchID, LastKnownStatus: valid, Entries: entries},
		},
		written: map[datatypes.UUID]uint8{},
	}

	ctx := vcdmsdjwt.CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	checker := bitstringstatus.NewChecker(bitstringstatus.VerificationContext{X509Context: ctx.X509VerificationContext})
	changed, err := NewRevocationService(nil).WithBitstringStatus(checker, store).RefreshStatuses(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, changed, "one batch changed")

	for _, inst := range store.instances {
		require.Equal(t, uint8(statuslist.StatusInvalid), store.written[inst.InstanceID], "instance %s", inst.InstanceID)
	}
}
