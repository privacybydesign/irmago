package integrationtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	cose "github.com/veraison/go-cose"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/isomdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/mdoc_dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
)

const (
	avDocType   = mdoc.AgeVerificationDocType
	avNameSpace = mdoc.AgeVerificationNameSpace

	testIssuerURL      = "https://issuer.example.com"
	testOrigin         = "https://verifier.example.com"
	testCredentialHash = "test-mdoc-batch-hash"
)

// heldClaims is what the wallet is issued in every test here. age_over_65 is
// deliberately NOT among them: it is the element the partial-satisfaction test
// asks for and cannot be given.
var heldClaims = map[string]any{
	"age_over_18": true,
	"age_over_16": true,
	"age_over_21": false,
}

// TestMain mirrors mdoc_dcql's. Without it eudi.Logger is nil, and the display
// resolver this path reaches through the real candidate search panics inside
// logrus rather than failing.
func TestMain(m *testing.M) {
	if eudi.Logger == nil {
		eudi.Logger = logrus.StandardLogger()
	}
	os.Exit(m.Run())
}

// ============================================================
// THE READER
// ============================================================

// reader is the verifier's whole half of an org-iso-mdoc exchange: the reader
// authentication identity of 9.1.4, and the ephemeral key and EncryptionInfo of
// 18013-7 Annex C that the response is sealed against.
type reader struct {
	rootCert *x509.Certificate
	leafCert *x509.Certificate
	leafKey  *ecdsa.PrivateKey

	// ephemeral is the HPKE recipient key. The wallet recovers its public half
	// from encryptionInfo; only the reader can open what is sealed to it.
	ephemeral *ecdsa.PrivateKey

	// encryptionInfo is kept as the base64url TEXT, never as a decoded struct:
	// the session transcript hashes this exact string on both sides.
	encryptionInfo string
}

// isoMdocReaderAuthEKU is 1.0.18013.5.1.6, the mdlReaderAuth usage of Table B.6.
// Stamped here so the reader certificate this test builds is the conformant
// shape, even though mdoc.VerifyReaderAuth reports its absence rather than
// enforcing it.
var isoMdocReaderAuthEKU = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}

func newReader(t *testing.T) *reader {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(0x0CA),
		Subject:               pkix.Name{CommonName: "Test Reader CA", Organization: []string{"Yivi Test"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(0x1EA),
		Subject:               pkix.Name{CommonName: "Test mdoc Reader", Organization: []string{"Yivi Test"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{isoMdocReaderAuthEKU},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	ephemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	nonce := make([]byte, 16)
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	info, err := mdoc.NewDCAPIEncryptionInfo(nonce, &ephemeral.PublicKey)
	require.NoError(t, err)
	encoded, err := cbor.Marshal(info)
	require.NoError(t, err)

	return &reader{
		rootCert:       rootCert,
		leafCert:       leafCert,
		leafKey:        leafKey,
		ephemeral:      ephemeral,
		encryptionInfo: base64.RawURLEncoding.EncodeToString(encoded),
	}
}

// roots is the anchor pool the wallet holds for this reader. In the wallet
// proper this is Configuration.Verifiers, reached through
// mdoc.NewVerifierFromTrustSource.
func (r *reader) roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(r.rootCert)
	return pool
}

// transcript is the session transcript both sides derive independently: the
// wallet from the request, the reader from what it sent. They agree only if the
// encryptionInfo text and the origin agree, which is the property the whole
// handover rests on.
func (r *reader) transcript(t *testing.T) mdoc.SessionTranscript {
	t.Helper()
	transcript, err := mdoc.NewDCAPISessionTranscript(r.encryptionInfo, testOrigin)
	require.NoError(t, err)
	return transcript
}

// request builds the `data` member of an org-iso-mdoc DC API request asking for
// the named elements of one docType.
//
// signed controls reader authentication, and it is not a detail: an unsigned
// request for an age verification credential is entitled to nothing at all
// (there is no 7.2.1 carve-out outside the mDL), so a test that forgets to sign
// is testing a refusal rather than the path it meant to.
func (r *reader) request(t *testing.T, signed bool, docType, namespace string, elements ...string) []byte {
	t.Helper()

	wanted := mdoc.DataElements{}
	for _, element := range elements {
		wanted[element] = false
	}
	docRequest, err := mdoc.NewDocRequest(mdoc.ItemsRequest{
		DocType:    docType,
		NameSpaces: map[string]mdoc.DataElements{namespace: wanted},
	}, nil)
	require.NoError(t, err)

	if signed {
		// Over the ItemsRequestBytes NewDocRequest just produced, never over a
		// re-encoding of them: 9.1.4.4 signs the bytes that travel.
		readerAuth, err := mdoc.SignReaderAuth(
			r.leafKey, cose.AlgorithmES256,
			[]*x509.Certificate{r.leafCert, r.rootCert},
			r.transcript(t), docRequest.ItemsRequest)
		require.NoError(t, err)
		docRequest.ReaderAuth = readerAuth
	}

	encoded, err := mdoc.DeviceRequest{
		Version:     mdoc.DeviceRequestVersion,
		DocRequests: []mdoc.DocRequest{docRequest},
	}.Encode()
	require.NoError(t, err)

	data, err := json.Marshal(map[string]string{
		"deviceRequest":  base64.RawURLEncoding.EncodeToString(encoded),
		"encryptionInfo": r.encryptionInfo,
	})
	require.NoError(t, err)
	return data
}

// open is what the verifier does with the answer: unseal against its own
// transcript and decode.
func (r *reader) open(t *testing.T, sealed mdoc.DCAPIEncryptedResponse) mdoc.DeviceResponse {
	t.Helper()

	plaintext, err := mdoc.OpenDCAPIResponse(sealed, r.ephemeral, r.transcript(t))
	require.NoError(t, err)

	var response mdoc.DeviceResponse
	require.NoError(t, cbor.Unmarshal(plaintext, &response))
	return response
}

// ============================================================
// THE WALLET
// ============================================================

// consent stands in for the user, and is the only fake left in this package.
type consent struct {
	refuse bool

	called bool
	seen   isomdoc.ConsentRequest

	// before runs while the wallet is parked waiting for an answer, which is the
	// only moment a test can observe storage mid-disclosure.
	before func(isomdoc.ConsentRequest)
}

// RequestConsent approves every attribute of the first option of every pick-one,
// which is what a user tapping through the default choice does.
func (c *consent) RequestConsent(request isomdoc.ConsentRequest) ([]clientmodels.DisclosureDisconSelection, error) {
	c.called = true
	c.seen = request
	if c.before != nil {
		c.before(request)
	}
	if c.refuse {
		return nil, nil
	}

	var choices []clientmodels.DisclosureDisconSelection
	for _, pickOne := range request.Plan.DisclosureChoicesOverview {
		if len(pickOne.OwnedOptions) == 0 {
			continue
		}
		var selected []clientmodels.SelectedCredential
		for _, credential := range pickOne.OwnedOptions[0].Credentials {
			paths := make([][]any, 0, len(credential.Attributes))
			for _, attribute := range credential.Attributes {
				paths = append(paths, attribute.ClaimPath)
			}
			selected = append(selected, clientmodels.SelectedCredential{
				CredentialId:   credential.CredentialId,
				CredentialHash: credential.Hash,
				AttributePaths: paths,
			})
		}
		choices = append(choices, clientmodels.DisclosureDisconSelection{Credentials: selected})
	}
	return choices, nil
}

// failFirstBinder is the real device key binder with a fault injected in front
// of it: the first N resolutions fail, the rest go through.
//
// This is the only way to reach a failure AFTER an instance has been reserved
// and before any response exists, which is the window the reserve/spend split
// exists for. Every other failure on this path happens either before the
// reservation or after the seal.
type failFirstBinder struct {
	inner    isomdoc.DeviceKeyBinder
	failures int
}

func (b *failFirstBinder) HolderForDeviceKey(deviceKey *ecdsa.PublicKey) (mdoc.Holder, error) {
	if b.failures > 0 {
		b.failures--
		return nil, fmt.Errorf("injected fault: no device key for this instance")
	}
	return b.inner.HolderForDeviceKey(deviceKey)
}

// env is one wallet holding one genuinely issued mdoc, wired to one reader.
type env struct {
	reader *reader

	store    db.MdocStore
	keyStore db.MdocDeviceKeyStore

	// issuerVerifier is the READER's verifier, trusting the issuer's IACA. It is
	// not the one the session uses, which trusts the reader CA instead.
	issuerVerifier *mdoc.Verifier

	queries   *dcql.DcqlHandler
	instances *services.MdocInstanceSelector
	consent   *consent

	discloser *isomdoc.WalletDiscloser
	session   *isomdoc.Session
}

// newEnv issues batchSize real mdocs, each bound to its own device key as
// issuance does, runs every one through the production format parser and stores
// them as one batch — so every layer below reads exactly the bytes issuance
// writes rather than a hand-built fixture.
//
// Copied in shape from mdoc_dcql's newTestEnvWithBatchSize deliberately: the
// point of these tests is lost the moment the stored bytes stop being the ones a
// real issuance produces.
func newEnv(t *testing.T, batchSize uint) *env {
	t.Helper()

	issuer, err := mdoc.NewTestIssuer()
	require.NoError(t, err)
	issuerVerifier := mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})
	parser := services.NewMdocCredentialFormatParser(issuerVerifier)

	var (
		instances     []models.MdocBatchInstance
		deviceKeyRows []models.MdocDeviceKey
		first         *services.ParsedCredential
	)
	for range batchSize {
		holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		holderKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(holderKey)
		require.NoError(t, err)

		issued, err := issuer.Issue(avDocType, avNameSpace, heldClaims, &holderKey.PublicKey)
		require.NoError(t, err)
		issuedCBOR, err := cbor.Marshal(issued)
		require.NoError(t, err)

		// The same seam client.New registers for mso_mdoc: it decides both the
		// claims cache the candidate search matches on and the raw bytes the
		// instance selector re-decodes.
		parsed, err := parser.ParseAndVerify(
			base64.RawURLEncoding.EncodeToString(issuedCBOR), testIssuerURL, true)
		require.NoError(t, err)
		require.NotNil(t, parsed.Mdoc)
		require.NotEmpty(t, parsed.Mdoc.DeviceKeyThumbprint)
		if first == nil {
			first = parsed
		}

		instances = append(instances, models.MdocBatchInstance{IssuerSigned: parsed.RawCredentialBytes})
		deviceKeyRows = append(deviceKeyRows, models.MdocDeviceKey{
			PublicKeyThumbprint: parsed.Mdoc.DeviceKeyThumbprint,
			PrivateKey:          holderKeyPKCS8,
			Curve:               "P-256",
		})
	}

	eudiStorage := newTestStorage(t)
	store := db.NewMdocStore(eudiStorage.Db())
	keyStore := db.NewMdocDeviceKeyStore(eudiStorage.Db())

	batch := &models.MdocBatch{
		DocType:          first.Mdoc.DocType,
		CredentialIssuer: testIssuerURL,
		Hash:             testCredentialHash,
		Namespaces:       first.Mdoc.Namespaces,
		SignedAt:         first.Mdoc.ValidityInfo.Signed,
		ValidFrom:        first.Mdoc.ValidityInfo.ValidFrom,
		ValidUntil:       first.Mdoc.ValidityInfo.ValidUntil,
		BatchSize:        batchSize,
		RemainingCount:   batchSize,
		IssuerVerified:   true,
		Instances:        instances,
	}
	require.NoError(t, store.StoreBatch(batch))
	require.NoError(t, keyStore.StoreKeys(deviceKeyRows))
	for i := range deviceKeyRows {
		require.NoError(t, keyStore.LinkToInstance(deviceKeyRows[i].ID, batch.Instances[i].ID))
	}

	e := &env{
		reader:   newReader(t),
		store:    store,
		keyStore: keyStore,

		issuerVerifier: issuerVerifier,

		// The same handler the OpenID4VP path searches with, over the same
		// storage, wired as client.New wires it.
		queries: dcql.NewDcqlHandler([]dcql.DcqlCredentialQueryHandler{
			mdoc_dcql.NewMdocDcqlHandler(eudiStorage, clientmodels.NewCurrentLocale("en"),
				services.NewMdocDeviceKeyBinder(keyStore)),
		}),
		instances: services.NewMdocInstanceSelector(store),
		consent:   &consent{},
	}
	e.wire(services.NewMdocDeviceKeyBinder(keyStore))
	return e
}

// wire builds the discloser and session over this env's storage with the given
// device key binder, replacing any previous pair.
//
// Rebuilding rather than mutating is what lets a test substitute a faulting
// binder without the rest of the stack knowing, exactly as mdoc_dcql's
// withDeviceKeyBinder does.
func (e *env) wire(binder isomdoc.DeviceKeyBinder) {
	e.discloser = isomdoc.NewWalletDiscloser(e.queries, e.instances, binder, e.consent)
	e.session = &isomdoc.Session{
		// The reader trust model, not the issuer one — the wallet authenticates a
		// reader against the same anchors that authenticate an OpenID4VP relying
		// party.
		Verifier:  mdoc.NewVerifierFromPool(e.reader.roots()),
		Discloser: e.discloser,
	}
}

// realBinder is the production device key binder over this env's key store.
func (e *env) realBinder() isomdoc.DeviceKeyBinder {
	return services.NewMdocDeviceKeyBinder(e.keyStore)
}

// respond drives one whole exchange the way client.isoMdocSession does: parse
// the DC API data member, answer it, and hand back the sealed response.
func (e *env) respond(t *testing.T, data []byte) (mdoc.DCAPIEncryptedResponse, error) {
	t.Helper()

	// Released on every path out, as the client does. Respond releases too; this
	// covers the paths that never reach it.
	defer e.discloser.Release()

	request, err := isomdoc.RequestFromDcApi(data, testOrigin)
	require.NoError(t, err)
	return e.session.Respond(request)
}

// remaining reads the batch's unspent count straight out of storage.
func (e *env) remaining(t *testing.T) uint {
	t.Helper()
	batch, err := e.store.GetBatchByHash(testCredentialHash)
	require.NoError(t, err)
	return batch.RemainingCount
}

func newTestStorage(t *testing.T) storage.Storage {
	t.Helper()

	var aesKey [32]byte
	copy(aesKey[:], "0123456789abcdef0123456789abcdef")

	s, err := storage.NewStorageWithDialector(
		sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", aesKey[:])},
		filesystem.NewFileSystemStorage(aesKey, t.TempDir()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}
