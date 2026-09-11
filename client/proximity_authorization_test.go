package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/proximity"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/sirupsen/logrus"
)

// TestMain gives the package a logger. eudi.Logger is normally installed by
// client.New, which these tests deliberately do not call: they run against bare
// structs so that no storage, scheme or configuration has to exist. The same
// guard the other eudi test packages use.
func TestMain(m *testing.M) {
	if eudi.Logger == nil {
		eudi.Logger = logrus.New()
		eudi.Logger.SetOutput(io.Discard)
	}
	os.Exit(m.Run())
}

// ============================================================
// A READER ASKING FOR MORE THAN IT MAY
// ============================================================
//
// Reader authentication says who is asking; the scheme extension in the same
// certificate says what that party is allowed to ask for. A reader that
// authenticates perfectly and then requests an attribute outside its authorized
// set is refused — the same check, against the same extension, that the OpenID4VP
// path applies to a verifier online.
//
// The refusal is deliberately asymmetric, and this is the thing worth pinning: the
// READER gets a well-formed response with documentErrors, because the ISO
// transaction is not in error and dropping the link would tell it less. The USER
// gets an error, because their wallet refused a request and "success" would be a
// lie about a session where nothing was disclosed and something was wrong.

// TestProximityUnauthorizedReaderIsRefusedAsAnError: the refusal reaches the app
// as a coherent final state.
//
// The regression this exists for: the error was recorded on the session state but
// the status was left alone, and State.Error never travels on its own — it goes to
// the app only as part of the state a finish() dispatches. The status the session
// later settled on was Status_Success, so the app was handed a successful session
// carrying an error, for a transaction it was never told had been refused.
func TestProximityUnauthorizedReaderIsRefusedAsAnError(t *testing.T) {
	consent, handler := newAuthorizationTestConsent(t)

	// Authorized for age_over_18 of the age verification credential, and asking for
	// the birth date.
	request := proximity.ConsentRequest{
		Plan: &clientmodels.DisclosurePlan{},
		Documents: []proximity.RequestedDocument{{
			DocType: mdoc.AgeVerificationDocType,
			Reader: &mdoc.ReaderAuthResult{
				Certificate: readerCertificate(t, mdoc.AgeVerificationDocType, "age_over_18"),
			},
		}},
		Query: dcql.DcqlQuery{Credentials: []dcql.CredentialQuery{{
			Id:     "doc0",
			Format: string(clientmodels.Format_MsoMdoc),
			Meta:   &dcql.Meta{DocTypeValue: mdoc.AgeVerificationDocType},
			Claims: []dcql.Claim{{
				Path: []any{mdoc.AgeVerificationDocType, "birth_date"},
			}},
		}}},
	}

	choices, err := consent.RequestConsent(request)
	if err != nil {
		t.Fatalf("a refusal is not a transport error: %v", err)
	}
	if len(choices) != 0 {
		t.Fatalf("an unauthorized reader got %d choices", len(choices))
	}

	// Never shown to the user: they are not asked to approve something the request
	// was not entitled to ask for in the first place.
	select {
	case state := <-handler.states:
		t.Fatalf("the app was asked about an unauthorized request: %v", state.Status)
	default:
	}

	if consent.session.State.Status != clientmodels.Status_Error {
		t.Errorf("status = %q, want %q: an error recorded beside any other status is one succeed() overwrites",
			consent.session.State.Status, clientmodels.Status_Error)
	}
	if consent.session.State.Error == nil {
		t.Fatal("the refusal was not recorded, so the user is never told why nothing was disclosed")
	}

	// And what eventually reaches the app says both halves of the same thing.
	consent.session.finish()
	select {
	case state := <-handler.states:
		if state.Status != clientmodels.Status_Error {
			t.Errorf("dispatched status = %q, want %q", state.Status, clientmodels.Status_Error)
		}
		if state.Error == nil {
			t.Error("the dispatched state carries no error")
		}
	default:
		t.Fatal("nothing was dispatched to the app")
	}
}

// TestProximityAuthorizedReaderStillReachesTheUser is the other side of the same
// check: a request inside the authorized set is not refused here, it is asked
// about. Without it the test above passes just as well on a wallet that refuses
// everything.
func TestProximityAuthorizedReaderStillReachesTheUser(t *testing.T) {
	consent, handler := newAuthorizationTestConsent(t)

	request := proximity.ConsentRequest{
		Plan: &clientmodels.DisclosurePlan{},
		Documents: []proximity.RequestedDocument{{
			DocType: mdoc.AgeVerificationDocType,
			Reader: &mdoc.ReaderAuthResult{
				Certificate: readerCertificate(t, mdoc.AgeVerificationDocType, "age_over_18"),
			},
		}},
		Query: dcql.DcqlQuery{Credentials: []dcql.CredentialQuery{{
			Id:     "doc0",
			Format: string(clientmodels.Format_MsoMdoc),
			Meta:   &dcql.Meta{DocTypeValue: mdoc.AgeVerificationDocType},
			Claims: []dcql.Claim{{
				Path: []any{mdoc.AgeVerificationDocType, "age_over_18"},
			}},
		}}},
	}

	done := make(chan []clientmodels.DisclosureDisconSelection, 1)
	go func() {
		choices, err := consent.RequestConsent(request)
		if err != nil {
			t.Errorf("RequestConsent: %v", err)
		}
		done <- choices
	}()

	select {
	case state := <-handler.states:
		if state.Status != clientmodels.Status_RequestPermission {
			t.Fatalf("dispatched status = %q, want %q", state.Status, clientmodels.Status_RequestPermission)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an authorized request never reached the user")
	}

	consent.answer(nil) // let RequestConsent return; the answer itself is not the subject
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RequestConsent did not return")
	}

	if consent.session.State.Error != nil {
		t.Errorf("an authorized request recorded an error: %v", consent.session.State.Error)
	}
}

// newAuthorizationTestConsent is newTestConsent with a client behind it, which the
// authorization path needs: reading the reader's scheme extension resolves its
// legal name in the current locale.
func newAuthorizationTestConsent(t *testing.T) (*proximityConsent, *recordingHandler) {
	t.Helper()

	handler := newRecordingHandler()
	client := &Client{
		sessionManager: sessionManager{Sessions: map[int]*session{}},
		currentLocale:  clientmodels.NewCurrentLocale("en"),
	}
	clientSession := &session{
		State:   &clientmodels.SessionState{Id: 1},
		handler: handler,
		client:  client,
	}
	consent := &proximityConsent{
		session: clientSession,
		client:  client,
		answers: make(chan *proximityAnswer, 1),
	}
	clientSession.proximityConsent = consent
	return consent, handler
}

// readerCertificate builds a reader certificate carrying the Yivi scheme
// extension, authorized for exactly the given attributes of one credential.
//
// Self-signed and never verified: this is the authorization half of the check,
// which reads the extension out of a certificate reader authentication has
// already accepted.
func readerCertificate(t *testing.T, credential string, attributes ...string) *x509.Certificate {
	t.Helper()

	requestor := scheme.RelyingPartyRequestor{
		Requestor: scheme.Requestor{
			Registration: "test",
			Organization: scheme.Organization{LegalName: map[string]string{"en": "Overreaching Reader"}},
		},
		RelyingParty: scheme.RelyingParty{
			AuthorizedQueryableAttributeSets: []scheme.AuthorizedAttributeSet{{
				Credential: credential,
				Attributes: attributes,
			}},
		},
	}
	// The extension holds a DER UTF8String whose contents are the scheme JSON, which
	// is what utils.GetRequestorInfoFromCertificate unwraps.
	document, err := json.Marshal(requestor)
	if err != nil {
		t.Fatalf("marshal scheme data: %v", err)
	}
	value, err := asn1.MarshalWithParams(string(document), "utf8")
	if err != nil {
		t.Fatalf("marshal scheme extension: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate reader key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x5CE),
		Subject:      pkix.Name{CommonName: "Scheme Reader"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 1, 123, 1}, // scheme.X509SchemeExtensionOID
			Value: value,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create reader cert: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse reader cert: %v", err)
	}
	return certificate
}
