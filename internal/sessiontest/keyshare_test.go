package sessiontest

import (
	"context"
	"encoding/base64"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi"
	"github.com/privacybydesign/irmago/internal/keysharecore"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server/keyshareserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var serv *http.Server

func startKeyshareServer(t *testing.T) {
	db := keyshareserver.NewMemoryDatabase()
	db.NewUser(keyshareserver.KeyshareUserData{
		Username: "",
		Coredata: keysharecore.EncryptedKeysharePacket{},
	})
	var ep keysharecore.EncryptedKeysharePacket
	p, err := base64.StdEncoding.DecodeString("YWJjZB7irkDzwMWtBC6PTItWmO2AgAGm1/gFOyrd+nyt3/0GaHLY5Z1S1TM6N5nzb1Jh+Nqx0z0c3f9R2UyoYuy+pnrerTpYL1mpoZZfz8MPqcrAMsmVdb2kHH0BuAGSC0V28tp1BCVzhYnfMJyrUlNWonsTWSn68Av1BwpIBOGxqBXYfW0JzaffuSmZIyubImmTN7p32ASbseJSNwu0Rg==")
	require.NoError(t, err)
	copy(ep[:], p)
	db.NewUser(keyshareserver.KeyshareUserData{
		Username: "testusername",
		Coredata: ep,
	})

	testdataPath := test.FindTestdataFolder(t)
	s, err := keyshareserver.New(&keyshareserver.Configuration{
		SchemesPath:           filepath.Join(testdataPath, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdataPath, "privatekeys"),
		URL:                   "http://localhost:8080/irma_keyshare_server/",
		DB:                    db,
		JwtKeyId:              0,
		JwtPrivateKeyFile:     filepath.Join(testdataPath, "jwtkeys", "kss-sk.pem"),
		StoragePrimaryKeyFile: filepath.Join(testdataPath, "keyshareStorageTestkey"),
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
	})
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Mount("/irma_keyshare_server/", s.Handler())

	serv = &http.Server{
		Addr:    "localhost:8080",
		Handler: r,
	}

	go func() {
		err := serv.ListenAndServe()
		if err == http.ErrServerClosed {
			err = nil
		}
		assert.NoError(t, err)
	}()
}

func stopKeyshareServer(t *testing.T) {
	err := serv.Shutdown(context.Background())
	assert.NoError(t, err)
}

func TestManualKeyshareSession(t *testing.T) {
	startKeyshareServer(t)
	defer stopKeyshareServer(t)
	request := irma.NewSignatureRequest("I owe you everything", irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"))
	ms := createManualSessionHandler(t, nil)

	_, status := manualSessionHelper(t, nil, ms, request, request, false)
	require.Equal(t, irma.ProofStatusValid, status)
	_, status = manualSessionHelper(t, nil, ms, request, nil, false)
	require.Equal(t, irma.ProofStatusValid, status)
}

func TestRequestorIssuanceKeyshareSession(t *testing.T) {
	startKeyshareServer(t)
	defer stopKeyshareServer(t)
	testRequestorIssuance(t, true, nil)
}

func TestKeyshareRegister(t *testing.T) {
	startKeyshareServer(t)
	defer stopKeyshareServer(t)
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	require.NoError(t, client.KeyshareRemoveAll())
	require.NoError(t, client.RemoveStorage())

	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})
	client.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")
	require.NoError(t, <-handler.c)

	require.Len(t, client.CredentialInfoList(), 1)

	StartIrmaServer(t, false, "")
	defer StopIrmaServer()

	requestorSessionHelper(t, getIssuanceRequest(true), client, sessionOptionReuseServer)
	keyshareSessions(t, client)
}

// Use the existing keyshare enrollment and credentials
// in a keyshare session of each session type.
// Use keyshareuser.sql to enroll the user at the keyshare server.
func TestKeyshareSessions(t *testing.T) {
	startKeyshareServer(t)
	defer stopKeyshareServer(t)
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	StartIrmaServer(t, false, "")
	defer StopIrmaServer()
	keyshareSessions(t, client)
}

func keyshareSessions(t *testing.T, client *irmaclient.Client) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	expiry := irma.Timestamp(irma.NewMetadataAttribute(0).Expiry())
	issuanceRequest := getCombinedIssuanceRequest(id)
	issuanceRequest.Credentials = append(issuanceRequest.Credentials,
		&irma.CredentialRequest{
			Validity:         &expiry,
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
			Attributes:       map[string]string{"email": "testusername"},
		},
	)
	requestorSessionHelper(t, issuanceRequest, client, sessionOptionReuseServer)

	disclosureRequest := getDisclosureRequest(id)
	disclosureRequest.AddSingle(irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"), nil, nil)
	requestorSessionHelper(t, disclosureRequest, client, sessionOptionReuseServer)

	sigRequest := getSigningRequest(id)
	sigRequest.AddSingle(irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"), nil, nil)
	requestorSessionHelper(t, sigRequest, client, sessionOptionReuseServer)
}

func TestIssuanceCombinedMultiSchemeSession(t *testing.T) {
	StartIrmaServer(t, false, "")
	defer StopIrmaServer()
	startKeyshareServer(t)
	defer stopKeyshareServer(t)

	id := irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")
	request := getCombinedIssuanceRequest(id)
	requestorSessionHelper(t, request, nil, sessionOptionReuseServer)

	id = irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request = irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
			Attributes: map[string]string{
				"email": "example@example.com",
			},
		},
	}, id)
	requestorSessionHelper(t, request, nil, sessionOptionReuseServer)
}
