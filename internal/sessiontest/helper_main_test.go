package sessiontest

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/privacybydesign/gabi/signed"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Create HTTP server for scheme managers
	test.StartSchemeManagerHttpServer()

	retval := m.Run()

	test.StopSchemeManagerHttpServer()

	os.Exit(retval)
}

func parseStorage(t *testing.T, opts ...option) (*irmaclient.IrmaClient, *TestClientHandler) {
	storage := test.SetupTestStorage(t)
	return parseExistingStorage(t, storage, opts...)
}

func parseExistingStorage(t *testing.T, storageFolder string, options ...option) (*irmaclient.IrmaClient, *TestClientHandler) {
	handler := &TestClientHandler{t: t, c: make(chan error), storage: storageFolder}
	path := test.FindTestdataFolder(t)

	var signer irmaclient.Signer
	bts, err := os.ReadFile(filepath.Join(storageFolder, "client", "ecdsa_sk.pem"))
	if os.IsNotExist(err) {
		signer = test.NewSigner(t)
	} else {
		require.NoError(t, err)
		sk, err := signed.UnmarshalPemPrivateKey(bts)
		require.NoError(t, err)
		signer = test.LoadSigner(t, sk)
	}

	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(path, "irma_configuration")

	conf, err := irma.NewConfiguration(
		filepath.Join(storagePath, "irma_configuration"),
		irma.ConfigurationOptions{Assets: irmaConfigurationPath, IgnorePrivateKeys: true},
	)
	require.NoError(t, err)

	irmaStorage := irmaclient.NewIrmaStorage(storagePath, conf, aesKey)
	require.NoError(t, irmaStorage.Open())

	sdjwtStorage, err := irmaclient.NewInMemorySdJwtVcStorage()
	require.NoError(t, err)

	keyBinder := sdjwtvc.NewDefaultKeyBinder(sdjwtvc.NewInMemoryKeyBindingStorage())

	x509Options, err := utils.CreateX509VerifyOptionsFromCertChain(
		testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes,
	)
	require.NoError(t, err)

	context := sdjwtvc.SdJwtVcVerificationContext{
		VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: *x509Options,
		},
		Clock:       sdjwtvc.NewSystemClock(),
		JwtVerifier: sdjwtvc.NewJwxJwtVerifier(),
	}
	client, err := irmaclient.NewIrmaClient(
		conf,
		handler,
		signer,
		irmaStorage,
		context,
		sdjwtStorage,
		keyBinder,
	)
	require.NoError(t, err)

	// Set max version we want to test on
	opts := processOptions(options...)
	if opts.enabled(optionNoSchemeAssets) {
		client.Configuration, err = irma.NewConfiguration(
			client.Configuration.Path,
			irma.ConfigurationOptions{IgnorePrivateKeys: true},
		)
		require.NoError(t, err)
		err = client.Configuration.ParseFolder()
		require.NoError(t, err)
	}

	if opts.enabled(optionPrePairingClient) {
		version := extractClientMaxVersion(client)
		// set to largest protocol version that dos not support pairing
		*version = irma.ProtocolVersion{Major: 2, Minor: 7}
	}

	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})
	return client, handler
}

func getDisclosureRequest(id irma.AttributeTypeIdentifier) *irma.DisclosureRequest {
	return irma.NewDisclosureRequest(id)
}

func getSigningRequest(id irma.AttributeTypeIdentifier) *irma.SignatureRequest {
	return irma.NewSignatureRequest("test", id)
}

func getIssuanceRequest(defaultValidity bool) *irma.IssuanceRequest {
	temp := irma.Timestamp(irma.FloorToEpochBoundary(time.Now().AddDate(1, 0, 0)))
	var expiry *irma.Timestamp
	if !defaultValidity {
		expiry = &temp
	}
	return irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			Validity:         expiry,
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
			Attributes: map[string]string{
				"university":        "Radboud",
				"studentCardNumber": "31415927",
				"studentID":         "s1234567",
				"level":             "42",
			},
		},
	})
}

func getNameIssuanceRequest() *irma.IssuanceRequest {
	expiry := irma.Timestamp(irma.NewMetadataAttribute(0).Expiry())
	return irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			Validity:         &expiry,
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
			Attributes: map[string]string{
				"firstnames": "Johan Pieter",
				"firstname":  "Johan",
				"familyname": "Stuivezand",
			},
		},
	})

}

func getSpecialIssuanceRequest(defaultValidity bool, attribute string) *irma.IssuanceRequest {
	request := getIssuanceRequest(defaultValidity)
	request.Credentials[0].Attributes["studentCardNumber"] = attribute
	return request
}

func getCombinedIssuanceRequest(id irma.AttributeTypeIdentifier) *irma.IssuanceRequest {
	request := getIssuanceRequest(false)
	request.AddSingle(id, nil, nil)
	return request
}

func getMultipleIssuanceRequest() *irma.IssuanceRequest {
	request := getIssuanceRequest(false)
	request.Credentials = append(request.Credentials, &irma.CredentialRequest{
		Validity:         request.Credentials[0].Validity,
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
		Attributes: map[string]string{
			"firstnames": "Johan Pieter",
			"firstname":  "Johan",
			"familyname": "Stuivezand",
		},
	})
	return request
}

func extractClientTransport(dismisser irmaclient.SessionDismisser) *irma.HTTPTransport {
	return extractPrivateField(dismisser, "transport").(*irma.HTTPTransport)
}

func extractClientMaxVersion(client *irmaclient.IrmaClient) *irma.ProtocolVersion {
	return extractPrivateField(client, "maxVersion").(*irma.ProtocolVersion)
}

func extractPrivateField(i interface{}, field string) interface{} {
	rct := reflect.ValueOf(i).Elem().FieldByName(field)
	return reflect.NewAt(rct.Type(), unsafe.Pointer(rct.UnsafeAddr())).Elem().Interface()
}

func setPairingMethod(method irma.PairingMethod, handler *TestHandler) string {
	optionsRequest := irma.NewFrontendOptionsRequest()
	optionsRequest.PairingMethod = method
	options := &irma.SessionOptions{}
	err := handler.frontendTransport.Post("frontend/options", options, optionsRequest)
	require.NoError(handler.t, err)
	return options.PairingCode
}

func expectedRequestorInfo(t *testing.T, conf *irma.Configuration) *irma.RequestorInfo {
	if common.ForceHTTPS {
		return irma.NewRequestorInfo("localhost")
	}
	require.Contains(t, conf.Requestors, "localhost")
	return conf.Requestors["localhost"]
}
