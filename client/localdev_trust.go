package client

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/privacybydesign/irmago/internal/common"
)

// LOCAL DEVELOPMENT ONLY -- DO NOT COMMIT.
//
// Everything in this file exists so a build running on a device can reach the
// docker stack over TLS, and it must not reach a release. Deleting this one file
// removes it completely: the certificate is installed from init() below, so no
// other file calls into it and none needs editing back.
//
// The problem it solves is not a trust anchor in the wallet's own model. The
// EUDI trust stores hold the certificates that authenticate an issuer's document
// signer and a relying party's request; this is one layer below all of that, at
// the TLS handshake. testdata/configurations/certs/localhost.crt is the
// self-signed certificate the tls_proxy container serves, and nothing on an
// Android device has any reason to trust it, so the very first HTTPS call of an
// issuance -- fetching credential issuer metadata -- fails with "x509:
// certificate signed by unknown authority" before any EUDI trust decision is
// reached.
//
// Installing the certificate through Android's settings does not fix this for a
// gomobile build: Go's crypto/x509 reads the system certificate directories, not
// the user store that Settings writes to, so a user-installed CA is invisible to
// this code.
//
// The equivalent for the CLI tools is trustProxyCertificate in
// yivi/cli/eudicli/mdoc-e2e, which does the same thing for a process running on
// a laptop.
const localDevelopmentProxyCertificate = `-----BEGIN CERTIFICATE-----
MIIDzTCCArWgAwIBAgIUXgrYzUkZRCZIn5Og4FB8Okxs2TYwDQYJKoZIhvcNAQEL
BQAwazELMAkGA1UEBhMCTkwxEDAOBgNVBAgMB1V0cmVjaHQxEDAOBgNVBAcMB1V0
cmVjaHQxFTATBgNVBAoMDENhZXNhciBHcm9lcDENMAsGA1UECwwEWWl2aTESMBAG
A1UEAwwJbG9jYWxob3N0MB4XDTI2MDQwODE0MjkxNVoXDTM2MDQwNTE0MjkxNVow
azELMAkGA1UEBhMCTkwxEDAOBgNVBAgMB1V0cmVjaHQxEDAOBgNVBAcMB1V0cmVj
aHQxFTATBgNVBAoMDENhZXNhciBHcm9lcDENMAsGA1UECwwEWWl2aTESMBAGA1UE
AwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl9fw
ANR8TmCaRnzPfcLatbjyGqkYrhzLCYDv0eIQ4pL6lacgR+1Nr/cduBr7eXtxq54d
vqt/lSsgXhZTYCueRROpTUlw5NtJMJV+dpiNmNlinPoaV2Y5YrGcOMTkWE7snspl
u2rqiqYx9M41ooDoXnE+9+LzoMAC1E80UnfR+omdXWPkftH/bgDbnMIAcc+JSHSq
dvIHNLUehyRURUEc4H8tlhTl7hcEVz4HuwEh/YdoaXpz1HR7n4mCbGEkRFivB5Ig
fvAp22XbMDC55CLKHe1Ii2Y0Bz32nXA48YMm6ScjAyuytJJ3BY/T9j4YVUf1rv06
sYUo0HYaoMfoevSuDwIDAQABo2kwZzAdBgNVHQ4EFgQU7FpUO9sdAAj0MbfL7xNn
jejPU2gwHwYDVR0jBBgwFoAU7FpUO9sdAAj0MbfL7xNnjejPU2gwDwYDVR0TAQH/
BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEB
ACVnQK7STdgQLlWt3HZKtJHza0BYNNPU4TG9lhH+Sx9NFtOdbwZUNBCahU62rGOx
DD3KCPSccWH6wuY4qo6REDX1Hl7H7ij4gLgPSMGsyiTTrSGI+DaAjH5F6SJlm5Ca
91ExmKxuf7c3mPDo2HDs4OV9X+nkG5d4hq8WsfTxl7Fdp7HniY0c9w2mcEcnUGWa
Rm0VUbpcTOQ99XxRlb/5WibV7vxVcIxDXDIy8QVuynKkojvQ5QPo2UN3OrqJ/FG8
vQozoQ6Mep8FDc+FdpZdyUhP8xnfbNzpPGx2IK5vw9dZJlfQTw5G2KwxmJUj3nUq
0ZAXD9PNIN34SVhau05ynAU=
-----END CERTIFICATE-----
`

// init installs the certificate at package load, rather than from
// SetPreferences, so that it cannot be missed by a session that starts before
// developer mode is applied — or by an app that never sets developer mode at
// all. This whole file is local-development-only, so gating it on a runtime
// preference buys nothing and only adds a way for it to silently not happen.
func init() {
	trustLocalDevelopmentProxyCertificate()
}

// trustLocalDevelopmentProxyCertificate adds the docker TLS proxy's self-signed
// certificate to the roots this process accepts, alongside the system ones
// rather than in place of them, so ordinary HTTPS to real hosts keeps working.
//
// It replaces http.DefaultTransport because that is what the shared
// common.HTTPClient resolves to -- it carries a nil Transport on purpose -- and
// that client is what the EUDI code uses for metadata, token, nonce, credential
// and request_uri calls.
func trustLocalDevelopmentProxyCertificate() {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(localDevelopmentProxyCertificate)) {
		common.Logger.Warnf("local development proxy certificate could not be parsed; TLS to the docker stack will fail")
		return
	}
	http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	common.Logger.Warnf("LOCAL DEVELOPMENT ONLY: trusting the docker tls_proxy certificate for all outbound TLS")
}
