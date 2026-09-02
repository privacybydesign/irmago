package walletconfig

import (
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/utils"
)

// The Yivi environments as this build knows them.
//
// Transitional. Until the Yivi Wallet Config CA exists and signs the first
// configs, neither environment is published: there is no URL to fetch from and
// no root to verify against, and the trusted entities are the ones compiled in
// below — the anchors that used to be PEM constants in eudi/trustanchors.go,
// expressed in the config's own entity model. At cutover the signed configs
// carry these entities, ConfigURL and SigningRoot are filled in, and the
// built-in entities are deleted.

const (
	// EnvironmentProduction and EnvironmentStaging are the names of the two Yivi
	// environments: what a config's `environment` field says, and what a Store
	// files a config under.
	EnvironmentProduction = "production"
	EnvironmentStaging    = "staging"
)

// YiviEnvironments is every environment a Yivi wallet build can live in:
// production and staging, in that order.
var YiviEnvironments = sync.OnceValue(func() []Environment {
	return []Environment{yiviProduction(), yiviStaging()}
})

func yiviProduction() Environment {
	return Environment{
		Name: EnvironmentProduction,
		BuiltinEntities: []TrustedEntity{
			yiviCA("yivi-issuers", RoleIssuer, productionYiviIssuerChainPEM, productionYiviRootCRL, productionYiviIssuerCACRL),
			yiviCA("yivi-verifiers", RoleVerifier, productionYiviVerifierChainPEM, productionYiviRootCRL, productionYiviVerifierCACRL),
			// The Ver.iD root signs both issuer and verifier certificates.
			thirdPartyCA("verid", "Ver.iD", productionVerIDRootPEM),
		},
	}
}

func yiviStaging() Environment {
	return Environment{
		Name: EnvironmentStaging,
		BuiltinEntities: []TrustedEntity{
			yiviCA("yivi-staging-issuers", RoleIssuer, stagingYiviIssuerChainPEM, stagingYiviRootCRL, stagingYiviIssuerCACRL),
			yiviCA("yivi-staging-verifiers", RoleVerifier, stagingYiviVerifierChainPEM, stagingYiviRootCRL, stagingYiviVerifierCACRL),
			// The Ver.iD development root signs both issuer and verifier certificates.
			thirdPartyCA("verid-dev", "Ver.iD (development)", developmentVerIDRootPEM),
		},
	}
}

// yiviCA is one of Yivi's own CAs: a chain of the issuing CA and the root it
// hangs under, anchored at the root with the issuing CA as intermediate. Yivi
// vouches for what it certifies itself, so the level is high.
func yiviCA(id string, role Role, chainPEM string, crlDistributionPoints ...string) TrustedEntity {
	chain := mustParseChain(id, chainPEM)
	root, intermediates := chain[len(chain)-1], chain[:len(chain)-1]
	// The PEM lists the chain leaf-to-root; the handle wants intermediates from
	// the root downwards.
	for i, j := 0, len(intermediates)-1; i < j; i, j = i+1, j-1 {
		intermediates[i], intermediates[j] = intermediates[j], intermediates[i]
	}
	handle := Handle{
		Type:                  HandleTypeX509CA,
		RootCertificate:       &Certificate{Certificate: root},
		CRLDistributionPoints: crlDistributionPoints,
	}
	for _, intermediate := range intermediates {
		handle.Intermediates = append(handle.Intermediates, Certificate{Certificate: intermediate})
	}
	return TrustedEntity{
		ID:         id,
		Name:       clientmodels.TranslatedString{"en": "Yivi", "nl": "Yivi"},
		Roles:      []Role{role},
		TrustLevel: clientmodels.TrustLevel_High,
		Handles:    []Handle{handle},
	}
}

// thirdPartyCA is a root Yivi anchors for both roles. High, as before this code
// existed: these roots were pinned next to Yivi's own.
func thirdPartyCA(id, name, rootPEM string) TrustedEntity {
	chain := mustParseChain(id, rootPEM)
	return TrustedEntity{
		ID:         id,
		Name:       clientmodels.TranslatedString{"en": name, "nl": name},
		Roles:      []Role{RoleIssuer, RoleVerifier},
		TrustLevel: clientmodels.TrustLevel_High,
		Handles: []Handle{{
			Type:            HandleTypeX509CA,
			RootCertificate: &Certificate{Certificate: chain[len(chain)-1]},
		}},
	}
}

// mustParseChain parses a compiled-in PEM chain. The constants below are part of
// the build, so a failure here is a build defect and panics at first use rather
// than anchoring nothing in silence.
func mustParseChain(id, pemChain string) []*x509.Certificate {
	chain, err := utils.ParsePemCertificateChain([]byte(pemChain))
	if err != nil {
		panic(fmt.Sprintf("walletconfig: built-in entity %q: %v", id, err))
	}
	if len(chain) == 0 {
		panic(fmt.Sprintf("walletconfig: built-in entity %q: no certificate in PEM", id))
	}
	return chain
}

// Production trust anchors.
const (
	productionYiviRootCRL        = "https://ca.yivi.app/ejbca/publicweb/crls/search.cgi?iHash=AKPlCD/saQ9CmdXzNQpPgmO%2BHQM"
	productionYiviIssuerCACRL    = "https://ca.yivi.app/ejbca/publicweb/crls/search.cgi?iHash=TNFX2bhlb1JXido8TZQr1Wqlcb8"
	productionYiviVerifierCACRL  = "https://ca.yivi.app/ejbca/publicweb/crls/search.cgi?iHash=kP7IIn8hVVbRGQECuKyMxPkQM8k"
	productionYiviIssuerChainPEM = `
Subject: CN=Yivi Attestation Providers CA,O=Yivi,C=NL
Issuer: CN=Yivi Requestors Root CA,O=Yivi,C=NL
-----BEGIN CERTIFICATE-----
MIIB5jCCAY2gAwIBAgIUDmP18B/Niv83bUlGCWVLgj/zDEMwCgYIKoZIzj0EAwQw
PjELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxIDAeBgNVBAMMF1lpdmkgUmVx
dWVzdG9ycyBSb290IENBMB4XDTI1MDkxOTA4MTMyM1oXDTQwMDkxMzA4MTMyMlow
RDELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxJjAkBgNVBAMMHVlpdmkgQXR0
ZXN0YXRpb24gUHJvdmlkZXJzIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
3tcJj5eiTUDzH8j5DCYZVdJEp3LHGtTLpyFGHMQ2XNBgEucAbz90qYvMwSBNP22I
aklST+9pXQs2FFuCfR8uiKNjMGEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAW
gBRUmaKaoWuB7Yx35NsCYsBSebDfuDAdBgNVHQ4EFgQUhgMtXET4IOJ9buDQJGiM
Nka2D2MwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMEA0cAMEQCIGFdvF6Sjtz2
OobvKAXVEceA1TJ4eHy0a39t/CpGdFv7AiBX3BCsdioE2bY/TZJSnKR8HDnf5Hoy
yWWmGlnckuP0gg==
-----END CERTIFICATE-----
Subject: CN=Yivi Requestors Root CA,O=Yivi,C=NL
Issuer: CN=Yivi Requestors Root CA,O=Yivi,C=NL
-----BEGIN CERTIFICATE-----
MIIB4zCCAYmgAwIBAgIUa1/sUuxZ8S4BMrTTy+owosdc5eMwCgYIKoZIzj0EAwQw
PjELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxIDAeBgNVBAMMF1lpdmkgUmVx
dWVzdG9ycyBSb290IENBMCAXDTI1MDkxOTA3Mjk0NloYDzIwNTUwOTA5MDcyOTQ1
WjA+MQswCQYDVQQGEwJOTDENMAsGA1UECgwEWWl2aTEgMB4GA1UEAwwXWWl2aSBS
ZXF1ZXN0b3JzIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARtliLj
sg1Lbp8iH4NNbfjHHUJje/U1BFWolXu/jgJfrkvuUGt5iMsIBHXUdHBxOJfPytqd
Pf6gdYd2Gk5HarSVo2MwYTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFFSZ
opqha4HtjHfk2wJiwFJ5sN+4MB0GA1UdDgQWBBRUmaKaoWuB7Yx35NsCYsBSebDf
uDAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwQDSAAwRQIgK9qm4AKZxudLjXEU
Si3+IDl+vIXsGmEwWgSitfB2x1wCIQDOxRpQEqIf+E6VIPR0erh7TRw7Zez04M8n
lzAIUfg4LA==
-----END CERTIFICATE-----
`
	productionYiviVerifierChainPEM = `
Subject: CN=Yivi Relying Parties CA,O=Yivi,C=NL
Issuer: CN=Yivi Requestors Root CA,O=Yivi,C=NL
-----BEGIN CERTIFICATE-----
MIIB4DCCAYegAwIBAgIUBSN5bB93aeuq69UFVHK5pzbs66MwCgYIKoZIzj0EAwQw
PjELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxIDAeBgNVBAMMF1lpdmkgUmVx
dWVzdG9ycyBSb290IENBMB4XDTI1MDkxOTA4MTEyNFoXDTQwMDkxMzA4MTEyM1ow
PjELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxIDAeBgNVBAMMF1lpdmkgUmVs
eWluZyBQYXJ0aWVzIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi6CJVtrb
9b6oAGFgd28qZxbH2c2nShSFIt/UN8QSUZGfFnDrIjWUkw2SI7Xha7mQ8MZpbHnf
Y5pQVFzhssXR+aNjMGEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRUmaKa
oWuB7Yx35NsCYsBSebDfuDAdBgNVHQ4EFgQUZirErCw75lEQe34Yhb92NXVrdLEw
DgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMEA0cAMEQCIFWUraLqgTnEEC7mibAj
w0rf8jtcfWjvzY2l0PbdTfN4AiAYiQzcmaVPM7YJf/3aS4ZQy47Z8N3gSFD7wCHd
agOJLA==
-----END CERTIFICATE-----
Subject: CN=Yivi Requestors Root CA,O=Yivi,C=NL
Issuer: CN=Yivi Requestors Root CA,O=Yivi,C=NL
-----BEGIN CERTIFICATE-----
MIIB4zCCAYmgAwIBAgIUa1/sUuxZ8S4BMrTTy+owosdc5eMwCgYIKoZIzj0EAwQw
PjELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxIDAeBgNVBAMMF1lpdmkgUmVx
dWVzdG9ycyBSb290IENBMCAXDTI1MDkxOTA3Mjk0NloYDzIwNTUwOTA5MDcyOTQ1
WjA+MQswCQYDVQQGEwJOTDENMAsGA1UECgwEWWl2aTEgMB4GA1UEAwwXWWl2aSBS
ZXF1ZXN0b3JzIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARtliLj
sg1Lbp8iH4NNbfjHHUJje/U1BFWolXu/jgJfrkvuUGt5iMsIBHXUdHBxOJfPytqd
Pf6gdYd2Gk5HarSVo2MwYTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFFSZ
opqha4HtjHfk2wJiwFJ5sN+4MB0GA1UdDgQWBBRUmaKaoWuB7Yx35NsCYsBSebDf
uDAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwQDSAAwRQIgK9qm4AKZxudLjXEU
Si3+IDl+vIXsGmEwWgSitfB2x1wCIQDOxRpQEqIf+E6VIPR0erh7TRw7Zez04M8n
lzAIUfg4LA==
-----END CERTIFICATE-----
`
	productionVerIDRootPEM = `
Subject: CN=Ver.iD Root CA,OU=Development team,O=Subst.id B.V.,postalCode=1013 AM,street=Koivistokade 3,L=Amsterdam,ST=Noord-Holland,C=NL
Issuer: CN=Ver.iD Root CA,OU=Development team,O=Subst.id B.V.,postalCode=1013 AM,street=Koivistokade 3,L=Amsterdam,ST=Noord-Holland,C=NL
-----BEGIN CERTIFICATE-----
MIIDBTCCAoqgAwIBAgIUR5qEGqVIjmng2qfbHTbs2CIXLTgwCgYIKoZIzj0EAwMw
gbAxCzAJBgNVBAYTAk5MMRYwFAYDVQQIEw1Ob29yZC1Ib2xsYW5kMRIwEAYDVQQH
EwlBbXN0ZXJkYW0xFzAVBgNVBAkTDktvaXZpc3Rva2FkZSAzMRAwDgYDVQQREwcx
MDEzIEFNMRYwFAYDVQQKEw1TdWJzdC5pZCBCLlYuMRkwFwYDVQQLExBEZXZlbG9w
bWVudCB0ZWFtMRcwFQYDVQQDEw5WZXIuaUQgUm9vdCBDQTAeFw0yNTExMjEwNzQ0
MjFaFw0zNTExMTkwNzQ0NTFaMIGwMQswCQYDVQQGEwJOTDEWMBQGA1UECBMNTm9v
cmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFtMRcwFQYDVQQJEw5Lb2l2aXN0
b2thZGUgMzEQMA4GA1UEERMHMTAxMyBBTTEWMBQGA1UEChMNU3Vic3QuaWQgQi5W
LjEZMBcGA1UECxMQRGV2ZWxvcG1lbnQgdGVhbTEXMBUGA1UEAxMOVmVyLmlEIFJv
b3QgQ0EwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATdqsle7OmL9SfSuP7yRid1seWc
Wl1oBPt/Qrguufwj85CYyio40D3dcWyJHK/o4cKo5ww+/sWXE+zYz1utx+FiwllC
5WQb16HPWdXEMJCIqzb2XInxiZ9dWYVpTVDNmGGjYzBhMA4GA1UdDwEB/wQEAwIB
BjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQTFeWtyRJNbgRTUFs3ou1DvGBX
2jAfBgNVHSMEGDAWgBQTFeWtyRJNbgRTUFs3ou1DvGBX2jAKBggqhkjOPQQDAwNp
ADBmAjEAph4IfXR83FEZ0dzrtyXMfFsQwyU/l3lo65ncAkO7wqZ+VfFScG0Q1DLe
QUGM3jboAjEApaYVEZwRz+VSxRWGqdifcDt+aoJrj6Bvzdc36dfOQ1Qrka91wXnz
iOCWv27pguzW
-----END CERTIFICATE-----
`
)

// Staging and development trust anchors, in force in the staging environment only.
const (
	stagingYiviRootCRL        = "https://ca.staging.yivi.app/ejbca/publicweb/crls/search.cgi?iHash=kFCOt8NLhJ8g0WqMAnl%2BvoN2RuY"
	stagingYiviIssuerCACRL    = "https://ca.staging.yivi.app/ejbca/publicweb/crls/search.cgi?iHash=NGSB30tAE2E/Z/j4V%2B%2BTTTS5Ay0"
	stagingYiviVerifierCACRL  = "https://ca.staging.yivi.app/ejbca/publicweb/crls/search.cgi?iHash=gVrSxh0lO5cdqAS18OiZ/oui5h4"
	stagingYiviIssuerChainPEM = `
Subject: CN=Yivi Staging Attestation Providers CA,O=Yivi,C=NL
Issuer: CN=Yivi Staging Requestors Root CA,O=Yivi,C=NL
-----BEGIN CERTIFICATE-----
MIICbTCCAhSgAwIBAgIUX8STjkv3TRF5UBstXlp4ILHy2h0wCgYIKoZIzj0EAwQw
RjELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxKDAmBgNVBAMMH1lpdmkgU3Rh
Z2luZyBSZXF1ZXN0b3JzIFJvb3QgQ0EwHhcNMjUwODEyMTUwODA1WhcNNDAwODA4
MTUwODA0WjBMMQswCQYDVQQGEwJOTDENMAsGA1UECgwEWWl2aTEuMCwGA1UEAwwl
WWl2aSBTdGFnaW5nIEF0dGVzdGF0aW9uIFByb3ZpZGVycyBDQTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABMDTwj6APykJnBdr0sCO8LpkULpbXFOBWV47hKKsJHsa
CVMarjLCYU3CV57UdklHSlMrtm7vfoDpYn4BvUv00UqjgdkwgdYwEgYDVR0TAQH/
BAgwBgEB/wIBADAfBgNVHSMEGDAWgBRjtHvVs5rhDnC0L2AUi+7ncyXe1jBwBgNV
HR8EaTBnMGWgY6Bhhl9odHRwczovL2NhLnN0YWdpbmcueWl2aS5hcHAvZWpiY2Ev
cHVibGljd2ViL2NybHMvc2VhcmNoLmNnaT9pSGFzaD1rRkNPdDhOTGhKOGcwV3FN
QW5sJTJCdm9OMlJ1WTAdBgNVHQ4EFgQUEjcBLRMmQGBJO0h04IL5Jwha1rEwDgYD
VR0PAQH/BAQDAgGGMAoGCCqGSM49BAMEA0cAMEQCIDEaWIs4uSm8KVQe+fy0EndE
Taj1ayt6dUgKQY/xZBO3AiAPYGwRlZMzbeCTFQ2ORLJiSowRtXzbmXpNDSyvtn7e
Dw==
-----END CERTIFICATE-----
Subject: CN=Yivi Staging Requestors Root CA,O=Yivi,C=NL
Issuer: CN=Yivi Staging Requestors Root CA,O=Yivi,C=NL
-----BEGIN CERTIFICATE-----
MIIB8jCCAZmgAwIBAgIUd8FwrZvzZ0+08+A0VNFgX5f/eIwwCgYIKoZIzj0EAwQw
RjELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxKDAmBgNVBAMMH1lpdmkgU3Rh
Z2luZyBSZXF1ZXN0b3JzIFJvb3QgQ0EwIBcNMjUwODA4MTAwMDUzWhgPMjA1NTA4
MDExMDAwNTJaMEYxCzAJBgNVBAYTAk5MMQ0wCwYDVQQKDARZaXZpMSgwJgYDVQQD
DB9ZaXZpIFN0YWdpbmcgUmVxdWVzdG9ycyBSb290IENBMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAECTtfysVgEPFVKrVL8FM/Jx3E64qquuKSfG2ZqEucIkH6QHGL
eJPEEhA1RUyGtPTLIZTjY5rHwR6foTSVThGrraNjMGEwDwYDVR0TAQH/BAUwAwEB
/zAfBgNVHSMEGDAWgBRjtHvVs5rhDnC0L2AUi+7ncyXe1jAdBgNVHQ4EFgQUY7R7
1bOa4Q5wtC9gFIvu53Ml3tYwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMEA0cA
MEQCIDCSNbPoyhDZ5A3SWupsyPj/tDF4xNoHYnE0WFIs2pz8AiA9mhXswiJPFbVR
9dYSupOhXkuQRk8CgJuN++OnESd8uw==
-----END CERTIFICATE-----
`
	stagingYiviVerifierChainPEM = `
Subject: CN=Yivi Staging Relying Parties CA,O=Yivi,C=NL
Issuer: CN=Yivi Staging Requestors Root CA,O=Yivi,C=NL
-----BEGIN CERTIFICATE-----
MIICaDCCAg6gAwIBAgIUVbrz0YgTTgjJE/qHcwLtn6lT4pEwCgYIKoZIzj0EAwQw
RjELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxKDAmBgNVBAMMH1lpdmkgU3Rh
Z2luZyBSZXF1ZXN0b3JzIFJvb3QgQ0EwHhcNMjUwODA4MTEzMDUxWhcNNDAwODA0
MTEzMDUwWjBGMQswCQYDVQQGEwJOTDENMAsGA1UECgwEWWl2aTEoMCYGA1UEAwwf
WWl2aSBTdGFnaW5nIFJlbHlpbmcgUGFydGllcyBDQTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABD6/Jx9e/BIjRZQNSMcyvb6jcv9jtE9DEnQUgdkR4ZbMsEqAa6Kj
SF358k8N8DrV3nRvi2jbcnXP2gWXc3yTpZujgdkwgdYwEgYDVR0TAQH/BAgwBgEB
/wIBADAfBgNVHSMEGDAWgBRjtHvVs5rhDnC0L2AUi+7ncyXe1jBwBgNVHR8EaTBn
MGWgY6Bhhl9odHRwczovL2NhLnN0YWdpbmcueWl2aS5hcHAvZWpiY2EvcHVibGlj
d2ViL2NybHMvc2VhcmNoLmNnaT9pSGFzaD1rRkNPdDhOTGhKOGcwV3FNQW5sJTJC
dm9OMlJ1WTAdBgNVHQ4EFgQUn+JmQGo29ozmYyzmKGG5lYN5maEwDgYDVR0PAQH/
BAQDAgGGMAoGCCqGSM49BAMEA0gAMEUCIQDs40VU7/tHrBsHdwVj2kc+ZqpvLoOf
EtyHWcNN5HZpUAIgI3qf4KxHuFXdzEakHYb4aOpiQI9O7Sk8TUxJT7jymXM=
-----END CERTIFICATE-----
Subject: CN=Yivi Staging Requestors Root CA,O=Yivi,C=NL
Issuer: CN=Yivi Staging Requestors Root CA,O=Yivi,C=NL
-----BEGIN CERTIFICATE-----
MIIB8jCCAZmgAwIBAgIUd8FwrZvzZ0+08+A0VNFgX5f/eIwwCgYIKoZIzj0EAwQw
RjELMAkGA1UEBhMCTkwxDTALBgNVBAoMBFlpdmkxKDAmBgNVBAMMH1lpdmkgU3Rh
Z2luZyBSZXF1ZXN0b3JzIFJvb3QgQ0EwIBcNMjUwODA4MTAwMDUzWhgPMjA1NTA4
MDExMDAwNTJaMEYxCzAJBgNVBAYTAk5MMQ0wCwYDVQQKDARZaXZpMSgwJgYDVQQD
DB9ZaXZpIFN0YWdpbmcgUmVxdWVzdG9ycyBSb290IENBMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAECTtfysVgEPFVKrVL8FM/Jx3E64qquuKSfG2ZqEucIkH6QHGL
eJPEEhA1RUyGtPTLIZTjY5rHwR6foTSVThGrraNjMGEwDwYDVR0TAQH/BAUwAwEB
/zAfBgNVHSMEGDAWgBRjtHvVs5rhDnC0L2AUi+7ncyXe1jAdBgNVHQ4EFgQUY7R7
1bOa4Q5wtC9gFIvu53Ml3tYwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMEA0cA
MEQCIDCSNbPoyhDZ5A3SWupsyPj/tDF4xNoHYnE0WFIs2pz8AiA9mhXswiJPFbVR
9dYSupOhXkuQRk8CgJuN++OnESd8uw==
-----END CERTIFICATE-----
`
	developmentVerIDRootPEM = `
Subject: CN=Ver.iD Dev Root CA,OU=Development team,O=Subst.id B.V.,postalCode=1013 AM,street=Koivistokade 3,L=Amsterdam,ST=Noord-Holland,C=NL
Issuer: CN=Ver.iD Dev Root CA,OU=Development team,O=Subst.id B.V.,postalCode=1013 AM,street=Koivistokade 3,L=Amsterdam,ST=Noord-Holland,C=NL
-----BEGIN CERTIFICATE-----
MIIDDDCCApKgAwIBAgIUNxnfZr1ei5h+X2CFs2izisJly5swCgYIKoZIzj0EAwMw
gbQxCzAJBgNVBAYTAk5MMRYwFAYDVQQIEw1Ob29yZC1Ib2xsYW5kMRIwEAYDVQQH
EwlBbXN0ZXJkYW0xFzAVBgNVBAkTDktvaXZpc3Rva2FkZSAzMRAwDgYDVQQREwcx
MDEzIEFNMRYwFAYDVQQKEw1TdWJzdC5pZCBCLlYuMRkwFwYDVQQLExBEZXZlbG9w
bWVudCB0ZWFtMRswGQYDVQQDExJWZXIuaUQgRGV2IFJvb3QgQ0EwHhcNMjUwNzAy
MTEyOTQ5WhcNMzUwNjMwMTEzMDE5WjCBtDELMAkGA1UEBhMCTkwxFjAUBgNVBAgT
DU5vb3JkLUhvbGxhbmQxEjAQBgNVBAcTCUFtc3RlcmRhbTEXMBUGA1UECRMOS29p
dmlzdG9rYWRlIDMxEDAOBgNVBBETBzEwMTMgQU0xFjAUBgNVBAoTDVN1YnN0Lmlk
IEIuVi4xGTAXBgNVBAsTEERldmVsb3BtZW50IHRlYW0xGzAZBgNVBAMTElZlci5p
RCBEZXYgUm9vdCBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABD3NwwE2awGI8KSz
86yYWoOR3EHJnhkPSsYEYkqQtQ4yRUak7206eGHC6brGtv3PTFviqQhmT93QCLgm
meJCzkRGqWgvscOtfx2INEwkWYe5/HsCwuKCH4YjrsTH/iFpeKNjMGEwDgYDVR0P
AQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI6IeA0r74RwATsB
EP7S4sZRdb85MB8GA1UdIwQYMBaAFI6IeA0r74RwATsBEP7S4sZRdb85MAoGCCqG
SM49BAMDA2gAMGUCMQD8rLlq1QTBqw2IsZfFTNJyqOfrQCEmf+R/VMYxKrmK051L
3TB6nw+/NtwVIl6fBJECMF8sl61iMvaY5q02RZOqJZIMknCqJwy4/JMGVRFmpfcR
pfcb9ZXzcEeIf/fVPsaMTg==
-----END CERTIFICATE-----
`
)
