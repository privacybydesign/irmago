package eudi

// Production trust anchors
const (
	Production_Yivi_RootCertificateRevocationListDistributionPoint       = "https://ca.yivi.app/ejbca/publicweb/crls/search.cgi?iHash=AKPlCD/saQ9CmdXzNQpPgmO%2BHQM"
	Production_Yivi_IssuerCaCertificateRevocationListDistributionPoint   = "https://ca.yivi.app/ejbca/publicweb/crls/search.cgi?iHash=TNFX2bhlb1JXido8TZQr1Wqlcb8"
	Production_Yivi_VerifierCaCertificateRevocationListDistributionPoint = "https://ca.yivi.app/ejbca/publicweb/crls/search.cgi?iHash=kP7IIn8hVVbRGQECuKyMxPkQM8k"

	Production_Yivi_IssuerTrustAnchor = `
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

	Production_Yivi_VerifierTrustAnchor = `
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
)

// ------------------------------------------------------------------------------

// Staging trust anchors
const (
	Staging_Yivi_RootCertificateRevocationListDistributionPoint       = "https://ca.staging.yivi.app/ejbca/publicweb/crls/search.cgi?iHash=kFCOt8NLhJ8g0WqMAnl%2BvoN2RuY"
	Staging_Yivi_IssuerCaCertificateRevocationListDistributionPoint   = "https://ca.staging.yivi.app/ejbca/publicweb/crls/search.cgi?iHash=NGSB30tAE2E/Z/j4V%2B%2BTTTS5Ay0"
	Staging_Yivi_VerifierCaCertificateRevocationListDistributionPoint = "https://ca.staging.yivi.app/ejbca/publicweb/crls/search.cgi?iHash=gVrSxh0lO5cdqAS18OiZ/oui5h4"

	Staging_Yivi_IssuerTrustAnchor = `
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

	// LOCAL DEVELOPMENT ONLY -- DO NOT COMMIT.
	//
	// The self-signed CA from testdata/eudi-pid-issuer-py/certs/ca.pem, the root
	// the eudi_pid_issuer_py container's document signer chains to. Without it the
	// wallet fetches a credential successfully and then refuses to store it, since
	// it verifies the MSO's chain against a trust anchor before anything is
	// written — "mdoc verification failed: chain verification failed".
	//
	// This is a separate store from the verifier anchor below: an issuer anchor
	// must not be able to authenticate a relying party, or vice versa. Registering
	// it here rather than in Verifiers is what keeps that boundary.
	Local_Demo_IssuerTrustAnchor = `
Subject: CN=Yivi Test EUDI Root CA
Issuer: CN=Yivi Test EUDI Root CA
-----BEGIN CERTIFICATE-----
MIIBljCCAT2gAwIBAgIUQV5HaZKiMElhN+N1AuRLk7PJvOgwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWWWl2aSBUZXN0IEVVREkgUm9vdCBDQTAeFw0yNjA1MTkxMTM5
MTlaFw0zNjA1MTYxMTM5MTlaMCExHzAdBgNVBAMMFllpdmkgVGVzdCBFVURJIFJv
b3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5gZajtxbEX9SRRDLM06zh
R27Ui/vAyTp8l+a/6MnoWkcF/96Nxyb9ejFNB0pxf601OZYrO7lBIH3KsZQTwJVD
o1MwUTAdBgNVHQ4EFgQUbRtcp/I/esL49jc0k2509Wd6JRgwHwYDVR0jBBgwFoAU
bRtcp/I/esL49jc0k2509Wd6JRgwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQD
AgNHADBEAiAl3QlSoUhzlnRP6ewQH67IIIV6iybC3FegBsFi24/zLgIgWeUPY83K
WTiL/Ir3Vw28eyT/vH82rx6wlkYbhRrKEzk=
-----END CERTIFICATE-----
`

	// LOCAL DEVELOPMENT ONLY -- DO NOT COMMIT.
	//
	// The self-signed CA from testdata/eudi/verifier/ca.crt, which signs the
	// relying party certificate the eudi_openid4vp / eudi_openid4vp_jwt containers
	// present. Added so an on-device run can use the local verifier while the
	// staging RP certificate is not yet authorized for eu.europa.ec.av.1.
	//
	// It is registered through its own addTrustAnchors call rather than appended
	// to Staging_Yivi_VerifierTrustAnchor: addTrustAnchors treats the LAST
	// certificate of a chain as the root, so appending it there would make this CA
	// the root of the real staging chain and both Yivi staging certificates would
	// be skipped with only a log warning.
	Local_Demo_VerifierTrustAnchor = `
Subject: CN=Demo Requestors Root,O=Demo Verifier CA,C=NL
Issuer: CN=Demo Requestors Root,O=Demo Verifier CA,C=NL
-----BEGIN CERTIFICATE-----
MIIB5DCCAYmgAwIBAgIUKp3l1e+X2zF9p49OH70NS4rA3VcwCgYIKoZIzj0EAwIw
RzELMAkGA1UEBhMCTkwxGTAXBgNVBAoMEERlbW8gVmVyaWZpZXIgQ0ExHTAbBgNV
BAMMFERlbW8gUmVxdWVzdG9ycyBSb290MB4XDTI1MDgwNTA5MjQzOFoXDTM1MDgw
MzA5MjQzOFowRzELMAkGA1UEBhMCTkwxGTAXBgNVBAoMEERlbW8gVmVyaWZpZXIg
Q0ExHTAbBgNVBAMMFERlbW8gUmVxdWVzdG9ycyBSb290MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAElfHqkpjpSmmijr87vW0ruduYTL/KKMTdzZFPBm3EMV8xzZAL
seXE5MY0bUbBkqAG5bWJUPf1KewjhlwMuTNTI6NTMFEwHQYDVR0OBBYEFDz3b3XV
Izc6lHcdBjuEo5SA4pZ2MB8GA1UdIwQYMBaAFDz3b3XVIzc6lHcdBjuEo5SA4pZ2
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhALfx43cubHCyMgts
23wjCKEPHUfoO9b5mI3qqIPZzwzbAiEA1iNh6vj9xUt5G0NPEd4ToTl1p6nqjKYE
s7X4XJAYkfM=
-----END CERTIFICATE-----
`

	Staging_Yivi_VerifierTrustAnchor = `
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
)
