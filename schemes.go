package irma

import (
	"fmt"
	"path/filepath"
)

// SchemeManagerPointer points to a remote IRMA scheme, containing information to download the scheme,
// including its (pinned) public key.
type SchemeManagerPointer struct {
	Url       string // URL to download scheme from
	Demo      bool   // Whether or not this is a demo scheme; if true, private keys are also downloaded
	Publickey []byte // Public key of scheme against which to verify files after they have been downloaded
}

var DefaultSchemeManagers = [2]SchemeManagerPointer{
	{
		Url:  "https://privacybydesign.foundation/schememanager/irma-demo",
		Demo: true,
		Publickey: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHVnmAY+kGkFZn7XXozdI4HY8GOjm
54ngh4chTfn6WsTCf2w5rprfIqML61z2VTE4k8yJ0Z1QbyW6cdaao8obTQ==
-----END PUBLIC KEY-----`),
	},
	{
		Url: "https://privacybydesign.foundation/schememanager/pbdf",
		Publickey: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELzHV5ipBimWpuZIDaQQd+KmNpNop
dpBeCqpDwf+Grrw9ReODb6nwlsPJ/c/gqLnc+Y3sKOAJ2bFGI+jHBSsglg==
-----END PUBLIC KEY-----`),
	},
}

func (conf *Configuration) DownloadDefaultSchemes() error {
	Logger.Info("downloading default schemes (may take a while)")
	for _, s := range DefaultSchemeManagers {
		Logger.Debugf("Downloading scheme at %s", s.Url)
		scheme, err := DownloadSchemeManager(s.Url)
		if err != nil {
			return err
		}
		if err := conf.InstallSchemeManager(scheme, s.Publickey); err != nil {
			return err
		}
		if s.Demo {
			if err := conf.downloadPrivateKeys(scheme); err != nil {
				return err
			}
		}
	}
	Logger.Info("Finished downloading schemes")
	return nil
}

func (conf *Configuration) downloadPrivateKeys(scheme *SchemeManager) error {
	transport := NewHTTPTransport(scheme.URL)

	err := transport.GetFile("sk.pem", filepath.Join(conf.Path, scheme.ID, "sk.pem"))
	if err != nil { // If downloading of any of the private key fails just log it, and then continue
		Logger.Warnf("Downloading private key of scheme %s failed ", scheme.ID)
	}

	for issid := range conf.Issuers {
		// For all public keys that this issuer has in storage, see if a corresponding private key can be downloaded
		indices, err := conf.PublicKeyIndices(issid)
		if err != nil {
			return err
		}
		for _, index := range indices {
			remote := fmt.Sprintf("%s/PrivateKeys/%d.xml", issid.Name(), index)
			local := filepath.Join(conf.Path, scheme.ID, remote)
			if err = transport.GetFile(remote, filepath.FromSlash(local)); err != nil {
				Logger.Warnf("Downloading private key %d of issuer %s failed", index, issid.String())
			}
		}
	}

	return nil
}
