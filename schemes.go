package irma

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/privacybydesign/irmago/internal/common"
)

// SchemeManagerPointer points to a remote IRMA scheme, containing information to download the scheme,
// including its (pinned) public key.
type SchemeManagerPointer struct {
	Url       string // URL to download scheme from
	Publickey []byte // Public key of scheme against which to verify files after they have been downloaded
}

var DefaultSchemeManagers = [2]SchemeManagerPointer{
	{
		Url: "https://privacybydesign.foundation/schememanager/irma-demo",
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
	}
	Logger.Info("Finished downloading schemes")
	return nil
}

// downloadDemoPrivateKeys attempts to download the scheme and issuer private keys, if the scheme is
// a demo scheme and if they are not already present in the scheme, without failing if any of them
// is not available.
func (conf *Configuration) downloadDemoPrivateKeys(scheme *SchemeManager) error {
	if !scheme.Demo {
		return nil
	}

	Logger.Debugf("Attempting downloading of private keys of scheme %s", scheme.ID)
	transport := NewHTTPTransport(scheme.URL, true)

	err := conf.downloadFile(transport, scheme.ID, "sk.pem")
	if err != nil { // If downloading of any of the private key fails just log it, and then continue
		Logger.Warnf("Downloading private key of scheme %s failed ", scheme.ID)
	}

	pkpath := fmt.Sprintf(pubkeyPattern, conf.Path, scheme.ID, "*")
	files, err := filepath.Glob(pkpath)
	if err != nil {
		return err
	}

	// For each public key, attempt to download a corresponding private key
	for _, file := range files {
		i := strings.LastIndex(pkpath, "PublicKeys")
		skpath := file[:i] + strings.Replace(file[i:], "PublicKeys", "PrivateKeys", 1)
		parts := strings.Split(skpath, "/")
		exists, err := common.PathExists(filepath.FromSlash(skpath))
		if exists || err != nil {
			continue
		}
		remote := strings.Join(parts[len(parts)-3:], "/")
		if err = conf.downloadFile(transport, scheme.ID, remote); err != nil {
			Logger.Warnf("Downloading private key %s failed: %s", skpath, err)
		}
	}

	return nil
}
