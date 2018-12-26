package irma

type SchemeManagerPointer struct {
	Url       string
	Publickey []byte
}

var DefaultSchemeManagers = [2]SchemeManagerPointer{
	{
		Url: "https://raw.githubusercontent.com/privacybydesign/irma-demo-schememanager/master",
		Publickey: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHVnmAY+kGkFZn7XXozdI4HY8GOjm
54ngh4chTfn6WsTCf2w5rprfIqML61z2VTE4k8yJ0Z1QbyW6cdaao8obTQ==
-----END PUBLIC KEY-----`),
	},
	{
		Url: "https://raw.githubusercontent.com/privacybydesign/pbdf-schememanager/master",
		Publickey: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELzHV5ipBimWpuZIDaQQd+KmNpNop
dpBeCqpDwf+Grrw9ReODb6nwlsPJ/c/gqLnc+Y3sKOAJ2bFGI+jHBSsglg==
-----END PUBLIC KEY-----`),
	},
}

func (conf *Configuration) DownloadDefaultSchemes() error {
	Logger.Info("downloading default schemes")
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
