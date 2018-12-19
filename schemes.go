package irma

type SchemeManagerPointer struct {
	Url       string
	Publickey []byte
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
	for _, s := range DefaultSchemeManagers {
		scheme, err := DownloadSchemeManager(s.Url)
		if err != nil {
			return err
		}
		if err := conf.InstallSchemeManager(scheme, s.Publickey); err != nil {
			return err
		}
	}
	return nil
}
