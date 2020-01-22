package main

import (
	"net/http"

	"github.com/privacybydesign/irmago/keyshareServerCore"
)

func main() {
	s, err := keyshareServerCore.New(&keyshareServerCore.Configuration{
		SchemesPath:           "schemes/",
		URL:                   "http://10.0.2.2:8080/",
		DbType:                keyshareServerCore.DatabaseTypePostgres,
		DbConnstring:          "postgresql://localhost:5432/test",
		JwtKeyId:              0,
		JwtPrivateKeyFile:     "schemes/test/kss-0.private.pem",
		StoragePrimaryKeyFile: "storagekey",
		KeyshareCredential:    "test.test.mijnirma",
		KeyshareAttribute:     "email",
	})

	if err != nil {
		panic(err)
	}

	http.Handle("/", s.Handler())
	panic(http.ListenAndServe(":8080", nil))
}
