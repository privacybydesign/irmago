package main

import (
	"net/http"

	"github.com/privacybydesign/irmago/server/myirmaserver"
)

func main() {
	db := &myirmaserver.MyirmaMemoryDB{
		UserData: map[string]myirmaserver.MemoryUserData{
			"rgBpfxdwfE": myirmaserver.MemoryUserData{
				ID: 1,
			},
		},
	}
	s, err := myirmaserver.New(&myirmaserver.Configuration{
		URL:                    "http://127.0.0.1:8080",
		StaticPath:             "irma_keyshare_webclient/build",
		StaticPrefix:           "/test/",
		DB:                     db,
		KeyshareAttributeNames: []string{"pbdf.sidn-pbdf.irma.pseudonym"},
	})
	if err != nil {
		panic(err)
	}
	http.ListenAndServe("localhost:8080", s.Handler())
}
