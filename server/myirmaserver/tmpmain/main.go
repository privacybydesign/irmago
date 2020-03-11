package main

import (
	"net/http"

	"github.com/privacybydesign/irmago/server/myirmaserver"
)

func main() {
	db := &myirmaserver.MyirmaMemoryDB{
		UserData: map[string]myirmaserver.MemoryUserData{
			"rgBpfxdwfE": myirmaserver.MemoryUserData{
				ID:    1,
				Email: []string{"test@test.com"},
			},
			"blabla": myirmaserver.MemoryUserData{
				ID:    2,
				Email: []string{"test@test.com", "test2@test.com"},
			},
		},
		LoginEmailTokens: map[string]string{},
	}
	s, err := myirmaserver.New(&myirmaserver.Configuration{
		URL:                    "http://127.0.0.1:8080",
		StaticPath:             "irma_keyshare_webclient/build",
		StaticPrefix:           "/test/",
		DB:                     db,
		KeyshareAttributeNames: []string{"pbdf.sidn-pbdf.irma.pseudonym"},
		EmailServer:            "localhost:1025",
		EmailFrom:              "test@example.com",
		DefaultLanguage:        "en",
		LoginEmailFiles:        map[string]string{"en": "testtemplate.html"},
		LoginEmailSubject:      map[string]string{"en": "Login MyIRMA"},
		LoginEmailBaseURL:      map[string]string{"en": "http://127.0.0.1:8080/test/#token="},
	})
	if err != nil {
		panic(err)
	}
	http.ListenAndServe("localhost:8080", s.Handler())
}
