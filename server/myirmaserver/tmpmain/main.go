package main

import (
	"net/http"

	"github.com/privacybydesign/irmago/server/myirmaserver"
)

func main() {
	s, err := myirmaserver.New(&myirmaserver.Configuration{
		URL: "http://localhost:8080",
	})
	if err != nil {
		panic(err)
	}
	http.ListenAndServe("localhost:8080", s.Handler())
}
