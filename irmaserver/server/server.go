package server

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irmaserver"
	"github.com/privacybydesign/irmago/irmaserver/irmarequestor"
)

var server *http.Server

func Start(port int, conf *irmaserver.Configuration) error {
	if err := irmarequestor.Initialize(conf); err != nil {
		return err
	}

	router := chi.NewRouter()

	// Mount server for irmaclient
	router.Mount("/irma/", irmarequestor.HttpHandlerFunc("/irma/"))

	// Server routes
	router.Post("/create", handleCreate)
	router.Get("/status/{token}", handleStatus)
	router.Get("/result/{token}", handleResult)

	// Start server
	server = &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: router}
	server.ListenAndServe()
	return nil
}

func Stop() {
	server.Close()
}

func handleCreate(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		irmaserver.WriteError(w, irmaserver.ErrorInvalidRequest, err.Error())
		return
	}
	request, err := parseRequest(body)
	if err != nil {
		irmaserver.WriteError(w, irmaserver.ErrorInvalidRequest, err.Error())
		return
	}

	qr, _, err := irmarequestor.StartSession(request, nil)
	if err != nil {
		irmaserver.WriteError(w, irmaserver.ErrorInvalidRequest, err.Error())
		return
	}

	irmaserver.WriteJson(w, qr)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	res := irmarequestor.GetSessionResult(chi.URLParam(r, "token"))
	if res == nil {
		irmaserver.WriteError(w, irmaserver.ErrorSessionUnknown, "")
		return
	}
	irmaserver.WriteJson(w, res.Status)
}

func handleResult(w http.ResponseWriter, r *http.Request) {
	res := irmarequestor.GetSessionResult(chi.URLParam(r, "token"))
	if res == nil {
		irmaserver.WriteError(w, irmaserver.ErrorSessionUnknown, "")
		return
	}
	irmaserver.WriteJson(w, res)
}

func parseRequest(bts []byte) (request irma.SessionRequest, err error) {
	request = &irma.DisclosureRequest{}
	if err = irma.UnmarshalValidate(bts, request); err == nil {
		return request, nil
	}
	request = &irma.SignatureRequest{}
	if err = irma.UnmarshalValidate(bts, request); err == nil {
		return request, nil
	}
	request = &irma.IssuanceRequest{}
	if err = irma.UnmarshalValidate(bts, request); err == nil {
		return request, nil
	}
	return nil, errors.New("Invalid session type")
}
