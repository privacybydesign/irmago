package irmaserver

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmarequestor"
)

type Configuration struct {
	*server.Configuration
	Port int
}

var s *http.Server

// Start the server. If successful then it will not return until Stop() is called.
func Start(conf *Configuration) error {
	handler, err := Handler(conf.Configuration)
	if err != nil {
		return err
	}

	// Start server
	s = &http.Server{Addr: fmt.Sprintf(":%d", conf.Port), Handler: handler}
	err = s.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil // Server was closed normally
	}

	return err
}

func Stop() {
	s.Close()
}

func Handler(conf *server.Configuration) (http.Handler, error) {
	if err := irmarequestor.Initialize(conf); err != nil {
		return nil, err
	}

	router := chi.NewRouter()

	// Mount server for irmaclient
	router.Mount("/irma/", irmarequestor.HttpHandlerFunc("/irma/"))

	// Server routes
	router.Post("/create", handleCreate)
	router.Get("/status/{token}", handleStatus)
	router.Get("/result/{token}", handleResult)

	return router, nil
}

func handleCreate(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	request, err := parseRequest(body)
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	qr, _, err := irmarequestor.StartSession(request, nil)
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	server.WriteJson(w, qr)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	res := irmarequestor.GetSessionResult(chi.URLParam(r, "token"))
	if res == nil {
		server.WriteError(w, server.ErrorSessionUnknown, "")
		return
	}
	server.WriteJson(w, res.Status)
}

func handleResult(w http.ResponseWriter, r *http.Request) {
	res := irmarequestor.GetSessionResult(chi.URLParam(r, "token"))
	if res == nil {
		server.WriteError(w, server.ErrorSessionUnknown, "")
		return
	}
	server.WriteJson(w, res)
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
