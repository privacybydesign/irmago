package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irmaserver"
	"github.com/privacybydesign/irmago/irmaserver/irmarequestor"
)

var server *http.Server

func Start(port int, conf *irmaserver.Configuration) error {
	mux := http.NewServeMux()
	if err := irmarequestor.Initialize(conf); err != nil {
		return err
	}

	mux.HandleFunc("/irma/", irmarequestor.HttpHandlerFunc("/irma/"))

	mux.HandleFunc("/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, irmaserver.ErrorInvalidRequest, "")
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeError(w, irmaserver.ErrorInvalidRequest, err.Error())
			return
		}
		request, err := parseRequest(body)
		if err != nil {
			writeError(w, irmaserver.ErrorInvalidRequest, err.Error())
			return
		}

		qr, _, err := irmarequestor.StartSession(request, nil)
		if err != nil {
			writeError(w, irmaserver.ErrorInvalidRequest, err.Error())
			return
		}

		b, _ := json.Marshal(qr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	})

	mux.HandleFunc("/status/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, irmaserver.ErrorInvalidRequest, "")
			return
		}
		token := r.URL.Path[len("/status/"):]
		res := irmarequestor.GetSessionResult(token)
		if res == nil {
			writeError(w, irmaserver.ErrorSessionUnknown, "")
			return
		}
		b, _ := json.Marshal(res.Status)
		w.Write(b)
	})

	mux.HandleFunc("/result/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, irmaserver.ErrorInvalidRequest, "")
			return
		}
		token := r.URL.Path[len("/result/"):]
		res := irmarequestor.GetSessionResult(token)
		if res == nil {
			writeError(w, irmaserver.ErrorInvalidRequest, "")
			return
		}
		b, _ := json.Marshal(res)
		w.Write(b)
	})

	server = &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
	server.ListenAndServe()
	return nil
}

func Stop() {
	server.Close()
}

func writeError(w http.ResponseWriter, err irmaserver.Error, msg string) {
	status, bts := irmaserver.JsonResponse(nil, irmaserver.RemoteError(err, msg))
	w.WriteHeader(status)
	w.Write(bts)
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
