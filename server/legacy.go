package server

import (
	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
)

func parseLegacySessionRequest(r []byte) (irma.RequestorRequest, error) {
	var attempts = []irma.Validator{&irma.ServiceProviderRequest{}, &irma.SignatureRequestorRequest{}, &irma.IdentityProviderRequest{}}
	t, err := tryUnmarshalJson(r, attempts)
	if err == nil {
		return t.(irma.RequestorRequest), nil
	}
	attempts = []irma.Validator{&irma.DisclosureRequest{}, &irma.SignatureRequest{}, &irma.IssuanceRequest{}}
	t, err = tryUnmarshalJson(r, attempts)
	if err == nil {
		return wrapSessionRequest(t.(irma.SessionRequest))
	}
	return nil, errors.New("Failed to JSON unmarshal request bytes")
}

func tryUnmarshalJson(bts []byte, attempts []irma.Validator) (irma.Validator, error) {
	for _, a := range attempts {
		if err := irma.UnmarshalValidate(bts, a); err == nil {
			return a, nil
		}
	}
	return nil, errors.New("")
}
