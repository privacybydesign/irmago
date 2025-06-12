package dcql

import (
	"github.com/privacybydesign/irmago/eudi/credentials"
)

type CredentialQueryHandler interface {
	// returns for which credential formats this handler can be used
	SupportsFormat(format credentials.CredentialFormat) bool

	// handles the given query and returns the result
	Handle(query CredentialQuery) (QueryResponse, error)
}

type VpTokenCreator func([]QueryResponse) (vpToken string, err error)

func QueryCredentials(query DcqlQuery, handlers []CredentialQueryHandler) (responses []QueryResponse, err error) {
	for _, cred := range query.Credentials {
		for _, handler := range handlers {
			if handler.SupportsFormat(cred.Format) {
				response, err := handler.Handle(cred)
				if err != nil {
					return []QueryResponse{}, err
				}
				responses = append(responses, response)
			}
		}
	}

	return responses, nil
}
