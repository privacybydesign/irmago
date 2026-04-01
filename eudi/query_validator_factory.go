package eudi

import (
	"github.com/privacybydesign/irmago/eudi/scheme"
)

// QueryValidatorFactory creates validators for DCQL queries based on the relying party.
type QueryValidatorFactory interface {
	CreateQueryValidator(rp *scheme.RelyingParty) QueryValidator
}

// QueryValidator validates credential queries against a relying party's authorization.
type QueryValidator interface {
	ValidateCredentialQueries(queries []scheme.CredentialQueryInfo) error
}

type DefaultQueryValidatorFactory struct{}

func (f *DefaultQueryValidatorFactory) CreateQueryValidator(rp *scheme.RelyingParty) QueryValidator {
	return &scheme.SchemeQueryValidator{
		RelyingParty: rp,
	}
}
