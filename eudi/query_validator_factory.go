package eudi

import (
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

type QueryValidatorFactory interface {
	CreateQueryValidator(rp *RelyingParty) dcql.QueryValidator
}

type DefaultQueryValidatorFactory struct{}

func (f *DefaultQueryValidatorFactory) CreateQueryValidator(rp *RelyingParty) dcql.QueryValidator {
	return &SchemeQueryValidator{
		RelyingParty: rp,
	}
}
