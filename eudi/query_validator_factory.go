package eudi

import (
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/scheme"
)

type QueryValidatorFactory interface {
	CreateQueryValidator(rp *scheme.RelyingParty) dcql.QueryValidator
}

type DefaultQueryValidatorFactory struct{}

func (f *DefaultQueryValidatorFactory) CreateQueryValidator(rp *scheme.RelyingParty) dcql.QueryValidator {
	return &scheme.SchemeQueryValidator{
		RelyingParty: rp,
	}
}
