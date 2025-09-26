package eudi

import (
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/scheme"
)

type MockQueryValidatorFactory struct {
	failsQueryValidation bool
}

type MockQueryValidator struct {
	failsValidation bool
}

func (f *MockQueryValidatorFactory) CreateQueryValidator(rp *scheme.RelyingParty) dcql.QueryValidator {
	return &MockQueryValidator{
		failsValidation: f.failsQueryValidation,
	}
}

func (m *MockQueryValidator) ValidateQuery(query *dcql.DcqlQuery) error {
	if m.failsValidation {
		return errors.New("query validation failed")
	}
	return nil
}
