package irma

import (
	"encoding/json"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/irmago/internal/common"
)

// This file contains compatibility code for the legacy, pre-condiscon session requests,
// which supported only condis requests.
//
// Old requests can always be converted to new requests, and this is automatically done by the JSON
// unmarshaler when it encounters a legacy session request.
// New requests can be converted to old requests only if all inner conjunctions contain exactly
// 1 attribute. This can be done using the Legacy() method.
//
// Droppping compatibility with pre-condiscon session requests should thus be more or less:
// 1. delete this file
// 2. solve all compiler errors by removing the lines on which they occur
// 3. adjust the minimal supported protocol version in irmaclient and server

// LegacyDisjunction is a disjunction of attributes from before the condiscon feature,
// representing a list of attribute types one of which must be given by the user,
// possibly requiring specific values. (C.f. AttributeCon, also defined as []AttributeRequest,
// which is only satisfied if all listed attributes are given by the user.)
type LegacyDisjunction []AttributeRequest

type LegacyLabeledDisjunction struct {
	Label      string            `json:"label"`
	Attributes LegacyDisjunction `json:"attributes"`
}

type LegacyDisclosureRequest struct {
	BaseRequest
	Content []LegacyLabeledDisjunction `json:"content"`
}

func (dr *LegacyDisclosureRequest) Validate() error                 { panic("not implemented") }
func (dr *LegacyDisclosureRequest) Disclosure() *DisclosureRequest  { panic("not implemented") }
func (dr *LegacyDisclosureRequest) Identifiers() *IrmaIdentifierSet { panic("not implemented") }
func (dr *LegacyDisclosureRequest) Base() *BaseRequest              { return &dr.BaseRequest }
func (dr *LegacyDisclosureRequest) Action() Action                  { return ActionDisclosing }
func (dr *LegacyDisclosureRequest) Legacy() (SessionRequest, error) { return dr, nil }

type LegacySignatureRequest struct {
	LegacyDisclosureRequest
	Message string `json:"message"`
}

func (ir *LegacySignatureRequest) Action() Action { return ActionIssuing }

type LegacyIssuanceRequest struct {
	BaseRequest
	Credentials []*CredentialRequest       `json:"credentials"`
	Disclose    []LegacyLabeledDisjunction `json:"disclose"`
}

func (ir *LegacyIssuanceRequest) Validate() error                 { panic("not implemented") }
func (ir *LegacyIssuanceRequest) Disclosure() *DisclosureRequest  { panic("not implemented") }
func (ir *LegacyIssuanceRequest) Identifiers() *IrmaIdentifierSet { panic("not implemented") }
func (ir *LegacyIssuanceRequest) Base() *BaseRequest              { return &ir.BaseRequest }
func (ir *LegacyIssuanceRequest) Action() Action                  { return ActionIssuing }
func (ir *LegacyIssuanceRequest) Legacy() (SessionRequest, error) { return ir, nil }

func convertConDisCon(cdc AttributeConDisCon, labels map[int]TranslatedString) ([]LegacyLabeledDisjunction, error) {
	var disjunctions []LegacyLabeledDisjunction
	for i, dis := range cdc {
		l := LegacyLabeledDisjunction{}
		for _, con := range dis {
			if len(con) != 1 {
				return nil, errors.New("request not convertible to legacy request")
			}
			l.Attributes = append(l.Attributes, AttributeRequest{Type: con[0].Type, Value: con[0].Value})
		}
		l.Label = labels[i]["en"]
		if l.Label == "" {
			l.Label = l.Attributes[0].Type.Name()
		}
		disjunctions = append(disjunctions, l)
	}
	return disjunctions, nil
}

func convertDisjunctions(disjunctions []LegacyLabeledDisjunction) (
	condiscon AttributeConDisCon, labels map[int]TranslatedString,
) {
	labels = make(map[int]TranslatedString)
	condiscon = make(AttributeConDisCon, len(disjunctions))

	for i, dis := range disjunctions {
		condiscon[i] = AttributeDisCon{}
		for _, attr := range dis.Attributes {
			condiscon[i] = append(condiscon[i], AttributeCon{{Type: attr.Type, Value: attr.Value}})
		}
		labels[i] = TranslatedString{"en": dis.Label, "nl": dis.Label}
	}

	return
}

func checkType(typ, expected Action) error {
	if typ != expected {
		return errors.New("not a " + expected + " session request")
	}
	return nil
}

func (l *LegacyDisjunction) UnmarshalJSON(bts []byte) error {
	var err error
	var lst []AttributeTypeIdentifier
	if err = json.Unmarshal(bts, &lst); err == nil {
		for _, id := range lst {
			*l = append(*l, AttributeRequest{Type: id})
		}
		return nil
	}

	m := map[AttributeTypeIdentifier]*string{}
	if err = json.Unmarshal(bts, &m); err == nil {
		for id, val := range m {
			*l = append(*l, AttributeRequest{Type: id, Value: val})
		}
		return nil
	}

	return errors.New("Failed to unmarshal legacy attribute conjunction")
}

func (l *LegacyDisjunction) MarshalJSON() ([]byte, error) {
	hasvalues := false
	for _, r := range *l {
		if r.Value != nil {
			hasvalues = true
			break
		}
	}

	var tmp interface{}
	if hasvalues {
		m := map[AttributeTypeIdentifier]*string{}
		for _, r := range *l {
			m[r.Type] = r.Value
		}
		tmp = m
	} else {
		var m []AttributeTypeIdentifier
		for _, r := range *l {
			m = append(m, r.Type)
		}
		tmp = m
	}

	return json.Marshal(tmp)
}

func (dr *DisclosureRequest) Legacy() (SessionRequest, error) {
	disjunctions, err := convertConDisCon(dr.Disclose, dr.Labels)
	if err != nil {
		return nil, err
	}
	return &LegacyDisclosureRequest{
		BaseRequest: BaseRequest{
			Type:            ActionDisclosing,
			Context:         dr.Context,
			Nonce:           dr.Nonce,
			ProtocolVersion: dr.ProtocolVersion,
		},
		Content: disjunctions,
	}, nil
}

func (dr *DisclosureRequest) UnmarshalJSON(bts []byte) (err error) {
	var ldContext string
	if ldContext, err = common.ParseLDContext(bts); err != nil {
		return err
	}

	if ldContext != "" {
		type newDisclosureRequest DisclosureRequest // Same type with default JSON unmarshaler
		var req newDisclosureRequest
		if err = json.Unmarshal(bts, &req); err != nil {
			return err
		}
		*dr = DisclosureRequest(req)
		return nil
	}

	var legacy LegacyDisclosureRequest
	if err = json.Unmarshal(bts, &legacy); err != nil {
		return err
	}
	dr.BaseRequest = legacy.BaseRequest
	dr.legacy = true
	dr.LDContext = LDContextDisclosureRequest
	dr.Disclose, dr.Labels = convertDisjunctions(legacy.Content)

	return checkType(legacy.Type, ActionDisclosing)
}

func (sr *SignatureRequest) Legacy() (SessionRequest, error) {
	disjunctions, err := convertConDisCon(sr.Disclose, sr.Labels)
	if err != nil {
		return nil, err
	}
	return &LegacySignatureRequest{
		Message: sr.Message,
		LegacyDisclosureRequest: LegacyDisclosureRequest{
			BaseRequest: BaseRequest{
				Type:            ActionSigning,
				Context:         sr.Context,
				Nonce:           sr.Nonce,
				ProtocolVersion: sr.ProtocolVersion,
			},
			Content: disjunctions,
		},
	}, nil
}

func (sr *SignatureRequest) UnmarshalJSON(bts []byte) (err error) {
	var ldContext string
	if ldContext, err = common.ParseLDContext(bts); err != nil {
		return err
	}

	if ldContext != "" {
		var req struct { // Identical type with default JSON unmarshaler
			BaseRequest
			Disclose AttributeConDisCon       `json:"disclose"`
			Labels   map[int]TranslatedString `json:"labels"`
			Message  string                   `json:"message"`
		}
		if err = json.Unmarshal(bts, &req); err != nil {
			return err
		}
		*sr = SignatureRequest{
			DisclosureRequest{
				req.BaseRequest,
				req.Disclose,
				req.Labels,
			},
			req.Message,
		}
		return nil
	}

	var legacy LegacySignatureRequest
	if err = json.Unmarshal(bts, &legacy); err != nil {
		return err
	}
	sr.BaseRequest = legacy.BaseRequest
	sr.legacy = true
	sr.LDContext = LDContextSignatureRequest
	sr.Disclose, sr.Labels = convertDisjunctions(legacy.Content)
	sr.Message = legacy.Message

	return checkType(legacy.Type, ActionSigning)
}

func (ir *IssuanceRequest) Legacy() (SessionRequest, error) {
	disjunctions, err := convertConDisCon(ir.Disclose, ir.Labels)
	if err != nil {
		return nil, err
	}
	return &LegacyIssuanceRequest{
		BaseRequest: BaseRequest{
			Type:            ActionIssuing,
			Context:         ir.Context,
			Nonce:           ir.Nonce,
			ProtocolVersion: ir.ProtocolVersion,
		},
		Credentials: ir.Credentials,
		Disclose:    disjunctions,
	}, nil
}

func (ir *IssuanceRequest) UnmarshalJSON(bts []byte) (err error) {
	var ldContext string
	if ldContext, err = common.ParseLDContext(bts); err != nil {
		return err
	}

	if ldContext != "" {
		var req struct { // Identical type with default JSON unmarshaler
			BaseRequest
			Disclose    AttributeConDisCon       `json:"disclose"`
			Labels      map[int]TranslatedString `json:"labels"`
			Credentials []*CredentialRequest     `json:"credentials"`
		}
		if err = json.Unmarshal(bts, &req); err != nil {
			return err
		}
		*ir = IssuanceRequest{
			DisclosureRequest: DisclosureRequest{req.BaseRequest, req.Disclose, req.Labels},
			Credentials:       req.Credentials,
		}
		return nil
	}

	var legacy LegacyIssuanceRequest
	if err = json.Unmarshal(bts, &legacy); err != nil {
		return err
	}
	ir.BaseRequest = legacy.BaseRequest
	ir.legacy = true
	ir.LDContext = LDContextIssuanceRequest
	ir.Credentials = legacy.Credentials
	ir.Disclose, ir.Labels = convertDisjunctions(legacy.Disclose)

	return checkType(legacy.Type, ActionIssuing)
}

func (s *ServerSessionResponse) MarshalJSON() ([]byte, error) {
	if !s.ProtocolVersion.Below(2, 7) {
		type response ServerSessionResponse
		return json.Marshal((*response)(s))
	}

	if s.NextSession != nil {
		return nil, errors.New("cannot marshal next session pointer into legacy server session response")
	}

	if s.SessionType != ActionIssuing {
		return json.Marshal(s.ProofStatus)
	}
	return json.Marshal(s.IssueSignatures)
}

func (s *ServerSessionResponse) UnmarshalJSON(bts []byte) error {
	if !s.ProtocolVersion.Below(2, 7) {
		type response ServerSessionResponse
		return json.Unmarshal(bts, (*response)(s))
	}
	if s.SessionType != ActionIssuing {
		return json.Unmarshal(bts, &s.ProofStatus)
	}

	err := json.Unmarshal(bts, &s.IssueSignatures)
	if err != nil {
		return err
	}
	s.ProofStatus = ProofStatusValid
	return nil
}

type KeysharePublicKeyRegistry struct {
	PublicKeyRegistryJWT string `json:"jwt"`
}

type KeysharePublicKeyRegistryData struct {
	Username       string `json:"id"`
	Pin            string `json:"pin"`
	ECDSAPublicKey []byte `json:"ecdsa_publickey,omitempty"`
}

type KeysharePublicKeyRegistryClaims struct {
	jwt.RegisteredClaims
	KeysharePublicKeyRegistryData
}
