package irma

import (
	"encoding/json"

	"github.com/go-errors/errors"
)

type legacyAttributeDisjunction []AttributeRequest

type attributeDisjunction struct {
	Label      string
	Attributes legacyAttributeDisjunction
}

type legacyDisclosureRequest struct {
	BaseRequest
	Content []attributeDisjunction `json:"content"`
}

func convertDisjunctions(disjunctions []attributeDisjunction) (
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

func parseVersion(bts []byte) (int, error) {
	var v struct {
		Version int `json:"v"`
	}
	if err := json.Unmarshal(bts, &v); err != nil {
		return 0, err
	}
	return v.Version, nil
}

func checkType(typ, expected Action) error {
	if typ != expected {
		return errors.New("not a " + expected + " session request")
	}
	return nil
}

// Reuses AttributeCon.UnmarshalJSON()
func (l *legacyAttributeDisjunction) UnmarshalJSON(bts []byte) error {
	var con AttributeCon
	if err := json.Unmarshal(bts, &con); err != nil {
		return err
	}
	*l = legacyAttributeDisjunction(con)
	return nil
}

func (dr *DisclosureRequest) UnmarshalJSON(bts []byte) (err error) {
	var version int
	if version, err = parseVersion(bts); err != nil {
		return err
	}

	if version >= 2 {
		type newDisclosureRequest DisclosureRequest // Same type with default JSON unmarshaler
		var req newDisclosureRequest
		if err = json.Unmarshal(bts, &req); err != nil {
			return err
		}
		*dr = DisclosureRequest(req)
		return nil
	}

	var legacy legacyDisclosureRequest
	if err = json.Unmarshal(bts, &legacy); err != nil {
		return err
	}
	dr.BaseRequest = legacy.BaseRequest
	dr.Version = 2
	dr.Disclose, dr.Labels = convertDisjunctions(legacy.Content)

	return checkType(legacy.Type, ActionDisclosing)
}

func (sr *SignatureRequest) UnmarshalJSON(bts []byte) (err error) {
	var version int
	if version, err = parseVersion(bts); err != nil {
		return err
	}

	if version >= 2 {
		var req struct { // Identical type with default JSON unmarshaler
			BaseRequest
			Disclose AttributeConDisCon       `json:"disclose"`
			Labels   map[int]TranslatedString `json:"labels"`
			Message  string                   `json"string"`
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

	var legacy struct {
		legacyDisclosureRequest
		Message string `json:"message"`
	}
	if err = json.Unmarshal(bts, &legacy); err != nil {
		return err
	}
	sr.BaseRequest = legacy.BaseRequest
	sr.Version = 2
	sr.Disclose, sr.Labels = convertDisjunctions(legacy.Content)
	sr.Message = legacy.Message

	return checkType(legacy.Type, ActionSigning)
}

func (ir *IssuanceRequest) UnmarshalJSON(bts []byte) (err error) {
	var version int
	if version, err = parseVersion(bts); err != nil {
		return err
	}

	if version >= 2 {
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

	var legacy struct {
		BaseRequest
		Credentials []*CredentialRequest   `json:"credentials"`
		Disclose    []attributeDisjunction `json:"disclose"`
	}
	if err = json.Unmarshal(bts, &legacy); err != nil {
		return err
	}
	ir.BaseRequest = legacy.BaseRequest
	ir.Version = 2
	ir.Credentials = legacy.Credentials
	ir.Disclose, ir.Labels = convertDisjunctions(legacy.Disclose)

	return checkType(legacy.Type, ActionIssuing)
}
