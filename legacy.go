package irmago

import (
	"encoding/json"
	"math/big"

	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

// Legacy from the old Android app, and from the protocol that will be updated
// in the future

func (pki *publicKeyIdentifier) MarshalJSON() ([]byte, error) {
	temp := struct {
		Issuer  map[string]string `json:"issuer"`
		Counter uint              `json:"counter"`
	}{
		Issuer:  map[string]string{"identifier": pki.Issuer},
		Counter: pki.Counter,
	}
	return json.Marshal(temp)
}

func (comms *proofPCommitmentMap) UnmarshalJSON(bytes []byte) error {
	comms.Commitments = map[publicKeyIdentifier]*gabi.ProofPCommitment{}
	temp := struct {
		C [][]*json.RawMessage `json:"c"`
	}{}
	if err := json.Unmarshal(bytes, &temp); err != nil {
		return err
	}
	for _, raw := range temp.C {
		tempPkID := struct {
			Issuer struct {
				Identifier string `json:"identifier"`
			} `json:"issuer"`
			Counter uint `json:"counter"`
		}{}
		comm := gabi.ProofPCommitment{}
		if err := json.Unmarshal([]byte(*raw[0]), &tempPkID); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(*raw[1]), &comm); err != nil {
			return err
		}
		pkid := publicKeyIdentifier{Issuer: tempPkID.Issuer.Identifier, Counter: tempPkID.Counter}
		comms.Commitments[pkid] = &comm
	}
	return nil
}

func (si *SessionInfo) UnmarshalJSON(b []byte) error {
	temp := &struct {
		Jwt     string          `json:"jwt"`
		Nonce   *big.Int        `json:"nonce"`
		Context *big.Int        `json:"context"`
		Keys    [][]interface{} `json:"keys"`
	}{}
	err := json.Unmarshal(b, temp)
	if err != nil {
		return err
	}

	si.Jwt = temp.Jwt
	si.Nonce = temp.Nonce
	si.Context = temp.Context
	si.Keys = make(map[IssuerIdentifier]int, len(temp.Keys))
	for _, item := range temp.Keys {
		var idmap map[string]interface{}
		var idstr string
		var counter float64
		var ok bool
		if idmap, ok = item[0].(map[string]interface{}); !ok {
			return errors.New("Failed to deserialize session info")
		}
		if idstr, ok = idmap["identifier"].(string); !ok {
			return errors.New("Failed to deserialize session info")
		}
		if counter, ok = item[1].(float64); !ok {
			return errors.New("Failed to deserialize session info")
		}
		id := NewIssuerIdentifier(idstr)
		si.Keys[id] = int(counter)
	}
	return nil
}

const (
	androidLogVerificationType = "verification"
	androidLogIssueType        = "issue"
	androidLogSignatureType    = "signature"
	androidLogRemoveType       = "remove"

	androidLogTimeFormat = "January 2, 2006 3:04:05 PM MST -07:00"
)

type androidLogEnvelope struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

func (env *androidLogEnvelope) Parse() (interface{}, error) {
	switch env.Type {
	case androidLogVerificationType:
		val := &androidLogVerification{}
		return val, json.Unmarshal(env.Value, val)
	case androidLogIssueType:
		val := &androidLogIssuance{}
		return val, json.Unmarshal(env.Value, val)
	case androidLogSignatureType:
		val := &androidLogSignature{}
		return val, json.Unmarshal(env.Value, val)
	case androidLogRemoveType:
		val := &androidLogRemoval{}
		return val, json.Unmarshal(env.Value, val)
	default:
		return nil, errors.New("Invalid Android log type")
	}
}

type androidLogEntry struct {
	Time       string `json:"timestamp"`
	Credential struct {
		Identifier CredentialTypeIdentifier `json:"identifier"`
	} `json:"credential"`
}

func (entry *androidLogEntry) GetTime() Timestamp {
	// An example date directly from cardemu.xml: September 29, 2017 11:12:57 AM GMT+02:00
	// Unfortunately, the seemingly appropriate format parameter for time.Parse, with
	// "MST-07:00" at the end, makes time.Parse emit an error: "GMT+02" gets to be
	// interpreted as the timezone, i.e. as MST, and then nothing gets mapped onto "-07".
	// So, we put a space between "GMT" and "+02:00".
	fixed := strings.Replace(entry.Time, "+", " +", 1)
	parsed, _ := time.Parse(androidLogTimeFormat, fixed)
	return Timestamp(parsed)
}

type androidLogIssuance struct {
	androidLogEntry
}

type androidLogRemoval struct {
	androidLogEntry
}

type androidLogVerification struct {
	androidLogEntry
	Disclosed map[string]bool `json:"attributeDisclosed"`
}

type androidLogSignature struct {
	androidLogVerification
	Message string `json:"message"`
}

// TODO remove on protocol upgrade
type logSessionInfo struct {
	Jwt     string         `json:"jwt"`
	Nonce   *big.Int       `json:"nonce"`
	Context *big.Int       `json:"context"`
	Keys    map[string]int `json:"keys"`
}

// TODO remove on protocol upgrade
func (entry *LogEntry) MarshalJSON() ([]byte, error) {
	resp := entry.raw
	if len(resp) == 0 {
		if bytes, err := json.Marshal(entry.Response); err == nil {
			resp = json.RawMessage(bytes)
		} else {
			return nil, err
		}
	}

	temp := &jsonLogEntry{
		Type:     entry.Type,
		Time:     entry.Time,
		Response: resp,
		SessionInfo: &logSessionInfo{
			Jwt:     entry.SessionInfo.Jwt,
			Nonce:   entry.SessionInfo.Nonce,
			Context: entry.SessionInfo.Context,
			Keys:    make(map[string]int),
		},
	}

	for iss, count := range entry.SessionInfo.Keys {
		temp.SessionInfo.Keys[iss.String()] = count
	}

	return json.Marshal(temp)
}
