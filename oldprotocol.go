package irmago

import (
	"encoding/json"
	"math/big"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

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
