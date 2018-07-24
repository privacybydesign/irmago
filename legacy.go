package irma

import (
	"encoding/json"
	"math/big"

	"github.com/go-errors/errors"
)

// Legacy from the protocol that will be updated in the future

// Because the Java version of the current version of the protocol misses a serializer for the Java-equivalent
// of the Java-equivalent of the IssuerIdentifier struct, these get serialized to an ugly map structure that we
// have to parse here.
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
