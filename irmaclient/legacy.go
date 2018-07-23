package irmaclient

import (
	"encoding/json"

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
