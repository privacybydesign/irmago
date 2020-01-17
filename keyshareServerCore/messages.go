package keyshareServerCore

import (
	"github.com/privacybydesign/gabi"
)

type keyshareEnrollment struct {
	Username string  `json:"username"`
	Pin      string  `json:"pin"`
	Email    *string `json:"email"`
	Language string  `json:"language"`
}

type keyshareChangepin struct {
	Username string `json:"id"`
	OldPin   string `json:"oldpin"`
	NewPin   string `json:"newpin"`
}

type keyshareAuthorization struct {
	Status     string   `json:"status"`
	Candidates []string `json:"candidates"`
}

type keysharePinMessage struct {
	Username string `json:"id"`
	Pin      string `json:"pin"`
}

type keysharePinStatus struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type proofPCommitmentMap struct {
	Commitments map[string]*gabi.ProofPCommitment `json:"c"`
}
