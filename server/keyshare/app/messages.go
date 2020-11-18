package app

import (
	"github.com/privacybydesign/gabi"
)

type keyshareEnrollment struct {
	Pin      string  `json:"pin"`
	Email    *string `json:"email"`
	Language string  `json:"language"`
}

type keyshareChangePin struct {
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
