package lote

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/privacybydesign/irmago/eudi/jades"
)

// Sign produces a signed LoTE, and is the counterpart of VerifySigned.
//
// It enforces the rules about binding this certificate to this document at this
// moment — clause 6.8.0 and clause 6.6.5 — and not document conformance, which
// belongs to ValidateDocument and to `yivi eudi lote build`. A document reaching
// here is assumed built and validated.
func Sign(
	document Document,
	chain []*x509.Certificate,
	key crypto.Signer,
	signedAt time.Time,
) (Signed, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("no signing certificate given")
	}

	if err := CheckSigningCertificate(chain[0], document.LoTE.SchemeInformation); err != nil {
		return nil, err
	}
	if err := checkSigningTime(document.LoTE.SchemeInformation, signedAt); err != nil {
		return nil, err
	}

	payload, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}

	return jades.SignBaselineB(payload, jades.SignOptions{
		Typ:      LoteTyp,
		Chain:    chain,
		Key:      key,
		SignedAt: signedAt,
	})
}

// CheckSigningCertificate enforces clause 6.8.0 plus the key usage the wallet
// checks, binding a certificate to the scheme whose list it signs.
//
// Enforcing it on read would be pointless — a forger writes the document, so it
// names its own certificate — which makes signing time the only place a mismatch
// can be caught.
func CheckSigningCertificate(leaf *x509.Certificate, scheme SchemeInformation) error {
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("signing certificate does not carry the digitalSignature key usage")
	}

	if scheme.SchemeTerritory == "" {
		return fmt.Errorf("the document declares no SchemeTerritory, so the certificate's country cannot be checked")
	}
	if !slices.Contains(leaf.Subject.Country, scheme.SchemeTerritory) {
		return fmt.Errorf(
			"clause 6.8.0: certificate subject country %v does not include the scheme territory %q",
			leaf.Subject.Country, scheme.SchemeTerritory)
	}

	operatorNames := slices.Collect(maps.Values(scheme.SchemeOperatorName))
	if len(operatorNames) == 0 {
		return fmt.Errorf("the document declares no SchemeOperatorName, so the certificate's organization cannot be checked")
	}
	for _, organization := range leaf.Subject.Organization {
		if slices.Contains(operatorNames, organization) {
			return nil
		}
	}
	return fmt.Errorf(
		"clause 6.8.0: certificate subject organization %v is not one of the scheme operator names %v",
		leaf.Subject.Organization, operatorNames)
}

// checkSigningTime enforces clause 6.6.5, which asks the scheme operator to keep
// the issue date and the moment of signing consistent.
//
// The clause states no tolerance, so both bounds come from the document rather than
// a constant: signing before its issue date means it is dated in the future,
// signing past NextUpdate means publishing what the wallet refuses on arrival. A
// document issued long ago but still inside its window passes.
func checkSigningTime(scheme SchemeInformation, signedAt time.Time) error {
	if scheme.ListIssueDateTime.IsZero() || scheme.NextUpdate.IsZero() {
		return fmt.Errorf("the document is missing ListIssueDateTime or NextUpdate, so clause " +
			"6.6.5 consistency cannot be checked")
	}

	if signedAt.Before(scheme.ListIssueDateTime.Add(-ClockSkew)) {
		return fmt.Errorf(
			"clause 6.6.5: signing at %s a document issued at %s, which is dated in the future",
			signedAt.UTC().Format(time.RFC3339), scheme.ListIssueDateTime.UTC().Format(time.RFC3339))
	}
	if !signedAt.Before(scheme.NextUpdate) {
		return fmt.Errorf(
			"clause 6.6.5: signing at %s a document whose next_update was %s, so it is already expired",
			signedAt.UTC().Format(time.RFC3339), scheme.NextUpdate.UTC().Format(time.RFC3339))
	}
	return nil
}
