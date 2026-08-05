package vcdmsdjwt

import (
	"fmt"
	"slices"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// CheckKeyBindingConfirmationUniqueness verifies that no two credentials in a
// batch share a `cnf` holder binding key. Per draft-ietf-oauth-status-list
// §13.2-style unlinkability, every one-time-use copy in a batch must be bound
// to its own key so presentations cannot be correlated. Mirrors
// sdjwtvc.CheckKeyBindingConfirmationUniqueness for the VCDM data model.
func CheckKeyBindingConfirmationUniqueness(verified []*VerifiedSdJwtVcdm) error {
	for _, v := range verified {
		cnf := v.RegisteredClaims.Confirm
		if cnf == nil {
			continue
		}

		duplicate := slices.ContainsFunc(verified, func(other *VerifiedSdJwtVcdm) bool {
			otherCnf := other.RegisteredClaims.Confirm
			return other != v && otherCnf != nil &&
				((cnf.Jwk != nil && otherCnf.Jwk != nil && jwk.Equal(*otherCnf.Jwk, *cnf.Jwk)) ||
					(cnf.Kid != nil && otherCnf.Kid != nil && *otherCnf.Kid == *cnf.Kid))
		})

		if duplicate {
			return fmt.Errorf(
				"duplicate cryptographic key binding confirmation found for SD-JWT-secured VCDM credential of type %q",
				v.Document.TypeIdentity(),
			)
		}
	}

	return nil
}
