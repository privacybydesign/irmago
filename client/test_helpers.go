package client

import "github.com/privacybydesign/irmago/eudi/storage"

// EudiStorageForTesting exposes the client's EUDI storage to tests in other
// packages, for the two things the app-facing API deliberately cannot do:
// inspect what issuance actually wrote, and put the wallet in a state no issuer
// will hand out on demand.
//
// Both are load-bearing for the mso_mdoc integration tests:
//
//   - Reading back a batch after real issuance is the only way to assert the
//     properties a single presentation cannot show — that every instance carries
//     its own device key (one key reused across a batch would correlate the very
//     presentations the batch exists to separate), and that a presentation spends
//     exactly one instance. Nothing on the client surfaces per-instance keys, and
//     nothing should.
//   - Seeding reaches the states worth testing that an issuer will not produce:
//     an expired credential, a batch with every instance spent, and one signed by
//     an issuer the verifier does not trust. The mdoc AV disclosure tests also
//     need the issuing IACA in hand so it can be given to the verifier as a trust
//     anchor, which a container-issued credential cannot provide.
//
// Everything downstream of either — DCQL matching, the disclosure plan, device
// signing, the response the verifier checks — runs exactly as in production.
//
// (An earlier version of this comment justified the helper by claiming no
// container issues mdoc credentials. That stopped being true on 2026-08-10:
// TestSessionHandler/openid4vci/mdoc/eudi-pid-python issues real mdocs from the
// EUDI Python PID issuer.)
//
// Kept in a non-test file because Go only exports test helpers to other packages
// that way. It is not part of the app-facing API and cannot become one by
// accident: gomobile binds yivi_core/irmagobridge, not this package, and a method
// returning an interface from another package is not bindable regardless.
func (client *Client) EudiStorageForTesting() storage.Storage {
	return client.eudiStorage
}
