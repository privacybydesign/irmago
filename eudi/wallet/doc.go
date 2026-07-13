// Package wallet is a standalone, headless proof-of-concept SD-JWT VC wallet
// client for the EUDI (European Digital Identity) spectrum.
//
// Unlike the top-level client package — which is a unified IRMA + EUDI wallet
// bound to the keyshare protocol, a bbolt store and a mobile UI callback model —
// this package wires together ONLY the eudi/* libraries and exposes a small,
// synchronous API that runs the full SD-JWT VC lifecycle:
//
//   - Receive: obtain a credential over OpenID4VCI (pre-authorized and
//     authorization code grants) and store it encrypted at rest (SQLCipher).
//   - Present: disclose a credential over OpenID4VP (direct_post and
//     direct_post.jwt response modes).
//   - Credentials / Logs / Reset: inspect and manage stored state.
//
// The wallet is driven by a Policy that decides, headlessly, whether to accept
// an issuance offer and which claims to disclose. This replaces the interactive
// permission prompts of the mobile app so the flows can run from a CLI or a
// test.
//
// See docs/poc-sdjwtvc-wallet-design.md for the design and its known
// limitations (deferred issuance, DPoP, did:jwk KB-JWT verification, revocation,
// mdoc/W3C VC, etc.), all of which are inherited from the underlying eudi/*
// packages and out of scope for the POC.
package wallet
