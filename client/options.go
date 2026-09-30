package client

import (
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc/zk"
)

// ============================================================
// CONSTRUCTION OPTIONS
// ============================================================
//
// New takes the arguments every wallet needs. An Option carries the ones only
// some builds have — capabilities that arrive from outside irmago, where the
// alternative is a parameter that is nil in almost every caller.
//
// The zero options case is a complete wallet. Nothing here is required.

// Option configures a Client at construction. Applied in order, after the
// client is otherwise built, so an option can read what New assembled.
type Option func(*Client)

// WithZkProver registers a zero-knowledge proof system for the wallet to use
// when a reader asks for one.
//
// This is the seam the native prover arrives through, and the reason the whole
// zk package exists. irmago cannot implement a ZK system itself — the only one
// in scope is a C++ library, and irmago deliberately does not compile C++ — so
// the implementation lives in a module of its own and the application wires the
// two together:
//
//	client.New(..., client.WithZkProver(longfellow.OpenDir(circuitDir)))
//
// The parameter is zk.System, irmago's own stdlib-only interface, never a type
// from the prover's module. That is what lets a build with no prover link
// nothing extra, and what keeps the dependency pointing one way: the prover
// module imports irmago, irmago never imports it.
//
// Passing no prover is not a degraded wallet, it is the ordinary one. AV Annex A
// §A.8 requires that "where the User's device does not support Zero-Knowledge
// Proof generation, the AVI SHALL fall back to the plain ISO mDoc presentation
// defined in Section A.6", so a session with no system registered takes the
// fallback rather than failing — see isomdoc.Session. It becomes a refusal only
// against a reader that set zkRequired, which is that reader's choice.
//
// Repeatable: each call adds a system, so a build can carry more than one. They
// are consulted in registration order.
func WithZkProver(system zk.System) Option {
	return func(client *Client) {
		if system == nil {
			return
		}
		if client.zkSystems == nil {
			client.zkSystems = mdoc.NewZkSystemRepository()
		}
		// Wrapped here rather than by the caller: ProverSystem is the adapter
		// between the byte-oriented boundary and this package's domain types, and
		// an application has no reason to know it exists.
		client.zkSystems.Add(mdoc.NewProverSystem(system))
	}
}
