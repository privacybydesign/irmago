// Package walletconfig holds the wallet configuration: one signed document per
// environment that says who Yivi vouches for on the OpenID4VC side, how much,
// and under what policy. It is the only trust format the client parses — any
// other list (ETSI LoTE, LOTL) is converted into it server-side.
//
// The package covers the document's lifecycle in the wallet and nothing else:
//
//   - [Config] is the payload and knows how to validate itself. Unknown fields
//     are ignored on parse, so a minor schema bump is not an app release.
//   - [Verify] checks a signed document against exactly one root — the root of
//     the [Environment] it is claimed for. Nothing that chains to an issuer or
//     verifier anchor can sign a config: those pools are never consulted here.
//   - [Manager] holds the current verified config, loads it from the copy bundled
//     with the release or the one persisted from an earlier fetch, refreshes it
//     in the background, refuses rollbacks, and switches environments atomically.
//     Sessions read [Manager.Snapshot], which never touches the network.
//
// What a config means for a session — matching parties to entities, computing
// effective trust levels, enforcing the policy — lives with the consumers of a
// Snapshot, not here.
//
// Everything on the read path is fail-soft. A config that will not fetch, will
// not verify or rolls back leaves the one already held in force; freshness
// (fresh, stale, expired) is reported on the snapshot for consumers to act on.
package walletconfig
