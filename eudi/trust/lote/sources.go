package lote

// RecognizedSources is the set of recognized lists this build consults — the
// compiled-in trust decision, alongside the pinned anchors in
// eudi/trustanchors.go. Only a release can change who is allowed to vouch for a
// party.
//
// It is empty: Yivi does not publish its LoTE yet, and pointing released wallets
// at a URL that does not resolve would mean a failed download on every refresh
// for no gain. Until the endpoint exists the recognized-list channel contributes
// nothing and every party is ranked by the certificate channel alone, which is
// what the wallet does today.
//
// Fill this in when the list is published; nothing else has to change.
//
// A wallet that must consult a different set — an integration test serving a list
// it controls, or a staging build — names it in client.Config.RecognizedTrustLists
// rather than assigning here, so what a wallet consults is fixed by the call that
// built it.
var RecognizedSources = []Source{}
