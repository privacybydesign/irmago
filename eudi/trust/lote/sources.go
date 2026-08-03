package lote

// ProductionSources is the compiled-in set of recognized lists — the lists a
// released wallet consults, alongside the pinned trust anchors in
// eudi/trustanchors.go.
//
// It is empty: Yivi does not publish its LoTE yet, and pointing released
// wallets at a URL that does not resolve would mean a failed download on every
// refresh for no gain. Until the endpoint exists the recognized-list channel
// contributes nothing in production and every party is ranked by the
// certificate channel alone, which is what the wallet does today.
//
// Fill this in when the list is published; nothing else has to change.
var ProductionSources = []Source{}
