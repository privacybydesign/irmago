// Package integrationtest composes the whole org-iso-mdoc path — ISO/IEC TS
// 18013-7 Annex C — against the wallet's real storage, and holds nothing but
// tests.
//
// # Why it exists
//
// Every layer of that path already passes its own tests with the layer below it
// faked: isomdoc.Session against a fake Discloser, isomdoc.WalletDiscloser
// against a fake DCQL handler and a fake store, client.isoMdocSession against no
// discloser at all. Each of those is the right unit test for what it covers, and
// none of them can see a defect that lives in the seam between two layers.
//
// This repo has already paid for that. The ISO 18013-5 8.3.2.1.2.1
// partial-satisfaction gap — a request naming one element the wallet does not
// hold yielding no document at all, where the clause wants the rest returned —
// survived review because the fake wallet never ran a real DCQL query, and the
// real one is all-or-nothing in a way no fake reproduced by accident.
//
// So what is under test here is specifically composition:
//
//	real SQLCipher storage holding a genuinely issued mdoc
//	  -> mdoc_dcql.MdocDcqlHandler        real candidate search
//	  -> dcql.DcqlHandler
//	  -> isomdoc.WalletDiscloser      real instance selector, real device-key binder
//	  -> isomdoc.Session
//	  -> mdoc.OpenDCAPIResponse           opened and verified as the reader would
//
// The only fake left is the consent handler, which stands in for a human.
//
// # Why it is its own package
//
// eudi/isomdoc's own tests are cgo-free and fast, and they are worth keeping
// that way: SQLCipher needs cgo, which needs a C toolchain that is not present on
// every machine this package is developed on. Putting these tests in
// eudi/isomdoc would make that whole package unbuildable without gcc for the
// sake of four tests. A sibling directory keeps the cost where the benefit is —
// `go test ./eudi/isomdoc` stays toolchain-free, `go test ./eudi/...` runs
// both.
package integrationtest
