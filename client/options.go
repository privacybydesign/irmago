package client

import "github.com/privacybydesign/irmago/eudi/lote"

// productionRecognizedLists is the compiled-in set of trust lists the wallet
// recognizes, and the source of the medium rung on the trust ladder.
//
// It is empty. Yivi's own list is not published yet, and recognizing a list
// means pinning both where it is served and the anchor its signing certificate
// chains to — neither of which exists to be pinned. Until the entry is filled
// in, the recognized-list channel contributes nothing and the certificate
// channel decides every rung, which is the behaviour a wallet that cannot reach
// any list has anyway.
var productionRecognizedLists []lote.RecognizedList

// Option configures the client at construction.
type Option func(*options)

type options struct {
	recognizedLists []lote.RecognizedList
}

// WithRecognizedLists replaces the compiled-in set of recognized trust lists.
//
// This is a test seam, and the only one the trust ladder has: a session test
// points the wallet at a list it serves itself (see lote.TestListServer) and
// then drives whole sessions against it, rather than reaching inside the client
// to swap out an evaluator.
func WithRecognizedLists(lists ...lote.RecognizedList) Option {
	return func(o *options) {
		o.recognizedLists = lists
	}
}
