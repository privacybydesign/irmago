package lote

// Store persists the signed list documents across restarts, so a wallet that
// starts up offline still knows who is on a recognized list.
//
// What is stored is the signed document, not the parsed content: it is
// re-verified against the anchors in force at the time it is read, so a signing
// certificate that has since been revoked invalidates the lists already on
// disk rather than only the next download.
//
// A store never reports read errors. An unreadable document is a miss, which
// costs a fetch and, offline, one degradation to low — the same outcome as
// never having held the list, and not something a caller could act on.
//
// A nil Store is the "do not persist" case: the checker still holds its lists in
// memory for the run, and re-fetches on every start. There is no in-memory
// implementation because that is all one would be — the checker's own held map.
type Store interface {
	// Get returns the stored document for listId, or ok=false when there is
	// none.
	Get(listId string) (rawJws []byte, ok bool)

	// Put writes (or replaces) the document stored for listId.
	Put(listId string, rawJws []byte) error
}
