package lote

// Store persists the signed list documents across restarts, so a wallet that
// starts up offline still knows who is on a recognized list. The signed document
// is what is stored, re-verified against the anchors in force when it is read, so
// a since-revoked signing certificate invalidates lists already on disk.
//
// A store never reports read errors: an unreadable document is a miss, which is
// the same outcome as never having held the list. A nil Store does not persist at
// all, leaving the checker's in-memory lists to be re-fetched on every start.
type Store interface {
	Get(listId string) (rawJws []byte, ok bool)
	Put(listId string, rawJws []byte) error
}
