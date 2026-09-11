package proximity

import (
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
)

// ============================================================
// THE BLE TRANSPORT — ISO/IEC 18013-5 8.3.3.1.1
// ============================================================
//
// Session turns one message into the next. This turns a GATT connection into that
// stream of messages: what to subscribe to, in what order, when to write the byte
// that starts the exchange, how to split a reply and reassemble a request, and how
// either side ends it.
//
// # Why this is in Go rather than in the app
//
// None of it needs a radio. It is ISO sequencing that happens to call six platform
// functions, and the platform functions are the only part Go genuinely cannot do:
// gomobile has no bindings to android.bluetooth or CoreBluetooth, and the Go BLE
// libraries target desktop rather than a phone.
//
// Written in the app instead, it would be written twice — once in Kotlin, once in
// Swift — and the two would drift on exactly the details that are easy to get
// wrong and silent when wrong. "Subscribe to both characteristics, THEN write
// 0x01" is a requirement of 8.3.3.1.1.5, not a platform quirk. So the platform
// implements BLEPort, six methods with no ISO knowledge in them, and everything
// above it is here, where it can be tested without a radio.
//
// # mdoc central client mode
//
// The wallet is the GATT *client* and the reader is the GATT server (8.3.3.1.1.1).
// The wallet never advertises. Consequences that shape this file:
//
//   - The characteristics are Table 12's, hosted by the READER — including Ident,
//     which Table 11 has no counterpart for.
//   - Notification back-pressure is the reader's problem, not ours. In peripheral
//     server mode it would be ours, and it is the classic source of silently
//     dropped chunks.
//   - The service UUID is still the MDOC's choice (8.3.3.1.1.3) even though the
//     reader is the one broadcasting it. Scanning is the caller's job, before a
//     transport exists; Session.ServiceUUID says what to scan for.

// BLEPort is the platform's side of the connection: six operations, none of which
// knows anything about ISO 18013-5.
//
// The caller has already scanned for Session.ServiceUUID, connected to the reader
// and discovered its service before building a transport over it. Everything after
// that point is driven from here.
//
// Each characteristic is identified by its 16 raw UUID bytes, which is what
// gomobile can carry — see CharacteristicUUID for turning those into the platform's
// own representation.
type BLEPort interface {
	// Scan finds the reader advertising serviceUUID and connects to it, returning
	// once its service and characteristics are discovered and the other methods can
	// be used. It must give up after timeoutMillis rather than block forever.
	//
	// Which UUID to look for, when to give up and what to do afterwards are all
	// decided in Go; this is the one step that cannot be, because scanning is a
	// platform API call.
	Scan(serviceUUID []byte, timeoutMillis int) error

	// Subscribe enables notifications on a characteristic (writing 0x0001 to its
	// CCCD). It must not return until the subscription is in effect: 8.3.3.1.1.5
	// has the mdoc signal readiness only afterwards, and a StateStart that races
	// its own subscription loses the first notification.
	Subscribe(characteristic []byte) error

	// Read reads a characteristic's value once.
	Read(characteristic []byte) ([]byte, error)

	// Write writes one part to a characteristic (Write Without Response). It must
	// respect the platform's own write queue — returning before the stack has
	// accepted the part drops chunks locally, which looks exactly like a peer that
	// stopped listening.
	Write(characteristic, data []byte) error

	// Disconnect tears the connection down.
	Disconnect() error

	// MTU is the NEGOTIATED ATT MTU, not the 23-byte default. Chunk sizing is
	// derived from it, so reporting the default when a larger one was negotiated
	// merely wastes packets, while reporting a larger one than was negotiated
	// silently truncates every part.
	MTU() int
}

// transportState tracks how far the exchange has got.
type transportState int

const (
	transportIdle transportState = iota
	transportStarted
	transportClosed
)

// BLETransport drives one proximity session over one GATT connection.
//
// The platform calls Start once, then OnNotification for every notification and
// OnDisconnect if the link drops. Everything else happens in here.
//
// Safe for concurrent calls from the platform: notifications arrive on whatever
// thread the BLE stack uses, and the session underneath tolerates no concurrency at
// all (its message counters are the reason), so every entry point takes the same
// lock.
type BLETransport struct {
	mu sync.Mutex

	session *Session
	port    BLEPort
	state   transportState

	// assembler reassembles inbound parts. One instance for the whole session; it
	// resets itself after each complete message.
	assembler mdoc.MessageAssembler

	// verifyIdent reads and checks the reader's Ident characteristic during Start.
	// Checking it is a "may" in 8.3.3.1.1.3, not a shall.
	verifyIdent bool

	// done closes when the exchange ends, however it ends. Run waits on it, so the
	// caller gets one blocking call instead of a lifecycle to manage.
	done chan struct{}
	// failure is what ended it, if anything did other than an orderly finish.
	failure error
}

// NewBLETransport builds a transport over an established connection.
//
// verifyIdent asks for the Ident check of 8.3.3.1.1.3, which guards against
// connecting to the wrong reader when several are in range. It is optional in the
// clause and costs one extra read; prefer it on.
func NewBLETransport(session *Session, port BLEPort, verifyIdent bool) (*BLETransport, error) {
	if session == nil {
		return nil, fmt.Errorf("BLE transport needs a session")
	}
	if port == nil {
		return nil, fmt.Errorf("BLE transport needs a port to reach the reader through")
	}
	return &BLETransport{session: session, port: port, verifyIdent: verifyIdent, done: make(chan struct{})}, nil
}

// Start brings the connection up to the point where the reader will talk.
//
// The order is fixed by 8.3.3.1.1.5 and is the single most common thing to get
// wrong: subscribe to BOTH characteristics first, and only then write StateStart.
// A reader that has been told the mdoc is ready will begin sending immediately, so
// a subscription that is not yet in effect loses the first part of the first
// message — which presents as a session that hangs rather than one that fails.
func (t *BLETransport) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state != transportIdle {
		return fmt.Errorf("BLE transport has already been started")
	}

	if err := t.port.Subscribe(mdoc.CentralClientStateCharacteristic[:]); err != nil {
		return fmt.Errorf("subscribe to State: %w", err)
	}
	if err := t.port.Subscribe(mdoc.CentralClientServer2ClientCharacteristic[:]); err != nil {
		return fmt.Errorf("subscribe to Server2Client: %w", err)
	}

	// Before announcing readiness, not after: an Ident mismatch means this is the
	// wrong reader, and 8.3.3.1.1.3 says to terminate rather than talk to it.
	if t.verifyIdent {
		if err := t.checkIdent(); err != nil {
			t.closeLocked()
			return err
		}
	}

	if err := t.port.Write(mdoc.CentralClientStateCharacteristic[:], []byte{mdoc.StateStart}); err != nil {
		return fmt.Errorf("write StateStart: %w", err)
	}

	t.state = transportStarted
	return nil
}

// checkIdent reads Ident from the reader and compares it with what this session's
// own engagement implies.
//
// The comparison is of public, engagement-derived values on both sides, so it
// authenticates nothing — it only establishes that this is the reader that scanned
// our QR rather than another one in range. Reader authentication is 9.1.4 and
// happens later, inside the session.
func (t *BLETransport) checkIdent() error {
	received, err := t.port.Read(mdoc.CentralClientIdentCharacteristic[:])
	if err != nil {
		return fmt.Errorf("read Ident: %w", err)
	}
	if err := mdoc.VerifyBLEIdent(t.session.EDeviceKeyBytes(), received); err != nil {
		return fmt.Errorf("this is not the reader that scanned the engagement: %w", err)
	}
	return nil
}

// OnNotification delivers one notification from the reader.
//
// Parts must arrive IN ORDER and EXACTLY ONCE. The session's IV is never
// transmitted — both sides reconstruct it from counters they keep themselves — so a
// dropped, duplicated or reordered part desynchronises everything after it. That is
// what Table 20's status 10 exists for, and it is unrecoverable by design.
func (t *BLETransport) OnNotification(characteristic, data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state != transportStarted {
		return fmt.Errorf("BLE transport is not running")
	}

	switch {
	case equalUUID(characteristic, mdoc.CentralClientStateCharacteristic):
		return t.onState(data)
	case equalUUID(characteristic, mdoc.CentralClientServer2ClientCharacteristic):
		return t.onData(data)
	default:
		// A notification from a characteristic we never subscribed to is the
		// platform wiring being wrong, not the reader misbehaving. Named rather
		// than ignored, because silently dropping it would present as a hang.
		return fmt.Errorf("notification from an unexpected characteristic %x", characteristic)
	}
}

// onState handles the State characteristic (Table 13).
func (t *BLETransport) onState(data []byte) error {
	if len(data) != 1 {
		return fmt.Errorf("the State characteristic carries one byte, got %d", len(data))
	}
	switch data[0] {
	case mdoc.StateEnd:
		// The reader ended the exchange. 9.1.1.4 has both parties destroy their key
		// material; Session.Close does our half.
		t.closeLocked()
		return nil
	case mdoc.StateStart:
		// StateStart is written BY the GATT client, which is us. Receiving one back
		// is a reader that has the roles confused.
		return fmt.Errorf("the reader sent StateStart, which only the GATT client writes")
	default:
		return fmt.Errorf("unknown State value 0x%02x", data[0])
	}
}

// onData reassembles a part and, once a message is complete, answers it.
func (t *BLETransport) onData(part []byte) error {
	message, complete, err := t.assembler.Add(part)
	if err != nil {
		return fmt.Errorf("reassemble: %w", err)
	}
	if !complete {
		return nil
	}

	reply, err := t.session.Handle(message)
	if err != nil {
		// A local fault the reader cannot be told about. Drop the link rather than
		// leave it open on a session that can no longer answer.
		t.fail(err)
		t.closeLocked()
		return err
	}

	if reply != nil {
		if err := t.send(reply); err != nil {
			return err
		}
	}

	// Handle returns a status message and terminates for an undecryptable or
	// malformed message; the reply above is what tells the reader why, so it is
	// sent before the link goes.
	if t.session.Terminated() {
		t.closeLocked()
	}
	return nil
}

// send splits a message and writes every part to Client2Server.
func (t *BLETransport) send(message []byte) error {
	parts, err := mdoc.ChunkMessage(message, t.port.MTU())
	if err != nil {
		return fmt.Errorf("chunk outbound message: %w", err)
	}
	for i, part := range parts {
		if err := t.port.Write(mdoc.CentralClientClient2ServerCharacteristic[:], part); err != nil {
			return fmt.Errorf("write part %d of %d: %w", i+1, len(parts), err)
		}
	}
	return nil
}

// OnDisconnect reports that the link dropped, from either side.
//
// The session's keys go either way: an interrupted transaction is over, and 9.1.1.4
// does not make destroying them conditional on an orderly ending.
func (t *BLETransport) OnDisconnect() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == transportClosed {
		return
	}
	t.state = transportClosed
	_, _ = t.session.Close()
	close(t.done)
}

// Close ends the exchange from this side: StateEnd to the reader, then the session's
// own termination, then the link.
//
// Either party may send StateEnd at any time (Table 13). It is written rather than
// notified because in this mode the reader is the GATT server.
func (t *BLETransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state == transportClosed {
		return nil
	}
	if t.state == transportStarted {
		// Best effort: the link may already be gone, and the session still has to be
		// closed either way.
		_ = t.port.Write(mdoc.CentralClientStateCharacteristic[:], []byte{mdoc.StateEnd})
	}
	t.closeLocked()
	return nil
}

// Running reports whether the exchange is still live.
func (t *BLETransport) Running() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state == transportStarted
}

// closeLocked destroys the session and drops the link. Caller holds the lock.
func (t *BLETransport) closeLocked() {
	if t.state == transportClosed {
		return
	}
	t.state = transportClosed
	_, _ = t.session.Close()
	_ = t.port.Disconnect()
	close(t.done)
}

// equalUUID compares a platform-supplied characteristic id with one of Table 12's.
func equalUUID(raw []byte, known uuid.UUID) bool {
	if len(raw) != len(known) {
		return false
	}
	for i := range known {
		if raw[i] != known[i] {
			return false
		}
	}
	return true
}

// CharacteristicUUIDs returns the Table 12 characteristics this transport uses, in
// the order Start touches them, as raw 16-byte ids.
//
// Exposed so the platform can register or look them up without hardcoding the
// values in Kotlin and Swift, where a transposed digit is a connection that
// silently never receives anything.
func CharacteristicUUIDs() (state, client2Server, server2Client, ident []byte) {
	return mdoc.CentralClientStateCharacteristic[:],
		mdoc.CentralClientClient2ServerCharacteristic[:],
		mdoc.CentralClientServer2ClientCharacteristic[:],
		mdoc.CentralClientIdentCharacteristic[:]
}

// Run conducts the entire exchange: find the reader, connect, bring the link up,
// and stay until the transaction ends.
//
// This is the call the app should make. Everything a caller would otherwise have to
// sequence — which UUID to scan for, when to give up, subscribing before signalling
// readiness, verifying Ident, chunking, reassembly, termination — happens inside it.
// The app supplies a BLEPort, calls this on a background thread, and forwards
// notifications to OnNotification as they arrive.
//
// It returns when the session is over: an orderly finish returns nil, and anything
// else returns what ended it. It does NOT return when the response has been sent —
// 9.1.1.4 lets the exchange continue, and the reader may ask again on the same
// session.
//
// Blocks. It waits for a human to answer a consent screen, so it must not be called
// on the UI thread: the thread that would draw the screen would be the one waiting
// for its answer.
func (t *BLETransport) Run(scanTimeoutMillis int) error {
	serviceUUID, err := t.session.ServiceUUID()
	if err != nil {
		return fmt.Errorf("read the engagement's service UUID: %w", err)
	}

	// The reader advertises the UUID the MDOC chose and put in the QR code
	// (8.3.3.1.1.3), which is why this value comes from our own engagement rather
	// than from anything scanned.
	if err := t.port.Scan(serviceUUID, scanTimeoutMillis); err != nil {
		return fmt.Errorf("find the reader: %w", err)
	}

	if err := t.Start(); err != nil {
		return err
	}

	<-t.done

	t.mu.Lock()
	defer t.mu.Unlock()
	return t.failure
}

// fail records why the exchange ended, for Run to return. Caller holds the lock.
func (t *BLETransport) fail(err error) {
	if t.failure == nil {
		t.failure = err
	}
}
