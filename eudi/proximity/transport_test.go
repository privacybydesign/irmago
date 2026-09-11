package proximity

import (
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	cose "github.com/veraison/go-cose"

	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
)

// ============================================================
// THE BLE TRANSPORT, WITHOUT A RADIO
// ============================================================
//
// BLEPort is six functions, so the transport above it can be driven by a fake that
// records what it was asked to do and relays bytes to a real Go reader. That makes
// the GATT sequencing testable — which is the whole reason it lives in Go rather
// than being written twice in Kotlin and Swift.
//
// The ordering test is the one that earns its keep. "Subscribe to both, THEN write
// StateStart" is a requirement of 8.3.3.1.1.5, and getting it backwards produces a
// session that hangs rather than one that fails, on a phone, intermittently.

// fakePort implements BLEPort and records every call in order.
type fakePort struct {
	// calls is the ordered log, e.g. "subscribe:State", "write:State:01".
	calls []string

	// ident is what Read returns for the Ident characteristic.
	ident []byte
	// identErr makes the read fail.
	identErr error

	// writes collects everything written to Client2Server, in order.
	writes [][]byte

	// mtu is what the transport sizes its chunks from.
	mtu int

	// failWriteOn makes Write fail for a characteristic, to exercise the error path.
	failWriteOn []byte

	// scanErr makes Scan fail, for the reader-not-found path.
	scanErr error

	disconnected bool
}

func newFakePort(ident []byte) *fakePort {
	return &fakePort{ident: ident, mtu: 48}
}

// name renders a characteristic as its Table 12 role, so the call log reads.
func (p *fakePort) name(characteristic []byte) string {
	state, c2s, s2c, ident := CharacteristicUUIDs()
	switch {
	case equalBytes(characteristic, state):
		return "State"
	case equalBytes(characteristic, c2s):
		return "Client2Server"
	case equalBytes(characteristic, s2c):
		return "Server2Client"
	case equalBytes(characteristic, ident):
		return "Ident"
	}
	return fmt.Sprintf("%x", characteristic)
}

func (p *fakePort) Scan(serviceUUID []byte, timeoutMillis int) error {
	p.calls = append(p.calls, "scan")
	if p.scanErr != nil {
		return p.scanErr
	}
	return nil
}

func (p *fakePort) Subscribe(characteristic []byte) error {
	p.calls = append(p.calls, "subscribe:"+p.name(characteristic))
	return nil
}

func (p *fakePort) Read(characteristic []byte) ([]byte, error) {
	p.calls = append(p.calls, "read:"+p.name(characteristic))
	if p.identErr != nil {
		return nil, p.identErr
	}
	return p.ident, nil
}

func (p *fakePort) Write(characteristic, data []byte) error {
	if p.failWriteOn != nil && equalBytes(characteristic, p.failWriteOn) {
		return fmt.Errorf("write refused (test)")
	}
	p.calls = append(p.calls, fmt.Sprintf("write:%s:%x", p.name(characteristic), data))
	_, c2s, _, _ := CharacteristicUUIDs()
	if equalBytes(characteristic, c2s) {
		p.writes = append(p.writes, append([]byte(nil), data...))
	}
	return nil
}

func (p *fakePort) Disconnect() error {
	p.calls = append(p.calls, "disconnect")
	p.disconnected = true
	return nil
}

func (p *fakePort) MTU() int { return p.mtu }

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// index returns where a call appears in the log, or -1.
func (p *fakePort) index(call string) int {
	for i, c := range p.calls {
		if c == call {
			return i
		}
	}
	return -1
}

// transportFixture is a session, a matching reader, and the fake port between them.
type transportFixture struct {
	session   *Session
	transport *BLETransport
	port      *fakePort
	reader    *Reader
	wallet    *wallet
}

func newTransportFixture(t *testing.T, verifyIdent bool) *transportFixture {
	t.Helper()

	w, issuer := newWallet(t)
	pki := newReaderPKI(t)

	session, err := NewSession(SessionConfig{Discloser: w, DeviceKeys: w, Readers: pki.trust()})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// The Ident the reader would serve, derived from this session's own engagement.
	ident, err := stdmdoc.BLEIdent(session.EDeviceKeyBytes())
	if err != nil {
		t.Fatalf("BLEIdent: %v", err)
	}

	port := newFakePort(ident)
	transport, err := NewBLETransport(session, port, verifyIdent)
	if err != nil {
		t.Fatalf("NewBLETransport: %v", err)
	}

	qr, err := session.EngagementQR()
	if err != nil {
		t.Fatalf("EngagementQR: %v", err)
	}
	reader := NewReader(ReaderConfig{
		Signer:    pki.key,
		Algorithm: cose.AlgorithmES256,
		Chain:     pki.chain(),
		Issuers:   stdmdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()}),
	})
	if err := reader.Engage(qr); err != nil {
		t.Fatalf("Engage: %v", err)
	}

	return &transportFixture{session: session, transport: transport, port: port, reader: reader, wallet: w}
}

// notify feeds a whole message to the transport as chunked Server2Client
// notifications, the way a reader would.
func (f *transportFixture) notify(t *testing.T, message []byte) error {
	t.Helper()
	_, _, s2c, _ := CharacteristicUUIDs()
	parts, err := stdmdoc.ChunkMessage(message, f.port.MTU())
	if err != nil {
		t.Fatalf("ChunkMessage: %v", err)
	}
	for _, part := range parts {
		if err := f.transport.OnNotification(s2c, part); err != nil {
			return err
		}
	}
	return nil
}

// reassembleWrites turns everything written to Client2Server back into one message.
func (f *transportFixture) reassembleWrites(t *testing.T) []byte {
	t.Helper()
	var assembler stdmdoc.MessageAssembler
	for _, part := range f.port.writes {
		message, complete, err := assembler.Add(part)
		if err != nil {
			t.Fatalf("reassemble: %v", err)
		}
		if complete {
			return message
		}
	}
	t.Fatalf("the transport never wrote a complete message (%d parts)", len(f.port.writes))
	return nil
}

// ---------------------------------------------------------------------------
// Start ordering — 8.3.3.1.1.5
// ---------------------------------------------------------------------------

// TestTransportSubscribesBeforeSignallingReady is the test this file exists for.
//
// 8.3.3.1.1.5: StateStart "tells the GATT server that the GATT client is ready for
// the transmission to start". A reader that is told so begins sending at once, so a
// subscription not yet in effect loses the first part of the first message — which
// presents as a session that hangs rather than one that fails.
func TestTransportSubscribesBeforeSignallingReady(t *testing.T) {
	f := newTransportFixture(t, false)

	if err := f.transport.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	state := f.port.index("subscribe:State")
	s2c := f.port.index("subscribe:Server2Client")
	start := f.port.index("write:State:01")

	if state < 0 || s2c < 0 || start < 0 {
		t.Fatalf("missing a step: %v", f.port.calls)
	}
	if state > start || s2c > start {
		t.Errorf("StateStart was written before a subscription was in effect: %v", f.port.calls)
	}
}

// TestTransportStartIsNotRepeatable: a second Start would re-subscribe and re-signal
// readiness on a session already mid-exchange.
func TestTransportStartIsNotRepeatable(t *testing.T) {
	f := newTransportFixture(t, false)
	if err := f.transport.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := f.transport.Start(); err == nil {
		t.Error("Start succeeded twice")
	}
}

// ---------------------------------------------------------------------------
// Ident — 8.3.3.1.1.3
// ---------------------------------------------------------------------------

// TestTransportVerifiesIdentBeforeSignallingReady: the check has to happen before
// StateStart, because a mismatch means terminating rather than talking.
func TestTransportVerifiesIdentBeforeSignallingReady(t *testing.T) {
	f := newTransportFixture(t, true)

	if err := f.transport.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	read := f.port.index("read:Ident")
	start := f.port.index("write:State:01")
	if read < 0 {
		t.Fatalf("Ident was never read: %v", f.port.calls)
	}
	if read > start {
		t.Errorf("Ident was checked after readiness was signalled: %v", f.port.calls)
	}
}

// TestTransportRefusesTheWrongReader: a reader whose Ident does not match this
// engagement is a different reader in range. 8.3.3.1.1.3 says terminate.
func TestTransportRefusesTheWrongReader(t *testing.T) {
	f := newTransportFixture(t, true)
	f.port.ident = []byte("not the right ident value")

	err := f.transport.Start()
	if err == nil {
		t.Fatal("Start accepted a reader whose Ident does not match")
	}
	if !strings.Contains(err.Error(), "not the reader that scanned") {
		t.Errorf("error does not explain what went wrong: %v", err)
	}
	if !f.port.disconnected {
		t.Error("the connection was left open to the wrong reader")
	}
	if f.port.index("write:State:01") >= 0 {
		t.Error("readiness was signalled to the wrong reader")
	}
}

// TestTransportSkipsIdentWhenNotAsked: checking Ident is a "may", not a shall.
func TestTransportSkipsIdentWhenNotAsked(t *testing.T) {
	f := newTransportFixture(t, false)
	if err := f.transport.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if f.port.index("read:Ident") >= 0 {
		t.Error("Ident was read although verification was not requested")
	}
}

// ---------------------------------------------------------------------------
// The exchange
// ---------------------------------------------------------------------------

// TestTransportCarriesAWholeTransaction runs a real request from a real reader
// through the transport and checks the reader can read the answer back.
//
// The fake port is the only thing standing in for hardware: the session, the
// reader, the chunking and the reassembly are all production code.
func TestTransportCarriesAWholeTransaction(t *testing.T) {
	f := newTransportFixture(t, true)
	if err := f.transport.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	request, err := f.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}

	// Deliberately small MTU, so the request arrives in many parts and the reply
	// leaves in many. A transaction that fits one packet tests no framing at all.
	if err := f.notify(t, request); err != nil {
		t.Fatalf("OnNotification: %v", err)
	}
	if len(f.port.writes) < 2 {
		t.Errorf("the reply went out in %d part(s); the MTU should have forced several", len(f.port.writes))
	}

	response, err := f.reader.ReadResponse(f.reassembleWrites(t))
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if len(response.Documents) != 1 {
		t.Fatalf("got %d documents, want 1", len(response.Documents))
	}

	results, err := f.reader.Verify(response, testNamespace, testDocType)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !results[0].Valid || !results[0].DeviceAuthValid {
		t.Errorf("the response did not verify: %+v", results[0])
	}
}

// TestTransportChunksToTheNegotiatedMTU: the port reports the MTU, and every part
// has to fit it. Writing the 23-byte default when a larger one was negotiated only
// wastes packets; writing more than was negotiated truncates silently.
func TestTransportChunksToTheNegotiatedMTU(t *testing.T) {
	f := newTransportFixture(t, false)
	f.port.mtu = 100
	if err := f.transport.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	request, err := f.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if err := f.notify(t, request); err != nil {
		t.Fatalf("OnNotification: %v", err)
	}

	limit, err := stdmdoc.MaxCharacteristicSize(f.port.mtu)
	if err != nil {
		t.Fatalf("MaxCharacteristicSize: %v", err)
	}
	for i, part := range f.port.writes {
		if len(part) > limit {
			t.Errorf("part %d is %d bytes, over the %d the MTU allows", i, len(part), limit)
		}
	}
}

// ---------------------------------------------------------------------------
// Ending
// ---------------------------------------------------------------------------

// TestTransportEndsOnStateEnd: either party may send StateEnd at any time
// (Table 13), and 9.1.1.4 has both destroy their key material when it happens.
func TestTransportEndsOnStateEnd(t *testing.T) {
	f := newTransportFixture(t, false)
	if err := f.transport.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	state, _, _, _ := CharacteristicUUIDs()
	if err := f.transport.OnNotification(state, []byte{stdmdoc.StateEnd}); err != nil {
		t.Fatalf("OnNotification(StateEnd): %v", err)
	}

	if f.transport.Running() {
		t.Error("the transport is still running after StateEnd")
	}
	if !f.session.Terminated() {
		t.Error("the session's keys were not destroyed")
	}
	if !f.port.disconnected {
		t.Error("the link was left open")
	}
}

// TestTransportCloseSendsStateEnd: ending from this side tells the reader.
func TestTransportCloseSendsStateEnd(t *testing.T) {
	f := newTransportFixture(t, false)
	if err := f.transport.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := f.transport.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if f.port.index("write:State:02") < 0 {
		t.Errorf("StateEnd was not written: %v", f.port.calls)
	}
	if !f.session.Terminated() {
		t.Error("the session was not closed")
	}
	// Idempotent: a second Close must not write StateEnd again on a dead link.
	before := len(f.port.calls)
	if err := f.transport.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if len(f.port.calls) != before {
		t.Errorf("a second Close acted on the link: %v", f.port.calls[before:])
	}
}

// TestTransportDisconnectDestroysTheSession: an interrupted transaction is over,
// and 9.1.1.4 does not make key destruction conditional on an orderly ending.
func TestTransportDisconnectDestroysTheSession(t *testing.T) {
	f := newTransportFixture(t, false)
	if err := f.transport.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	f.transport.OnDisconnect()

	if f.transport.Running() {
		t.Error("still running after a disconnect")
	}
	if !f.session.Terminated() {
		t.Error("the session survived the link")
	}
}

// TestTransportRejectsUnknownCharacteristic: a notification from something never
// subscribed to is the platform wiring being wrong. Named rather than ignored,
// because dropping it silently presents as a hang.
func TestTransportRejectsUnknownCharacteristic(t *testing.T) {
	f := newTransportFixture(t, false)
	if err := f.transport.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	err := f.transport.OnNotification([]byte{0xde, 0xad, 0xbe, 0xef}, []byte{0x00})
	if err == nil {
		t.Fatal("a notification from an unsubscribed characteristic was accepted")
	}
	if !strings.Contains(err.Error(), "unexpected characteristic") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestTransportRefusesNotificationsBeforeStart: nothing should arrive before
// readiness is signalled, and treating it as valid would hide the ordering bug
// TestTransportSubscribesBeforeSignallingReady exists to catch.
func TestTransportRefusesNotificationsBeforeStart(t *testing.T) {
	f := newTransportFixture(t, false)
	_, _, s2c, _ := CharacteristicUUIDs()
	if err := f.transport.OnNotification(s2c, []byte{0x00}); err == nil {
		t.Error("a notification was accepted before Start")
	}
}

// TestTransportReportsAWriteFailure: a platform that cannot write is not a peer
// that went quiet, and the difference has to reach the caller.
func TestTransportReportsAWriteFailure(t *testing.T) {
	f := newTransportFixture(t, false)
	if err := f.transport.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, c2s, _, _ := CharacteristicUUIDs()
	f.port.failWriteOn = c2s

	request, err := f.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	err = f.notify(t, request)
	if err == nil {
		t.Fatal("a failed write was not reported")
	}
	if !strings.Contains(err.Error(), "write part") {
		t.Errorf("error does not say which part failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Run — the single call the app makes
// ---------------------------------------------------------------------------

// TestTransportRunDrivesTheWholeExchange: one call does scanning, the link, the
// transaction and the ending, so the app sequences nothing.
func TestTransportRunDrivesTheWholeExchange(t *testing.T) {
	f := newTransportFixture(t, true)

	request, err := f.reader.Request(itemsFor(testDocType, testNamespace, "age_over_18"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- f.transport.Run(5000) }()

	// Wait for Run to get the link up before the "reader" says anything, the way a
	// real reader waits for StateStart.
	waitFor(t, func() bool { return f.transport.Running() }, "transport never started")

	if err := f.notify(t, request); err != nil {
		t.Fatalf("OnNotification: %v", err)
	}

	// The response is out, but the exchange is not over: 9.1.1.4 lets the reader ask
	// again on the same session, so Run must still be waiting.
	if _, err := f.reader.ReadResponse(f.reassembleWrites(t)); err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("Run returned while the session was still open: %v", err)
	default:
	}

	// The reader ends it.
	state, _, _, _ := CharacteristicUUIDs()
	if err := f.transport.OnNotification(state, []byte{stdmdoc.StateEnd}); err != nil {
		t.Fatalf("OnNotification(StateEnd): %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("an orderly ending returned an error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the exchange ended")
	}
}

// TestTransportRunScansForTheEngagementUUID: the reader advertises the UUID the
// MDOC chose (8.3.3.1.1.3), so Run must scan for this session's own, not for
// anything discovered.
func TestTransportRunScansForTheEngagementUUID(t *testing.T) {
	f := newTransportFixture(t, false)
	f.port.scanErr = fmt.Errorf("no reader found (test)")

	err := f.transport.Run(100)
	if err == nil {
		t.Fatal("Run succeeded although no reader was found")
	}
	if !strings.Contains(err.Error(), "find the reader") {
		t.Errorf("error does not say scanning failed: %v", err)
	}
	if f.port.index("subscribe:State") >= 0 {
		t.Error("the transport subscribed although it never connected")
	}
}

// TestTransportRunReturnsOnDisconnect: the link dropping mid-transaction unblocks
// the app rather than leaving it parked forever.
func TestTransportRunReturnsOnDisconnect(t *testing.T) {
	f := newTransportFixture(t, false)

	done := make(chan error, 1)
	go func() { done <- f.transport.Run(5000) }()
	waitFor(t, func() bool { return f.transport.Running() }, "transport never started")

	f.transport.OnDisconnect()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return when the link dropped")
	}
	if !f.session.Terminated() {
		t.Error("the session survived the link")
	}
}

// waitFor polls until cond holds, so a test fails on a deadline instead of hanging.
func waitFor(t *testing.T, cond func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(message)
}
