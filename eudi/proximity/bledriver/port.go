package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"tinygo.org/x/bluetooth"

	"github.com/privacybydesign/irmago/eudi/proximity"
)

// Port implements proximity.BLEPort over a desktop radio.
//
// This is the piece irmamobile will write in Kotlin and Swift, and it is exactly
// as small here as it will be there: find the reader, connect, subscribe, read,
// write, disconnect, report the MTU. No ISO 18013-5 knowledge — the sequencing,
// the chunking, the Ident check and the session all live above it in
// proximity.BLETransport.
//
// Writing it twice, once here and once natively, is the point: if the Go
// transport works against this port, the only thing left to get wrong on a phone
// is the platform's own six methods.
type Port struct {
	adapter *bluetooth.Adapter

	mu     sync.Mutex
	device bluetooth.Device
	// chars caches the characteristics discovered on the reader's service, keyed
	// by canonical UUID string.
	chars     map[string]bluetooth.DeviceCharacteristic
	connected bool

	// notify hands an inbound notification to the transport. Set by the caller
	// before Scan, because notifications can arrive the moment a subscription
	// takes effect.
	notify func(characteristic, data []byte)

	// verbose prints every operation, which is most of the value of a bring-up
	// tool.
	verbose bool
}

func NewPort(notify func(characteristic, data []byte), verbose bool) *Port {
	return &Port{
		adapter: bluetooth.DefaultAdapter,
		chars:   map[string]bluetooth.DeviceCharacteristic{},
		notify:  notify,
		verbose: verbose,
	}
}

var _ proximity.BLEPort = (*Port)(nil)

func (p *Port) logf(format string, args ...any) {
	if p.verbose {
		fmt.Printf("  [ble] "+format+"\n", args...)
	}
}

// Enable brings the adapter up. Separate from Scan so a dead radio is reported
// before a QR code is shown to anyone.
//
// Note that on Windows this succeeds even when the radio is switched off — the
// failure surfaces later, from Scan, as "The device is not ready for use".
func (p *Port) Enable() error {
	if err := p.adapter.Enable(); err != nil {
		return fmt.Errorf("enable the Bluetooth adapter: %w", err)
	}
	return nil
}

// Scan finds the reader advertising serviceUUID, connects, and discovers its
// characteristics.
//
// Matching is on the SERVICE UUID in the advertisement, never on a device name:
// 8.3.3.1.1.3 has the reader advertise the UUID the mdoc chose and put in its QR,
// and in practice almost nothing on a crowded band advertises a name at all.
func (p *Port) Scan(serviceUUID []byte, timeoutMillis int) error {
	target, err := uuidFromBytes(serviceUUID)
	if err != nil {
		return err
	}
	p.logf("scanning for service %s (%d ms)", target.String(), timeoutMillis)

	found := make(chan bluetooth.ScanResult, 1)
	var once sync.Once

	// StopScan from a timer as well as from the callback: Scan blocks until it is
	// stopped, so a scan that only stops on success hangs forever when the reader
	// never appears.
	timer := time.AfterFunc(time.Duration(timeoutMillis)*time.Millisecond, func() {
		_ = p.adapter.StopScan()
	})
	defer timer.Stop()

	scanErr := p.adapter.Scan(func(a *bluetooth.Adapter, result bluetooth.ScanResult) {
		if !advertisesService(result, target) {
			return
		}
		once.Do(func() {
			found <- result
			_ = a.StopScan()
		})
	})
	if scanErr != nil {
		return fmt.Errorf("scan: %w", scanErr)
	}

	var result bluetooth.ScanResult
	select {
	case result = <-found:
	default:
		return fmt.Errorf(
			"no reader advertising %s within %d ms — is the reader's QR scan finished and its BLE advertising started?",
			target.String(), timeoutMillis)
	}

	p.logf("found %s (rssi %d), connecting", result.Address.String(), result.RSSI)
	device, err := p.adapter.Connect(result.Address, bluetooth.ConnectionParams{})
	if err != nil {
		return fmt.Errorf("connect to %s: %w", result.Address.String(), err)
	}

	services, err := device.DiscoverServices([]bluetooth.UUID{target})
	if err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("discover the mdoc service: %w", err)
	}
	if len(services) == 0 {
		_ = device.Disconnect()
		return fmt.Errorf("the reader advertised %s but does not host it", target.String())
	}

	// nil filter: take every characteristic the service has, so a reader that
	// omits the optional Ident is still usable.
	discovered, err := services[0].DiscoverCharacteristics(nil)
	if err != nil {
		_ = device.Disconnect()
		return fmt.Errorf("discover characteristics: %w", err)
	}

	p.mu.Lock()
	p.device = device
	p.connected = true
	for _, characteristic := range discovered {
		p.chars[strings.ToLower(characteristic.UUID().String())] = characteristic
		p.logf("characteristic %s", characteristic.UUID().String())
	}
	p.mu.Unlock()

	return nil
}

// characteristic looks one up by the raw 16 bytes the transport passes.
func (p *Port) characteristic(raw []byte) (bluetooth.DeviceCharacteristic, error) {
	id, err := uuidFromBytes(raw)
	if err != nil {
		return bluetooth.DeviceCharacteristic{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	characteristic, ok := p.chars[strings.ToLower(id.String())]
	if !ok {
		return bluetooth.DeviceCharacteristic{}, fmt.Errorf(
			"the reader does not expose characteristic %s", id.String())
	}
	return characteristic, nil
}

// Subscribe enables notifications and routes them to the transport.
//
// It must not return until the subscription is in effect: the transport signals
// readiness immediately afterwards and the reader starts sending at once, so a
// subscription still settling loses the first part of the first message.
// EnableNotifications is synchronous here, which is what makes that hold.
func (p *Port) Subscribe(characteristic []byte) error {
	target, err := uuidFromBytes(characteristic)
	if err != nil {
		return err
	}
	c, err := p.characteristic(characteristic)
	if err != nil {
		return err
	}

	// The raw id is captured rather than re-derived: the callback only receives a
	// buffer, so which characteristic it came from has to be bound per
	// subscription.
	owner := append([]byte(nil), characteristic...)
	if err := c.EnableNotifications(func(buf []byte) {
		if p.notify != nil {
			p.notify(owner, append([]byte(nil), buf...))
		}
	}); err != nil {
		return fmt.Errorf("subscribe to %s: %w", target.String(), err)
	}

	p.logf("subscribed to %s", target.String())
	return nil
}

// Read reads a characteristic once. Used for Ident (8.3.3.1.1.3).
func (p *Port) Read(characteristic []byte) ([]byte, error) {
	c, err := p.characteristic(characteristic)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read characteristic: %w", err)
	}
	p.logf("read %d bytes", n)
	return buf[:n], nil
}

// Write sends one part, Write Without Response as 8.3.3.1.1.6 specifies.
func (p *Port) Write(characteristic, data []byte) error {
	c, err := p.characteristic(characteristic)
	if err != nil {
		return err
	}
	if _, err := c.WriteWithoutResponse(data); err != nil {
		return fmt.Errorf("write %d bytes: %w", len(data), err)
	}
	p.logf("wrote %d bytes", len(data))
	return nil
}

// Disconnect drops the link.
func (p *Port) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.connected {
		return nil
	}
	p.connected = false
	p.logf("disconnecting")
	return p.device.Disconnect()
}

// MTU reports the negotiated ATT MTU.
//
// Taken from Client2Server because the MTU is a property of the connection rather
// than of a characteristic, and that one is guaranteed to exist. Falling back to
// the 23-byte minimum is safe — it only costs packets — whereas guessing high
// would truncate every part silently.
func (p *Port) MTU() int {
	state, client2Server, _, _ := proximity.CharacteristicUUIDs()
	for _, raw := range [][]byte{client2Server, state} {
		if c, err := p.characteristic(raw); err == nil {
			if mtu, err := c.GetMTU(); err == nil && mtu >= 23 {
				return int(mtu)
			}
		}
	}
	return 23
}

// uuidFromBytes turns the transport's raw 16 bytes into a tinygo UUID.
//
// Deliberately via the canonical string rather than bluetooth.NewUUID: the raw
// bytes are in RFC 4122 string order, tinygo's constructor takes its own 16-byte
// ordering, and a byte-order mistake here produces a UUID that simply never
// matches anything — with no error, just a scan that finds nothing. Parsing the
// text sidesteps the question entirely.
func uuidFromBytes(raw []byte) (bluetooth.UUID, error) {
	if len(raw) != 16 {
		return bluetooth.UUID{}, fmt.Errorf("a characteristic id is 16 bytes, got %d", len(raw))
	}
	text := fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
	id, err := bluetooth.ParseUUID(text)
	if err != nil {
		return bluetooth.UUID{}, fmt.Errorf("parse uuid %q: %w", text, err)
	}
	return id, nil
}

// advertisesService reports whether an advertisement carries the service we are
// looking for, comparing only the first EIGHT bytes.
//
// # Why not HasServiceUUID, and why only half the UUID
//
// tinygo.org/x/bluetooth v0.16.0 corrupts the back half of every service UUID it
// reports on Windows. gap_windows.go reads each entry out of the WinRT vector by
// taking the address of the returned local and reinterpreting it as a 16-byte
// syscall.GUID:
//
//	element, _ := serviceUuidsVector.GetAt(i)
//	serviceGUID := (*syscall.GUID)(unsafe.Pointer(&element))
//
// Only the first eight bytes survive that. It is visible in any scan: the standard
// Device Information Service, whose UUID must be
// 0000180a-0000-1000-8000-00805f9b34fb, is reported as
// 0000180a-0000-1000-0100-000000000000 — Data1, Data2 and Data3 correct, Data4
// garbage. So HasServiceUUID can never match a 128-bit UUID on this platform, and
// the failure is silent: a scan that finds nothing, with no error.
//
// Comparing the first eight bytes is sound here rather than merely convenient. The
// service UUID is generated per transaction from crypto/rand (8.3.3.1.1.3 requires
// it be unique per transaction), so those bytes carry 64 bits of entropy — a
// collision with another advertiser is not a practical concern, and a false match
// would fail at the next step anyway when the service turned out not to host the
// Table 12 characteristics.
//
// Delete this the moment the upstream bug is fixed; it is a workaround for a
// library defect, not a property of BLE.
func advertisesService(result bluetooth.ScanResult, target bluetooth.UUID) bool {
	want := target.BytesBigEndian()
	for _, advertised := range result.AdvertisementPayload.ServiceUUIDs() {
		got := advertised.BytesBigEndian()
		if [8]byte(got[:8]) == [8]byte(want[:8]) {
			return true
		}
	}
	return false
}
