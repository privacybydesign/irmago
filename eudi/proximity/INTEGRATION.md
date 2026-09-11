# Wiring proximity into the app

What irmamobile has to build so an ISO/IEC 18013-5 device retrieval transaction
works on a phone, and — as importantly — what it must not build, because irmago
already has it.

Written from the Go side, where the 18013-5 detail lives. Every clause number below
is from NEN-ISO/IEC 18013-5:2021, and every constant is exported from
`eudi/credentials/mdoc` so nothing here needs retyping into Kotlin or Swift as a
literal.

---

## The short version

**irmago owns every byte and every key. The native layer moves bytes over BLE and
nothing else.**

The wallet is the **GATT client**. It connects to a service the *reader* hosts, and
never advertises. Concretely, the app must:

1. show a QR code,
2. implement six BLE primitives (`BLEPort`),
3. call `RunOverBLE` on a background thread,
4. forward notifications and disconnects inward.

That is the whole native surface. No CBOR, no COSE, no cryptography, no session
state, no ISO structures — **and no sequencing**: not even "when to connect" or
"when to subscribe". The GATT state machine is `proximity.BLETransport`, in Go,
because none of it needs a radio, and written natively it would be written twice —
once in Kotlin, once in Swift — and the two would drift on exactly the details that
are silent when wrong.

---

## 1. The whole app-side flow

```go
session, err := client.NewProximitySession(sessionId)  // sessionId from Dart, as for every session
qr, err := session.EngagementQR()                      // render as a QR code

// on a BACKGROUND thread:
err = session.RunOverBLE(port, 30_000)                 // returns when the transaction is over

// from the BLE callback thread:
session.Notify(characteristic, data)                   // every notification
session.Disconnected()                                 // when the link drops
```

That is it. `RunOverBLE` finds the reader, brings the link up, subscribes in the
order 8.3.3.1.1.5 requires, verifies Ident, runs the exchange, asks for consent
through the app's normal permission flow, sends the response and ends the session.
The app sequences nothing.

`session.Dismiss()` cancels from the UI — it unblocks a run parked on consent.

### The one rule that will bite you

**`RunOverBLE` blocks, and part of what it waits for is a human.** It asks for
consent through the app's normal permission flow and parks until
`HandleUserInteraction` delivers an answer.

> Call it on a background thread. On the UI thread the app deadlocks: the thread
> that must draw the consent screen is the one waiting for the consent screen's
> answer.

Everything else about consent is unchanged — `Status_RequestPermission` with a
`DisclosurePlan`, the **same** screen OpenID4VP uses, the answer back through
`HandleUserInteraction`. The only addition is `ConsentRequest.Documents`, carrying
the authenticated reader's identity: who is physically standing there, which an
online request has no equivalent of.

---

## 2. What the platform implements: one interface

Six methods, none of which knows anything about ISO 18013-5:

```go
type BLEPort interface {
    Scan(serviceUUID []byte, timeoutMillis int) error  // find + connect + discover
    Subscribe(characteristic []byte) error             // write 0x0001 to the CCCD
    Read(characteristic []byte) ([]byte, error)
    Write(characteristic, data []byte) error           // Write Without Response
    Disconnect() error
    MTU() int                                          // the NEGOTIATED value, not 23
}
```

This is the irreducible part. Go under gomobile has no bindings to
`android.bluetooth` or CoreBluetooth, and the Go BLE libraries target desktop rather
than a phone — so these six calls must be native, and **nothing else has to be**.
Everything above them is `proximity.BLETransport`, in Go, covered by
`transport_test.go` without a radio.

Both directions bind through gomobile: a Go interface can be implemented in Java or
Swift, and the platform calls back in through `Notify` / `Disconnected`.

### Contract details that matter

- **`Subscribe` must not return until the subscription is in effect.** The transport
  signals readiness immediately afterwards, and a reader that has been told the mdoc
  is ready starts sending at once. A subscription still settling loses the first
  part of the first message — a hang, not an error.
- **`Scan` must give up after `timeoutMillis`** rather than block forever, and must
  return only once the service and characteristics are discovered.
- **`Write` must respect the platform's write queue.** Returning before the stack
  accepted the part drops chunks locally, which looks exactly like a peer that went
  quiet.
- **`MTU` must report the negotiated value.** Reporting 23 when more was negotiated
  wastes packets; reporting more than was negotiated truncates every part silently.
- **Notifications must arrive in order and exactly once.** The session's IV is never
  transmitted — both sides reconstruct it from their own counters — so a dropped,
  duplicated or reordered part desynchronises everything after it. Unrecoverable by
  design; that is what Table 20's status 10 is for.

### Characteristic UUIDs — Table 12

Call `proximity.CharacteristicUUIDs()` for the raw 16-byte ids rather than
hardcoding them in Kotlin and Swift, where a transposed digit is a connection that
silently never receives anything.

| characteristic | UUID | role |
|---|---|---|
| `State` | `00000005-A123-48CE-896B-4C76973373E6` | transport writes `0x01` to start, `0x02` to end |
| `Client2Server` | `00000006-A123-48CE-896B-4C76973373E6` | transport writes outbound parts |
| `Server2Client` | `00000007-A123-48CE-896B-4C76973373E6` | subscribe; forward notifications inward |
| `Ident` | `00000008-A123-48CE-896B-4C76973373E6` | transport reads it once |

Table 11 is the *other* mode's set, where the mdoc is the GATT server. Not used here.

### Back-pressure

In central client mode the **reader** owns notification back-pressure — the classic
source of silently dropped chunks — so it is not your problem. That was one of the
reasons this mode was chosen. Your own `Write` queue still is.

---

## 3. What the native layer must NOT do

Every item here is already implemented, tested against ISO's own Annex D vectors,
and in several cases subtle enough that a second implementation would differ:

| do not build | already in |
|---|---|
| DeviceEngagement / the QR payload | `deviceengagement.go` |
| SessionTranscript and its handovers | `sessiontranscript.go` |
| ECKA-DH, HKDF, session keys, AES-GCM, the IV counters | `session.go` |
| DeviceRequest parsing | `devicerequest.go` |
| mdoc reader authentication (9.1.4) | `readerauth.go` |
| Which data elements may be released | `profile.go` (7.2.1) |
| Selective disclosure, deviceAuth, DeviceResponse, errors | `proximity/session.go` |
| Chunking and reassembly | `ble.go` |
| **The GATT sequence itself** — subscribe order, StateStart timing, Ident check, the chunk pump, termination | `proximity/transport.go` |
| Ident | `BLEIdent` / `VerifyBLEIdent` |

Two in particular are traps. **The session transcript is hashed, not compared** — it
must be built from the exact engagement bytes that were transmitted, so re-encoding
anything natively silently changes every session key derived from it. And **the IV
is never transmitted**: both sides reconstruct it from counters they keep
themselves, so a dropped or reordered message desynchronises everything after it.
That is what Table 20's status 10 exists for, and it is why the native layer must
deliver messages **in order and exactly once**.

---

## 4. Errors and termination

`Handle` distinguishes two kinds of failure, and the app should too:

- **A returned `reply` that is a status message.** The session is over and the
  reader is being told why — an undecryptable message (Table 20 status 10) or
  malformed CBOR (status 11). Send it, then close the connection.
- **A non-nil `error`.** A local fault the reader cannot be told about. Close the
  connection; the session state already carries the error for the UI.

`session.Terminated()` reports whether the session is finished. After termination
the keys are destroyed and further messages are refused, so do not retry.

A user walking away is `Dismiss()`, which unblocks a `Handle` parked on consent.
Without it that goroutine waits forever.

---

## 5. Testing, in the order that finds bugs cheapest

1. **Tier 0 — already done, no device.** `eudi/proximity`'s tests run a complete
   transaction between the wallet and a Go reader over `net.Pipe` with the real
   chunking in between. If you change Go-side behaviour, this catches it in
   milliseconds.
2. **Tier 1 — your six methods, against the Go reader.** `proximity.Reader` is a real
   mdoc reader. Because the sequencing above your `BLEPort` is already covered by
   `transport_test.go`, a failure here is in one of your six methods — most often
   `Subscribe` returning early or `MTU` reporting the wrong value.
3. **Tier 2 — against an independent implementation.** The Multipaz `samples/testapp`
   does both proximity roles. This is the one that finds disagreements our own two
   sides cannot, since they share an author.

A failure at Tier 2 that passes Tier 1 is an interop bug; a failure at Tier 1 that
passes Tier 0 is in the native layer. Keep them separable.

---

## 6. Open questions for the app

Neither is decided, and both are the app's to decide:

- **Consent before or after the tap.** The reader is physically present, so the
  window is short. The current design asks after the request arrives, which is
  what lets the screen name the reader — nothing can be shown about a verifier
  before it has authenticated.
- **What to show for a reader with no Yivi scheme extension.** It is authenticated
  (its certificate chains to a trusted anchor) but carries no legal name or logo,
  so the wallet falls back to the certificate's common name. A conformant 18013-5
  reader that is not part of Yivi's scheme is a normal thing to meet, not an error.
