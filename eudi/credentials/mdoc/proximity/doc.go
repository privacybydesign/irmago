// Package proximity implements the ISO/IEC 18013-5 proximity session layer
// for mdoc presentations: DeviceEngagement (QR payload), SessionEncryption
// (ECDH-ES + HKDF-SHA256 + AES-256-GCM), and the SessionEstablishment /
// SessionData CBOR messages exchanged after engagement.
//
// Out of scope: physical BLE and NFC transports. This package deals only with
// the data-plane structures and the crypto on top of them — enough to plug
// into any byte-stream transport.
package proximity
