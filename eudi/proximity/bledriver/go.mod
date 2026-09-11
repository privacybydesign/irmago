// A SEPARATE MODULE on purpose.
//
// tinygo.org/x/bluetooth is the only Go BLE library covering Linux, macOS and
// Windows, and it also targets baremetal — so it drags in an ESP32 radio driver, a
// Raspberry Pi Pico W WiFi chip driver and two embedded network stacks. Thirteen
// dependencies in total, none of which belong in the dependency graph of a wallet.
//
// A nested module is excluded from the parent's `./...` patterns, so irmago's
// go.mod, its build, its release cross-compilation and its CI never see any of it.
// Build and run this tool from inside this directory.
module github.com/privacybydesign/irmago/eudi/proximity/bledriver

go 1.27

require (
	github.com/mdp/qrterminal v1.0.1
	github.com/privacybydesign/irmago v0.0.0
	tinygo.org/x/bluetooth v0.16.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/go-errors/errors v1.5.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-sql-driver/mysql v1.8.1 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jwx-go/es256k/v4 v4.0.4 // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/jwx/v4 v4.4.0 // indirect
	github.com/lestrrat-go/option/v3 v3.0.0-alpha1 // indirect
	github.com/mr-tron/base58 v1.1.3 // indirect
	github.com/privacybydesign/gabi v0.0.0-20221212095008-68a086907750 // indirect
	github.com/saltosystems/winrt-go v0.0.0-20260317170058-9c2fec580d96 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/soypat/cyw43439 v0.1.2-0.20260731160358-f2a6af121857 // indirect
	github.com/soypat/lneto v0.3.2 // indirect
	github.com/soypat/seqs v0.0.0-20260125140838-2c1c6b1bd69e // indirect
	github.com/stretchr/testify v1.12.0 // indirect
	github.com/tinygo-org/cbgo v0.0.4 // indirect
	github.com/tinygo-org/pio v0.3.0 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	github.com/veraison/go-cose v1.3.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/exp v0.0.0-20260727155853-b88d891fe743 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gorm.io/datatypes v1.2.7 // indirect
	gorm.io/driver/mysql v1.6.0 // indirect
	gorm.io/gorm v1.31.1 // indirect
	rsc.io/qr v0.2.0 // indirect
	tinygo.org/x/espradio v0.3.0 // indirect
)

replace github.com/privacybydesign/irmago => ../../..
