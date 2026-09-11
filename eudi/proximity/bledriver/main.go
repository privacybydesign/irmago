// Command bledriver is a desktop mdoc wallet: it conducts a real ISO/IEC 18013-5
// device retrieval transaction over this machine's Bluetooth radio.
//
// It exists so the Go proximity stack can be tested against an INDEPENDENT
// implementation — the Multipaz test app acting as reader on a phone — without
// writing a line of Kotlin or Swift first. Everything above the six BLE primitives
// is the same code the wallet will run on a phone.
//
//	go run .                 # mint credentials, show the QR, wait for a reader
//	go run . -v              # with every BLE operation logged
//
// Then, in Multipaz's test app: ISO mdoc Proximity Reading -> pick a docType ->
// "Request mdoc via QR Code" -> scan what this prints.
//
// # Which roles go where, and why it is not the other way round
//
// This wallet advertises mdoc central client mode, so it is the BLE central and
// the GATT client; the reader is the peripheral that advertises the service and
// hosts the characteristics. That is forced: Multipaz's BLE exists only for
// Android and iOS, and Windows supports the central role far better than
// peripheral. So the phone is the reader and the laptop is the wallet.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/mdp/qrterminal"

	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/proximity"
)

func main() {
	var (
		verbose     = flag.Bool("v", false, "log every BLE operation")
		scanTimeout = flag.Int("timeout", 60_000, "how long to wait for the reader to appear, in milliseconds")
		readerCA    = flag.String("reader-ca", "", "PEM file of reader CA certificates to trust (optional)")
		noIdent     = flag.Bool("no-ident", false, "skip the Ident check of 8.3.3.1.1.3 (it is a 'may')")
		showIACA    = flag.Bool("show-iaca", false, "print this wallet's IACA certificate and exit")
		scanDbg     = flag.Int("scan-debug", 0, "scan for N seconds printing every advertised service UUID, then exit")
		scanWant    = flag.String("scan-want", "", "with -scan-debug: the UUID to look for")
	)
	flag.Parse()

	if *scanDbg > 0 {
		if err := scanDebug(*scanDbg, *scanWant); err != nil {
			fmt.Fprintf(os.Stderr, "failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := run(*verbose, *scanTimeout, *readerCA, !*noIdent, *showIACA); err != nil {
		fmt.Fprintf(os.Stderr, "\nfailed: %v\n", err)
		os.Exit(1)
	}
}

func run(verbose bool, scanTimeout int, readerCA string, verifyIdent, showIACA bool) error {
	fmt.Println("mdoc wallet over BLE — ISO/IEC 18013-5 device retrieval")
	fmt.Println("=======================================================")

	w, err := newWallet()
	if err != nil {
		return err
	}

	if showIACA {
		return pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: w.IACACert().Raw})
	}

	fmt.Println("\ncredentials minted for this run:")
	fmt.Printf("  %-28s age_over_18, age_over_21, age_over_65\n", stdmdoc.AgeVerificationDocType)
	fmt.Printf("  %-28s the 11 mandatory elements of Table 5, plus age_over_18 and nationality\n", stdmdoc.MDLDocType)

	readers, err := readerTrust(readerCA)
	if err != nil {
		return err
	}

	session, err := proximity.NewSession(proximity.SessionConfig{
		Discloser:  w,
		DeviceKeys: w,
		Readers:    readers,
		Debugf: func(format string, args ...any) {
			fmt.Printf("  [iso] "+format+"\n", args...)
		},
	})
	if err != nil {
		return fmt.Errorf("start the session: %w", err)
	}

	explainTrust(readerCA)

	port := NewPort(nil, verbose)
	if err := port.Enable(); err != nil {
		return err
	}

	transport, err := proximity.NewBLETransport(session, port, verifyIdent)
	if err != nil {
		return err
	}
	// Wired after the transport exists, before anything can arrive: the port has
	// nowhere to deliver notifications until there is a transport to take them,
	// and nothing arrives until Run subscribes.
	port.notify = func(characteristic, data []byte) {
		if err := transport.OnNotification(characteristic, data); err != nil {
			fmt.Printf("  [!] notification rejected: %v\n", err)
		}
	}

	qr, err := session.EngagementQR()
	if err != nil {
		return err
	}
	serviceUUID, err := session.ServiceUUID()
	if err != nil {
		return err
	}

	fmt.Println("\nscan this with the reader (Multipaz: ISO mdoc Proximity Reading -> Request mdoc via QR Code):")
	fmt.Println()
	qrterminal.Generate(qr, qrterminal.L, os.Stdout)
	fmt.Printf("\n  engagement : %s\n", qr)
	fmt.Printf("  service    : %x\n", serviceUUID)
	fmt.Printf("\nwaiting up to %d ms for the reader to advertise that service...\n", scanTimeout)

	if err := transport.Run(scanTimeout); err != nil {
		return err
	}

	fmt.Println("\ntransaction finished cleanly.")
	return nil
}

// readerTrust builds the anchor set reader authentication (9.1.4) is checked
// against. An empty pool trusts nothing, which is the honest default here.
func readerTrust(pemFile string) (*stdmdoc.Verifier, error) {
	pool := x509.NewCertPool()
	if pemFile != "" {
		data, err := os.ReadFile(pemFile)
		if err != nil {
			return nil, fmt.Errorf("read reader CA file: %w", err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("no certificates found in %s", pemFile)
		}
	}
	return stdmdoc.NewVerifierFromPool(pool), nil
}

// explainTrust says up front what will happen, because the interesting outcome
// looks like a failure otherwise.
func explainTrust(readerCA string) {
	if readerCA != "" {
		fmt.Printf("\nreader trust: anchors loaded from %s\n", readerCA)
		return
	}
	fmt.Println("\nreader trust: NOTHING is trusted (no -reader-ca given).")
	fmt.Println("  Reader authentication (9.1.4) will therefore fail, and that is the point:")
	fmt.Printf("    %-28s -> nothing released, the reader gets a documentError.\n", stdmdoc.AgeVerificationDocType)
	fmt.Printf("    %-28s -> the 11 MANDATORY elements of Table 5 are released anyway,\n", stdmdoc.MDLDocType)
	fmt.Println("                                    because 7.2.1 forbids making reader authentication")
	fmt.Println("                                    a precondition for them; the optional ones are withheld.")
	fmt.Println("  So request the driving licence to see data flow, and the age credential to see the refusal.")
}
