package main

import (
	"fmt"
	"strings"
	"time"

	"tinygo.org/x/bluetooth"
)

// scanDebug prints every advertisement and the service UUIDs it carries.
//
// It exists because "no reader advertising <uuid>" has several possible causes
// that look identical from the outside: the reader is not advertising at all, it
// is advertising a different UUID than the engagement named, or it is advertising
// the right one somewhere this platform's scanner does not surface (a scan
// response rather than the advertisement, for instance). Printing what is
// actually on the air separates them in one run.
func scanDebug(seconds int, want string) error {
	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return fmt.Errorf("enable the adapter: %w", err)
	}

	fmt.Printf("listening for %ds; every advertisement carrying ANY service UUID is printed\n", seconds)
	if want != "" {
		fmt.Printf("looking for: %s\n", want)
	}
	fmt.Println()

	seen := map[string]bool{}
	withUUIDs := 0
	matched := false

	timer := time.AfterFunc(time.Duration(seconds)*time.Second, func() {
		_ = adapter.StopScan()
	})
	defer timer.Stop()

	err := adapter.Scan(func(a *bluetooth.Adapter, result bluetooth.ScanResult) {
		uuids := result.AdvertisementPayload.ServiceUUIDs()
		if len(uuids) == 0 {
			return // the vast majority: privacy beacons with nothing to identify
		}
		key := result.Address.String()
		if seen[key] {
			return
		}
		seen[key] = true
		withUUIDs++

		var ids []string
		for _, u := range uuids {
			s := u.String()
			ids = append(ids, s)
			if want != "" && strings.EqualFold(s, want) {
				matched = true
			}
		}
		name := result.AdvertisementPayload.LocalName()
		if name == "" {
			name = "(no name)"
		}
		fmt.Printf("  %-20s rssi=%-5d %-22s %s\n", key, result.RSSI, name, strings.Join(ids, " "))
	})
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	fmt.Printf("\n%d device(s) advertised a service UUID\n", withUUIDs)
	switch {
	case want == "":
	case matched:
		fmt.Println("MATCH — the reader is advertising the expected service.")
	default:
		fmt.Println("NO MATCH — nothing on the air carried that UUID.")
		fmt.Println("  If the reader says ADVERTISING, it is either advertising a different")
		fmt.Println("  UUID than the engagement named, or putting it somewhere this scanner")
		fmt.Println("  does not read (e.g. a scan response rather than the advertisement).")
	}
	return nil
}
