package server

import (
	"github.com/privacybydesign/irmago"
	sseclient "github.com/sietseringers/go-sse"
	"strings"
	"time"
)

const pollInterval = 1000 * time.Millisecond

func WaitStatus(transport *irma.HTTPTransport, initialStatus Status, statuschan chan Status, errorchan chan error) {
	if err := subscribeSSE(transport, statuschan, errorchan); err != nil {
		go poll(transport, initialStatus, statuschan, errorchan)
	}
}

func WaitStatusChanged(transport *irma.HTTPTransport, initialStatus Status, statuschan chan Status, errorchan chan error) {
	if err := subscribeSSE(transport, statuschan, errorchan); err != nil {
		go pollUntilChange(transport, initialStatus, statuschan, errorchan)
	}
}

// Start listening for server-sent events
func subscribeSSE(transport *irma.HTTPTransport, statuschan chan Status, errorchan chan error) error {

	events := make(chan *sseclient.Event)
	go func() {
		for {
			if e := <-events; e != nil && e.Type != "open" {
				status := Status(strings.Trim(string(e.Data), `"`))
				statuschan <- status
				if status.Finished() {
					errorchan <- nil
					return
				}
			}
		}
	}()

	err := sseclient.Notify(nil, transport.Server+"statusevents", true, events)
	if err != nil {
		close(events)
	}
	return err
}

// poll recursively polls the session status until a final status is received.
func poll(transport *irma.HTTPTransport, initialStatus Status, statuschan chan Status, errorchan chan error) {
	go func() {
		status := initialStatus
		for {
			statuschanPolling := make(chan Status)
			errorchanPolling := make(chan error)
			go pollUntilChange(transport, status, statuschanPolling, errorchanPolling)
			select {
			case status = <-statuschanPolling:
				statuschan <- status
				if status.Finished() {
					errorchan <- nil
					return
				}
				break
			case err := <-errorchanPolling:
				errorchan <- err
				return
			}
		}
	}()
}

func pollUntilChange(transport *irma.HTTPTransport, initialStatus Status, statuschan chan Status, errorchan chan error) {
	// First we wait
	<-time.NewTimer(pollInterval).C

	// Get session status
	var s string
	if err := transport.Get("status", &s); err != nil {
		errorchan <- err
		return
	}
	status := Status(strings.Trim(s, `"`))

	// report if status changed
	if status != initialStatus {
		statuschan <- status
		errorchan <- nil
		return
	}

	go pollUntilChange(transport, status, statuschan, errorchan)
}