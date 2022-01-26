package irma

import (
	"context"
	"strings"
	"time"

	sseclient "github.com/sietseringers/go-sse"
)

const pollInterval = 1000 * time.Millisecond

func WaitStatus(transport *HTTPTransport, initialStatus ServerStatus, statuschan chan ServerStatus, errorchan chan error) {
	if err := subscribeSSE(transport, statuschan, errorchan, false); err != nil {
		go poll(transport, initialStatus, statuschan, errorchan)
	}
}

func WaitStatusChanged(transport *HTTPTransport, initialStatus ServerStatus, statuschan chan ServerStatus, errorchan chan error) {
	if err := subscribeSSE(transport, statuschan, errorchan, true); err != nil {
		go pollUntilChange(transport, initialStatus, statuschan, errorchan)
	}
}

// Start listening for server-sent events
func subscribeSSE(transport *HTTPTransport, statuschan chan ServerStatus, errorchan chan error, untilNextOnly bool) error {
	ctx, cancel := context.WithCancel(context.Background())

	events := make(chan *sseclient.Event)
	cancelled := false
	go func() {
		var status ServerStatus
		for {
			e := <-events
			if e == nil || e.Type == "open" {
				continue
			}
			newStatus := ServerStatus(strings.Trim(string(e.Data), `"`))
			if newStatus == status {
				continue
			}
			status = newStatus
			statuschan <- status
			if untilNextOnly || status.Finished() {
				errorchan <- nil
				cancelled = true
				cancel()
				return
			}
		}
	}()

	err := sseclient.Notify(ctx, transport.Server+"statusevents", true, events)
	// When sse was cancelled, an error is expected to be returned. The channels are already closed then.
	if cancelled {
		return nil
	}
	close(events)
	return err
}

// poll recursively polls the session status until a final status is received.
func poll(transport *HTTPTransport, initialStatus ServerStatus, statuschan chan ServerStatus, errorchan chan error) {
	status := initialStatus
	statuschanPolling := make(chan ServerStatus)
	errorchanPolling := make(chan error)
	go pollUntilChange(transport, status, statuschanPolling, errorchanPolling)
	for {
		select {
		case status = <-statuschanPolling:
			statuschan <- status
			if status.Finished() {
				errorchan <- nil
				return
			}
			break
		case err := <-errorchanPolling:
			if err != nil {
				errorchan <- err
				return
			}
			go pollUntilChange(transport, status, statuschanPolling, errorchanPolling)
		}
	}
}

func pollUntilChange(transport *HTTPTransport, initialStatus ServerStatus, statuschan chan ServerStatus, errorchan chan error) {
	// First we wait
	<-time.NewTimer(pollInterval).C

	// Get session status
	var s string
	if err := transport.Get("status", &s); err != nil {
		errorchan <- err
		return
	}
	status := ServerStatus(strings.Trim(s, `"`))

	// report if status changed
	if status != initialStatus {
		statuschan <- status
		errorchan <- nil
		return
	}

	go pollUntilChange(transport, status, statuschan, errorchan)
}
