package services

import (
	"context"
	"net/http"
	"sync"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/internal/helpers"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
)

// LogoBackfiller is a handle on the goroutine that keeps the on-disk logo cache
// in step with the UI language.
//
// The wallet downloads only the logos that resolve for the locale in use, so
// switching language leaves stored credentials pointing at logos that were
// never fetched. Owners Request a sweep on startup and on every locale change,
// and Close the backfiller before the storage it reads.
//
// One worker, one pending locale. Sweeps therefore never overlap, and a burst
// of language changes collapses into a sweep for the language the user landed
// on rather than one per tap.
type LogoBackfiller struct {
	mu        sync.Mutex
	requested string        // locale for the next sweep; a newer one overwrites it
	wake      chan struct{} // cap 1, sent to non-blockingly, so Request never waits

	stop    context.CancelFunc
	stopped chan struct{}
}

// NewLogoBackfiller starts the worker. onSweepDone reports how many logos a
// sweep cached, so the owner can decide whether that is worth waking the UI
// for; it runs on the worker goroutine, and not at all for a sweep cut short
// by Close.
func NewLogoBackfiller(s storage.Storage, httpClient *http.Client, onSweepDone func(cached int)) *LogoBackfiller {
	ctx, cancel := context.WithCancel(context.Background())
	b := &LogoBackfiller{
		wake:    make(chan struct{}, 1),
		stop:    cancel,
		stopped: make(chan struct{}),
	}

	go func() {
		defer close(b.stopped)
		for {
			select {
			case <-ctx.Done():
				return
			case <-b.wake:
			}
			if ctx.Err() != nil {
				// Close landed at the same moment as a request; select takes a
				// ready case at random, so cancellation needs saying twice.
				return
			}

			b.mu.Lock()
			locale := b.requested
			b.requested = ""
			b.mu.Unlock()
			if locale == "" {
				continue // leftover wake from a request already taken with a newer one
			}

			cached := backfillLogos(ctx, s, httpClient, locale)

			// A cut-short sweep reports nothing: the owner is shutting down, and
			// the last thing it needs is a callback into a UI that is going away.
			if ctx.Err() == nil && onSweepDone != nil {
				onSweepDone(cached)
			}
		}
	}()

	return b
}

// Request asks for a sweep of the logos that resolve for locale. It returns
// immediately — no caller of this may block on the network — and supersedes any
// sweep not yet started. Requests after Close are ignored.
func (b *LogoBackfiller) Request(locale string) {
	b.mu.Lock()
	b.requested = locale
	b.mu.Unlock()

	select {
	case b.wake <- struct{}{}:
	default: // Already signalled; the worker will read the newer locale.
	}
}

// Close stops the worker and waits for a running sweep to unwind. Call it
// before closing the storage the sweeps read and write, so a sweep cannot
// outlive the database underneath it. Idempotent.
func (b *LogoBackfiller) Close() {
	b.stop()
	<-b.stopped
}

// backfillLogos downloads the logos that resolve for the given locale but are
// missing from the on-disk cache, for every stored credential batch. Returns
// the number of logos newly cached.
//
// Cancelling ctx aborts the sweep: the download in flight returns immediately
// and the loop stops at the next batch.
func backfillLogos(ctx context.Context, s storage.Storage, httpClient *http.Client, locale string) int {
	batches, err := db.NewCredentialStore(s.Db()).GetCredentialBatchList()
	if err != nil {
		eudi.Logger.Warnf("logo backfill: failed to list credential batches: %v", err)
		return 0
	}

	credentialLogos := s.FileSystem().Credentials().LogoManager()
	issuerLogos := s.FileSystem().Issuers().LogoManager()

	// Credentials from one issuer share an issuer logo, so without this the
	// sweep would re-check the same URI once per batch — and, when the download
	// fails, re-request a dead URL once per batch.
	seen := map[string]struct{}{}
	fetchOnce := func(manager filesystem.LogoManager, uri string) int {
		if _, done := seen[uri]; done {
			return 0
		}
		seen[uri] = struct{}{}
		return FetchLogoIfMissing(ctx, manager, httpClient, uri)
	}

	added := 0
	for _, batch := range batches {
		if ctx.Err() != nil {
			break
		}
		added += fetchOnce(issuerLogos, clientmodels.Resolve(IssuerLogoURIsByLanguage(batch.IssuerDisplay), locale))
		if batch.CredentialMetadata != nil {
			added += fetchOnce(credentialLogos, clientmodels.Resolve(CredentialLogoURIsByLanguage(batch.CredentialMetadata.Display), locale))
		}
	}
	return added
}

// FetchLogoIfMissing downloads and caches a logo unless the URI is empty or
// the logo is already cached. Returns 1 when a logo was newly cached, 0
// otherwise. An Exists error is treated as a miss: a redundant download beats
// permanently skipping the logo.
func FetchLogoIfMissing(ctx context.Context, manager filesystem.LogoManager, httpClient *http.Client, uri string) int {
	if uri == "" {
		return 0
	}
	if exists, err := manager.Exists(uri); err == nil && exists {
		return 0
	}
	data, mimeType, err := helpers.DownloadRemoteImage(ctx, httpClient, uri)
	if err != nil {
		eudi.Logger.Warnf("failed to download logo from %q: %v", uri, err)
		return 0
	}
	if err := manager.Save(uri, data, mimeType); err != nil {
		eudi.Logger.Warnf("failed to cache logo from %q: %v", uri, err)
		return 0
	}
	return 1
}
