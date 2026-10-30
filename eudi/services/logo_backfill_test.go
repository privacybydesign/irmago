package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type backfillTestStorage struct {
	db *gorm.DB
	fs filesystem.FileSystemStorage
}

// testLogoPNG is a logo the download accepts: an image, not just bytes.
var testLogoPNG = func() []byte {
	png, err := base64.StdEncoding.DecodeString(testPNGBase64)
	if err != nil {
		panic(err)
	}
	return png
}()

func (s *backfillTestStorage) Db() *gorm.DB                             { return s.db }
func (s *backfillTestStorage) FileSystem() filesystem.FileSystemStorage { return s.fs }
func (s *backfillTestStorage) Close() error                             { return nil }
func (s *backfillTestStorage) RemoveAll() error                         { return nil }

func newBackfillTestStorage(t *testing.T) *backfillTestStorage {
	t.Helper()
	return &backfillTestStorage{
		db: newTestHolderDB(t),
		fs: filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()),
	}
}

// Tests observe sweeps through a buffered channel of per-sweep cached counts
// rather than by waiting on Close, which cancels before it waits and so would
// cut short the very sweep under observation. Receiving blocks until the next
// sweep lands; go test's own timeout catches a sweep that never does.
func requireNoFurtherSweep(t *testing.T, ch chan int) {
	t.Helper()
	select {
	case cached := <-ch:
		t.Fatalf("an extra sweep ran and cached %d logo(s)", cached)
	case <-time.After(250 * time.Millisecond):
	}
}

// storeBackfillBatch stores one credential batch carrying an en and an nl logo
// for both the issuer and the credential, served from baseURL.
func storeBackfillBatch(t *testing.T, s *backfillTestStorage, baseURL string) {
	t.Helper()
	require.NoError(t, db.NewSdJwtVcStore(s.Db()).StoreBatch(backfillBatch(baseURL)))
}

// backfillBatch builds the batch storeBackfillBatch persists, so a test that
// needs a different logo layout can adjust it before storing.
func backfillBatch(baseURL string) *models.SdJwtVcBatch {
	iss := "https://issuer.example.com"
	return &models.SdJwtVcBatch{
		IssuerIdentifier:           iss,
		VerifiableCredentialType:   "https://vct.example.com/Test",
		Format:                     models.CredentialFormatSdJwtVc,
		Hash:                       "hash1",
		ProcessedSdJwtPayload:      datatypes.JSON(`{"sub":"user123"}`),
		IssuedAt:                   datatypes.NullTime{V: time.Now(), Valid: true},
		BatchSize:                  1,
		RemainingCount:             1,
		CredentialIssuerIdentifier: iss,
		IssuerDisplay: []models.IssuerMetadataDisplay{
			{Name: "Issuer EN", Locale: nullStr("en"), LogoURI: nullStr(baseURL + "/issuer-en.png")},
			{Name: "Issuer NL", Locale: nullStr("nl"), LogoURI: nullStr(baseURL + "/issuer-nl.png")},
		},
		CredentialMetadata: &models.CredentialMetadata{
			Display: []models.CredentialDisplay{
				{Name: "Cred EN", Locale: nullStr("en"), LogoURI: baseURL + "/cred-en.png"},
				{Name: "Cred NL", Locale: nullStr("nl"), LogoURI: baseURL + "/cred-nl.png"},
			},
		},
		Instances: []models.SdJwtVcBatchInstance{{RawCredential: []byte("raw")}},
	}
}

func TestBackfillLogos_FetchesOnlyMissingResolvingLogos(t *testing.T) {
	requests := map[string]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests[r.URL.Path]++
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(testLogoPNG)
	}))
	defer server.Close()

	s := newBackfillTestStorage(t)
	storeBackfillBatch(t, s, server.URL)

	// Pre-cache the nl issuer logo: the sweep must not re-download it.
	require.NoError(t, s.FileSystem().Issuers().LogoManager().Save(server.URL+"/issuer-nl.png", []byte("cached"), ""))

	added := backfillLogos(context.Background(), s, server.Client(), "nl", false)

	require.Equal(t, 1, added, "only the missing nl credential logo should be fetched")
	require.Equal(t, map[string]int{"/cred-nl.png": 1}, requests,
		"the en logos do not resolve for locale nl and the nl issuer logo is already cached")

	exists, err := s.FileSystem().Credentials().LogoManager().Exists(server.URL + "/cred-nl.png")
	require.NoError(t, err)
	require.True(t, exists, "fetched logo must land in the cache")

	// A second sweep with a warm cache downloads nothing.
	added = backfillLogos(context.Background(), s, server.Client(), "nl", false)
	require.Equal(t, 0, added)
	require.Equal(t, 1, requests["/cred-nl.png"])
}

// An issuer may serve one brand image as both its issuer and its credential
// logo. The two managers are separate directories, so the sweep must cache it in
// both — deduplicating downloads per manager rather than across the whole sweep.
func TestBackfillLogos_SharedUriIsCachedInBothManagers(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(testLogoPNG)
	}))
	defer server.Close()

	s := newBackfillTestStorage(t)

	// One image, used as both the nl issuer logo and the nl credential logo.
	shared := server.URL + "/brand.png"
	batch := backfillBatch(server.URL)
	for i := range batch.IssuerDisplay {
		if batch.IssuerDisplay[i].Locale.V == "nl" {
			batch.IssuerDisplay[i].LogoURI = nullStr(shared)
		}
	}
	for i := range batch.CredentialMetadata.Display {
		if batch.CredentialMetadata.Display[i].Locale.V == "nl" {
			batch.CredentialMetadata.Display[i].LogoURI = shared
		}
	}
	require.NoError(t, db.NewSdJwtVcStore(s.Db()).StoreBatch(batch))

	added := backfillLogos(context.Background(), s, server.Client(), "nl", false)

	require.Equal(t, 2, added, "the shared logo must be cached once per manager")
	require.Equal(t, 2, requests, "one download per manager that needs it")

	for _, m := range []filesystem.LogoManager{
		s.FileSystem().Issuers().LogoManager(),
		s.FileSystem().Credentials().LogoManager(),
	} {
		exists, err := m.Exists(shared)
		require.NoError(t, err)
		require.True(t, exists, "shared logo missing from one of the two managers")
	}

	// Warm cache: nothing further downloaded.
	require.Equal(t, 0, backfillLogos(context.Background(), s, server.Client(), "nl", false))
	require.Equal(t, 2, requests)
}

// Tapping through several languages must not queue up a sweep per tap. Only the
// language the user landed on is worth fetching logos for; the ones passed
// through on the way are already stale by the time a sweep could serve them.
func TestLogoBackfiller_SupersededRequestsCoalesceIntoOneSweep(t *testing.T) {
	var firstDownload sync.Once
	entered, release := make(chan struct{}), make(chan struct{})

	var mu sync.Mutex
	requests := map[string]int{}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold the first download open so the test can pile requests up behind
		// a sweep it knows is running.
		firstDownload.Do(func() {
			close(entered)
			<-release
		})

		mu.Lock()
		requests[r.URL.Path]++
		mu.Unlock()

		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(testLogoPNG)
	}))
	// server.Close waits for live handlers, so the blocked one must be let go
	// first — including on a failure path that never reaches the release below.
	releaseFirstDownload := sync.OnceFunc(func() { close(release) })
	defer server.Close()
	defer releaseFirstDownload()

	s := newBackfillTestStorage(t)
	storeBackfillBatch(t, s, server.URL)

	sweeps := make(chan int, 16) // a sweep must never block reporting its result
	b := NewLogoBackfiller(s, server.Client(), func(cached int) { sweeps <- cached })
	defer b.Close()

	b.Request("nl")
	<-entered // the nl sweep is now mid-download

	// Three more language changes while it runs. Only the last should survive.
	b.Request("nl")
	b.Request("de")
	b.Request("en")

	releaseFirstDownload()

	require.Equal(t, 2, <-sweeps, "the nl sweep caches both nl logos")
	require.Equal(t, 2, <-sweeps, "one further sweep, for the locale the user landed on")
	requireNoFurtherSweep(t, sweeps)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, map[string]int{
		"/issuer-nl.png": 1, "/cred-nl.png": 1,
		"/issuer-en.png": 1, "/cred-en.png": 1,
	}, requests, "no logo downloaded twice, and the de request never became a sweep of its own")
}

// Close is what the wallet calls on the way down, moments before it closes the
// database the sweep reads. It must not sit waiting out an HTTP timeout.
func TestLogoBackfiller_CloseAbortsAnInFlightDownload(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(testLogoPNG)
	}))
	defer server.Close()
	defer close(release)

	s := newBackfillTestStorage(t)
	storeBackfillBatch(t, s, server.URL)

	sweeps := make(chan int, 16) // a sweep must never block reporting its result
	b := NewLogoBackfiller(s, server.Client(), func(cached int) { sweeps <- cached })

	b.Request("nl")
	<-entered // the sweep is now blocked inside a download

	closed := make(chan struct{})
	go func() {
		b.Close()
		close(closed)
	}()

	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked on an in-flight download instead of cancelling it")
	}

	// The sweep was cut short, so it reports nothing: waking a UI that is going
	// away is the last thing a shutting-down wallet needs.
	requireNoFurtherSweep(t, sweeps)

	exists, err := s.FileSystem().Issuers().LogoManager().Exists(server.URL + "/issuer-nl.png")
	require.NoError(t, err)
	require.False(t, exists, "an aborted download must not leave a partial logo cached")
}

// A logo over plain http is fetched only in developer mode, as issuance only
// talks plain http then.
func TestBackfillLogos_PlainHTTPOnlyInDeveloperMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(testLogoPNG)
	}))
	defer server.Close()

	s := newBackfillTestStorage(t)
	storeBackfillBatch(t, s, server.URL)

	require.Equal(t, 0, backfillLogos(context.Background(), s, server.Client(), "nl", false))
	require.Equal(t, 2, backfillLogos(context.Background(), s, server.Client(), "nl", true),
		"the nl issuer and credential logos, over plain http")
}

// The backfiller sweeps with the developer mode setting it was last given.
func TestLogoBackfiller_SetAllowInsecureHttp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(testLogoPNG)
	}))
	defer server.Close()

	s := newBackfillTestStorage(t)
	storeBackfillBatch(t, s, server.URL)
	sweeps := make(chan int, 4)
	b := NewLogoBackfiller(s, server.Client(), func(cached int) { sweeps <- cached })
	defer b.Close()

	b.Request("nl")
	require.Equal(t, 0, <-sweeps, "plain http is refused outside developer mode")

	b.SetAllowInsecureHttp(true)
	b.Request("nl")
	require.Equal(t, 2, <-sweeps)
}

// storeBackfillBadge stores a VCDM credential whose subject has an Open Badges
// Image object per URL, as an Open Badges credential unless openBadges is
// false.
func storeBackfillBadge(t *testing.T, s *backfillTestStorage, hash string, openBadges bool, urls ...string) {
	t.Helper()
	types := []string{"https://www.w3.org/2018/credentials#VerifiableCredential"}
	if openBadges {
		types = append(types, vcdm.OpenBadgeCredentialType)
	}
	expandedTypes, err := json.Marshal(types)
	require.NoError(t, err)
	payload, err := json.Marshal(badgePayload(urls...))
	require.NoError(t, err)
	require.NoError(t, db.NewVcdmStore(s.Db()).StoreBatch(&models.VcdmBatch{
		TypeIdentity:     "https://www.w3.org/ns/credentials/v2 VerifiableCredential OpenBadgeCredential",
		IssuerIdentifier: "https://issuer.example.com",
		CredentialIssuer: "https://issuer.example.com",
		Format:           models.CredentialFormatSdJwtVcdm,
		Hash:             hash,
		ProcessedPayload: payload,
		ExpandedTypes:    expandedTypes,
		IssuedAt:         time.Now(),
		BatchSize:        1,
		RemainingCount:   1,
		Instances:        []models.VcdmBatchInstance{{RawCredential: []byte("raw")}},
	}))
}

func TestBackfillLogos_FillsInMissingClaimImages(t *testing.T) {
	server, requests := imageHost(t)
	s := newBackfillTestStorage(t)
	storeBackfillBadge(t, s, "badge", true, server.URL+"/a.png")

	require.Equal(t, 1, backfillLogos(context.Background(), s, server.Client(), "nl", false))
	exists, err := s.FileSystem().Credentials().LogoManager().Exists(server.URL + "/a.png")
	require.NoError(t, err)
	require.True(t, exists, "a claim image lands in the credential logo cache")

	require.Equal(t, 0, backfillLogos(context.Background(), s, server.Client(), "nl", false))
	require.Equal(t, 1, requests["/a.png"], "a cached image is not downloaded again")
}

func TestBackfillLogos_DoesNotReplaceACachedClaimImage(t *testing.T) {
	server, requests := imageHost(t)
	s := newBackfillTestStorage(t)
	storeBackfillBadge(t, s, "badge", true, server.URL+"/a.png")
	cached := append(slices.Clone(testLogoPNG), 0xFF)
	require.NoError(t, s.FileSystem().Credentials().LogoManager().Save(server.URL+"/a.png", cached, clientmodels.MimeTypePNG))

	require.Equal(t, 0, backfillLogos(context.Background(), s, server.Client(), "nl", false))
	require.Zero(t, requests["/a.png"])
	data, _, err := s.FileSystem().Credentials().LogoManager().Get(server.URL + "/a.png")
	require.NoError(t, err)
	require.Equal(t, cached, data)
}

func TestBackfillLogos_NoClaimImagesOutsideAnOpenBadge(t *testing.T) {
	server, requests := imageHost(t)
	s := newBackfillTestStorage(t)
	storeBackfillBadge(t, s, "not-a-badge", false, server.URL+"/a.png")

	require.Equal(t, 0, backfillLogos(context.Background(), s, server.Client(), "nl", false))
	require.Empty(t, requests)
}

// A failed download is tried again at the next sweep, also after a 404.
func TestBackfillLogos_RetriesAFailedClaimImage(t *testing.T) {
	server, requests := imageHost(t)
	s := newBackfillTestStorage(t)
	storeBackfillBadge(t, s, "badge", true, server.URL+"/missing.png")

	require.Equal(t, 0, backfillLogos(context.Background(), s, server.Client(), "nl", false))
	require.Equal(t, 0, backfillLogos(context.Background(), s, server.Client(), "nl", false))
	require.Equal(t, 2, requests["/missing.png"])
}

// One sweep handles at most maxClaimImageCredentialsPerSweep credentials that
// miss an image; the next sweep takes the rest. A credential whose images are
// all cached does not count.
func TestBackfillLogos_ClaimImageCredentialsPerSweep(t *testing.T) {
	server, _ := imageHost(t)
	s := newBackfillTestStorage(t)
	complete := server.URL + "/complete.png"
	require.NoError(t, s.FileSystem().Credentials().LogoManager().Save(complete, testLogoPNG, clientmodels.MimeTypePNG))
	for i := range 5 {
		storeBackfillBadge(t, s, "complete-"+strconv.Itoa(i), true, complete)
	}
	missing := maxClaimImageCredentialsPerSweep + 3
	for i := range missing {
		storeBackfillBadge(t, s, "badge-"+strconv.Itoa(i), true, server.URL+"/"+strconv.Itoa(i)+".png")
	}

	require.Equal(t, maxClaimImageCredentialsPerSweep, backfillLogos(context.Background(), s, server.Client(), "nl", false))
	require.Equal(t, 3, backfillLogos(context.Background(), s, server.Client(), "nl", false))
}

// The limits per credential hold in a sweep too: an image past the tenth
// stays out.
func TestBackfillLogos_ClaimImageLimitsPerCredential(t *testing.T) {
	server, requests := imageHost(t)
	s := newBackfillTestStorage(t)
	var urls []string
	for i := range 12 {
		urls = append(urls, server.URL+"/"+strconv.Itoa(i)+".png")
	}
	storeBackfillBadge(t, s, "badge", true, urls...)

	require.Equal(t, 10, backfillLogos(context.Background(), s, server.Client(), "nl", false))
	require.Zero(t, requests["/10.png"])
	require.Equal(t, 0, backfillLogos(context.Background(), s, server.Client(), "nl", false))
	require.Zero(t, requests["/10.png"], "an image a limit left out is not fetched later either")
}

func TestBackfillLogos_ClaimImagesStopWhenCancelled(t *testing.T) {
	server, requests := imageHost(t)
	s := newBackfillTestStorage(t)
	storeBackfillBadge(t, s, "badge", true, server.URL+"/a.png")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.Equal(t, 0, backfillLogos(ctx, s, server.Client(), "nl", false))
	require.Empty(t, requests)
}
