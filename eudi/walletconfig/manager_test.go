package walletconfig

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// world is one environment with its config CA, its config server, a clock and
// a store: everything a test wallet lives in.
type world struct {
	name   string
	signer *TestSigner
	server *TestServer
	clock  *TestClock
	store  *MemoryStore
	env    Environment
}

func newWorld(t *testing.T, name string) *world {
	t.Helper()
	signer := NewTestSigner(t)
	server := NewTestServer(t)
	return &world{
		name:   name,
		signer: signer,
		server: server,
		clock:  NewTestClock(time.Now().Truncate(time.Second)),
		store:  NewMemoryStore(),
		env:    signer.Environment(name, server.URL),
	}
}

// config is a valid config for this world, issued at the clock's current time.
func (w *world) config(version uint64) *Config {
	return NewTestConfig(w.name, version, w.clock.Now())
}

// publish makes the server serve config, signed.
func (w *world) publish(t *testing.T, config *Config) []byte {
	t.Helper()
	raw := w.signer.Sign(t, config)
	w.server.SetBody(raw)
	return raw
}

// bundle writes config, signed, as the release's bundled asset.
func (w *world) bundle(t *testing.T, config *Config) {
	t.Helper()
	path := filepath.Join(t.TempDir(), w.name+".jws")
	require.NoError(t, os.WriteFile(path, w.signer.Sign(t, config), 0o600))
	w.env.BundledConfigPath = path
}

// stored puts config, signed, in the store as if fetched earlier.
func (w *world) stored(t *testing.T, config *Config) []byte {
	t.Helper()
	raw := w.signer.Sign(t, config)
	require.NoError(t, w.store.Put(w.name, raw))
	return raw
}

func (w *world) options() Options {
	return Options{
		Environments: []Environment{w.env},
		Active:       w.name,
		Store:        w.store,
		HTTPClient:   w.server.Client(),
		Now:          w.clock.Now,
	}
}

func (w *world) manager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(w.options())
	require.NoError(t, err)
	return m
}

// withSecondEntity is config with one more entity, so its trust content differs.
func withSecondEntity(config *Config) *Config {
	config.TrustedEntities = append(config.TrustedEntities, TrustedEntity{
		ID:         "second",
		Name:       clientmodels.TranslatedString{"en": "Second"},
		Roles:      []Role{RoleVerifier},
		TrustLevel: clientmodels.TrustLevel_Medium,
		Handles:    []Handle{{Type: HandleTypeDID, DID: "did:web:second.example"}},
	})
	return config
}

func TestNewManager_RejectsAMisconfiguredWorld(t *testing.T) {
	w := newWorld(t, "test")
	cases := []struct {
		name string
		opts func(*Options)
		want string
	}{
		{"no environments", func(o *Options) { o.Environments = nil }, "no environments"},
		{"unknown active", func(o *Options) { o.Active = "production" }, `active environment "production"`},
		{"empty name", func(o *Options) { o.Environments[0].Name = "" }, "Name is empty"},
		{"duplicate name", func(o *Options) { o.Environments = append(o.Environments, o.Environments[0]) }, "used by another environment"},
		{"missing root", func(o *Options) { o.Environments[0].SigningRoot = nil }, "SigningRoot is nil"},
		{"relative URL", func(o *Options) { o.Environments[0].ConfigURL = "/wallet-config/v1/" }, "not an absolute URL"},
		{"empty URL", func(o *Options) { o.Environments[0].ConfigURL = "" }, "not an absolute URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := w.options()
			tc.opts(&opts)
			_, err := NewManager(opts)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestManager_StartsEmptyWithNothingBundledOrStored(t *testing.T) {
	w := newWorld(t, "test")
	m := w.manager(t)

	snapshot := m.Snapshot()
	require.Equal(t, "test", snapshot.Environment.Name)
	require.Nil(t, snapshot.Config)
	require.Equal(t, Absent, snapshot.Freshness)
	require.Equal(t, 0, w.server.Hits(), "construction never touches the network")
}

func TestManager_LoadsTheBundledConfigOnFirstRunAndPersistsIt(t *testing.T) {
	w := newWorld(t, "test")
	w.bundle(t, w.config(1))
	m := w.manager(t)

	snapshot := m.Snapshot()
	require.NotNil(t, snapshot.Config)
	require.Equal(t, uint64(1), snapshot.Config.Version)
	require.Equal(t, Fresh, snapshot.Freshness)

	stored, ok := w.store.Get("test")
	require.True(t, ok, "the bundled config becomes the stored rollback floor")
	bundled, err := os.ReadFile(w.env.BundledConfigPath)
	require.NoError(t, err)
	require.Equal(t, bundled, stored)
}

func TestManager_LoadsTheStoredConfig(t *testing.T) {
	w := newWorld(t, "test")
	w.stored(t, w.config(2))
	m := w.manager(t)

	require.Equal(t, uint64(2), m.Snapshot().Config.Version)
}

func TestManager_PrefersTheNewerOfBundledAndStored(t *testing.T) {
	t.Run("stored is newer", func(t *testing.T) {
		w := newWorld(t, "test")
		w.bundle(t, w.config(1))
		storedRaw := w.stored(t, w.config(2))
		m := w.manager(t)

		require.Equal(t, uint64(2), m.Snapshot().Config.Version)
		got, _ := w.store.Get("test")
		require.Equal(t, storedRaw, got, "the store is left alone")
	})
	t.Run("bundled is newer", func(t *testing.T) {
		w := newWorld(t, "test")
		w.bundle(t, w.config(3))
		w.stored(t, w.config(2))
		m := w.manager(t)

		require.Equal(t, uint64(3), m.Snapshot().Config.Version)
		got, _ := w.store.Get("test")
		bundled, _ := os.ReadFile(w.env.BundledConfigPath)
		require.Equal(t, bundled, got, "an app update that ships a newer config raises the floor")
	})
}

// A stored document is re-verified against the root in force when read, so one
// that no longer verifies — here, one signed under another root — is dropped.
func TestManager_DropsAStoredConfigThatNoLongerVerifies(t *testing.T) {
	t.Run("falls back to the bundled config", func(t *testing.T) {
		w := newWorld(t, "test")
		require.NoError(t, w.store.Put("test", NewTestSigner(t).Sign(t, w.config(5))))
		w.bundle(t, w.config(1))
		m := w.manager(t)
		require.Equal(t, uint64(1), m.Snapshot().Config.Version)
	})
	t.Run("or starts empty", func(t *testing.T) {
		w := newWorld(t, "test")
		require.NoError(t, w.store.Put("test", NewTestSigner(t).Sign(t, w.config(5))))
		m := w.manager(t)
		require.Nil(t, m.Snapshot().Config)
	})
}

func TestManager_DropsABundledConfigThatDoesNotVerify(t *testing.T) {
	w := newWorld(t, "test")
	path := filepath.Join(t.TempDir(), "bundled.jws")
	require.NoError(t, os.WriteFile(path, w.signer.Sign(t, NewTestConfig("production", 1, w.clock.Now())), 0o600))
	w.env.BundledConfigPath = path

	m := w.manager(t)
	require.Nil(t, m.Snapshot().Config, "a bundle for another environment anchors nothing")

	w.env.BundledConfigPath = filepath.Join(t.TempDir(), "missing.jws")
	m = w.manager(t)
	require.Nil(t, m.Snapshot().Config, "a missing bundle is a warning, not a failure")
}

func TestManager_Refresh_AdoptsANewerVersion(t *testing.T) {
	w := newWorld(t, "test")
	w.bundle(t, w.config(1))
	m := w.manager(t)
	published := w.publish(t, withSecondEntity(w.config(2)))

	changed, err := m.Refresh(context.Background())
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, uint64(2), m.Snapshot().Config.Version)
	require.Len(t, m.Snapshot().Config.TrustedEntities, 2)

	stored, _ := w.store.Get("test")
	require.Equal(t, published, stored)
}

func TestManager_Refresh_FillsAnEmptyWallet(t *testing.T) {
	w := newWorld(t, "test")
	m := w.manager(t)
	w.publish(t, w.config(1))

	changed, err := m.Refresh(context.Background())
	require.NoError(t, err)
	require.True(t, changed, "from nothing to something is a change")
	require.Equal(t, uint64(1), m.Snapshot().Config.Version)
}

func TestManager_Refresh_RefusesARollback(t *testing.T) {
	w := newWorld(t, "test")
	held := w.stored(t, w.config(2))
	m := w.manager(t)
	w.publish(t, w.config(1))

	changed, err := m.Refresh(context.Background())
	require.ErrorContains(t, err, "version 1")
	require.ErrorContains(t, err, "rolls back the held version 2")
	require.False(t, changed)
	require.Equal(t, uint64(2), m.Snapshot().Config.Version)
	stored, _ := w.store.Get("test")
	require.Equal(t, held, stored)
}

func TestManager_Refresh_TheSameIssueIsIdempotent(t *testing.T) {
	w := newWorld(t, "test")
	held := w.stored(t, w.config(1))
	m := w.manager(t)
	w.server.SetBody(held)

	changed, err := m.Refresh(context.Background())
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, 1, w.server.Hits())
}

// The publisher re-signs on a cadence so a config never goes stale while its
// content stands. A re-signing of the same version with a later issue date is
// adopted — the new next_update matters — but says nothing new to the app.
func TestManager_Refresh_AdoptsAReSigningOfTheSameVersionSilently(t *testing.T) {
	w := newWorld(t, "test")
	w.stored(t, w.config(1))
	m := w.manager(t)

	w.clock.Advance(time.Hour)
	reissued := w.publish(t, w.config(1))

	changed, err := m.Refresh(context.Background())
	require.NoError(t, err)
	require.False(t, changed)
	require.True(t, m.Snapshot().Config.IssuedAt.Equal(w.clock.Now()), "the later issue is held")
	stored, _ := w.store.Get("test")
	require.Equal(t, reissued, stored)
}

func TestManager_Refresh_RefusesAnEarlierIssueOfTheSameVersion(t *testing.T) {
	w := newWorld(t, "test")
	w.clock.Advance(time.Hour)
	w.stored(t, w.config(1))
	m := w.manager(t)

	w.clock.Advance(-time.Hour)
	w.publish(t, w.config(1))

	_, err := m.Refresh(context.Background())
	require.ErrorContains(t, err, "rolls back")
}

func TestManager_Refresh_KeepsTheHeldConfigWhenTheFetchFails(t *testing.T) {
	w := newWorld(t, "test")
	w.stored(t, w.config(1))
	m := w.manager(t)

	w.server.SetStatus(http.StatusInternalServerError)
	changed, err := m.Refresh(context.Background())
	require.ErrorContains(t, err, "non-2xx")
	require.False(t, changed)
	require.Equal(t, uint64(1), m.Snapshot().Config.Version)

	w.server.SetBody([]byte("not a jws"))
	_, err = m.Refresh(context.Background())
	require.ErrorContains(t, err, "parse JWS")
	require.Equal(t, uint64(1), m.Snapshot().Config.Version)
}

func TestManager_Refresh_RefusesAConfigForAnotherEnvironment(t *testing.T) {
	w := newWorld(t, "staging")
	m := w.manager(t)
	w.publish(t, NewTestConfig("production", 1, w.clock.Now()))

	_, err := m.Refresh(context.Background())
	require.ErrorContains(t, err, `for environment "production", expected "staging"`)
	require.Nil(t, m.Snapshot().Config)
}

// Each environment pins its own root; a config for staging signed by the
// production CA is not staging's config, whatever its `environment` says.
func TestManager_Refresh_RefusesAConfigSignedUnderAnotherEnvironmentsRoot(t *testing.T) {
	staging := newWorld(t, "staging")
	production := NewTestSigner(t)
	staging.server.SetBody(production.Sign(t, staging.config(1)))
	m := staging.manager(t)

	_, err := m.Refresh(context.Background())
	require.ErrorContains(t, err, "unknown authority")
	require.Nil(t, m.Snapshot().Config)
}

func TestManager_Refresh_ReportsNoChangeForAReissueWithTheSameContent(t *testing.T) {
	w := newWorld(t, "test")
	w.stored(t, w.config(1))
	m := w.manager(t)
	w.clock.Advance(time.Hour)
	w.publish(t, w.config(2))

	changed, err := m.Refresh(context.Background())
	require.NoError(t, err)
	require.False(t, changed, "a version bump that says the same thing about the same parties redraws nothing")
	require.Equal(t, uint64(2), m.Snapshot().Config.Version)
}

// An expired config had stopped conferring list trust. A re-issue with the same
// entries brings every listing back, which the app must hear about.
func TestManager_Refresh_ReportsAChangeWhenAnExpiredConfigIsRevived(t *testing.T) {
	w := newWorld(t, "test")
	w.stored(t, w.config(1))
	m := w.manager(t)

	w.clock.Advance(40 * 24 * time.Hour)
	require.Equal(t, Expired, m.Snapshot().Freshness)
	w.publish(t, w.config(2))

	changed, err := m.Refresh(context.Background())
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, Fresh, m.Snapshot().Freshness)
}

func TestManager_Snapshot_ReportsFreshnessAgainstTheClock(t *testing.T) {
	w := newWorld(t, "test")
	w.stored(t, w.config(1))
	m := w.manager(t)

	require.Equal(t, Fresh, m.Snapshot().Freshness)
	w.clock.Advance(30 * 24 * time.Hour)
	require.Equal(t, Stale, m.Snapshot().Freshness)
	w.clock.Advance(7 * 24 * time.Hour)
	require.Equal(t, Expired, m.Snapshot().Freshness)
}

func TestManager_RefreshIfDue_ThrottlesWhileFresh(t *testing.T) {
	w := newWorld(t, "test")
	held := w.stored(t, w.config(1))
	w.server.SetBody(held)
	m := w.manager(t)

	_, err := m.RefreshIfDue(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, w.server.Hits(), "never attempted before, so due")

	_, err = m.RefreshIfDue(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, w.server.Hits(), "fresh and attempted a moment ago, so not due")

	w.clock.Advance(DefaultRefreshInterval)
	_, err = m.RefreshIfDue(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, w.server.Hits(), "the interval has passed")
}

func TestManager_RefreshIfDue_HonoursAConfiguredInterval(t *testing.T) {
	w := newWorld(t, "test")
	held := w.stored(t, w.config(1))
	w.server.SetBody(held)
	opts := w.options()
	opts.RefreshInterval = 5 * time.Minute
	m, err := NewManager(opts)
	require.NoError(t, err)

	_, _ = m.RefreshIfDue(context.Background())
	w.clock.Advance(4 * time.Minute)
	_, _ = m.RefreshIfDue(context.Background())
	require.Equal(t, 1, w.server.Hits())
	w.clock.Advance(time.Minute)
	_, _ = m.RefreshIfDue(context.Background())
	require.Equal(t, 2, w.server.Hits())
}

// The throttle also covers failed attempts: a fresh config and a broken server
// mean one attempt per interval, not one per foreground event.
func TestManager_RefreshIfDue_ThrottlesFailedAttemptsToo(t *testing.T) {
	w := newWorld(t, "test")
	w.stored(t, w.config(1))
	w.server.SetStatus(http.StatusInternalServerError)
	m := w.manager(t)

	_, err := m.RefreshIfDue(context.Background())
	require.Error(t, err)
	_, err = m.RefreshIfDue(context.Background())
	require.NoError(t, err, "skipped, not failed")
	require.Equal(t, 1, w.server.Hits())
}

func TestManager_RefreshIfDue_FetchesEagerlyWhenStale(t *testing.T) {
	w := newWorld(t, "test")
	w.stored(t, w.config(1))
	w.server.SetStatus(http.StatusInternalServerError)
	m := w.manager(t)
	w.clock.Advance(30*24*time.Hour + time.Hour)
	require.Equal(t, Stale, m.Snapshot().Freshness)

	for range 3 {
		_, err := m.RefreshIfDue(context.Background())
		require.Error(t, err)
	}
	require.Equal(t, 3, w.server.Hits(), "past next_update the throttle does not apply")
}

func TestManager_RefreshIfDue_FetchesWheneverNothingIsHeld(t *testing.T) {
	w := newWorld(t, "test")
	w.server.SetStatus(http.StatusNotFound)
	m := w.manager(t)

	for range 3 {
		_, err := m.RefreshIfDue(context.Background())
		require.Error(t, err)
	}
	require.Equal(t, 3, w.server.Hits())
}

func TestManager_ConcurrentRefreshIfDueFetchesOnce(t *testing.T) {
	w := newWorld(t, "test")
	held := w.stored(t, w.config(1))
	w.server.SetBody(held)
	m := w.manager(t)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_, err := m.RefreshIfDue(context.Background())
			require.NoError(t, err)
		})
	}
	wg.Wait()
	require.Equal(t, 1, w.server.Hits())
}

func TestManager_Snapshot_NeverBlocksOnARefreshInFlight(t *testing.T) {
	w := newWorld(t, "test")
	w.stored(t, w.config(1))
	release := make(chan struct{})
	hanging := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(hanging.Close)
	w.env.ConfigURL = hanging.URL
	m := w.manager(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = m.Refresh(context.Background())
	}()

	snapshot := make(chan Snapshot, 1)
	go func() { snapshot <- m.Snapshot() }()
	select {
	case s := <-snapshot:
		require.Equal(t, uint64(1), s.Config.Version)
	case <-time.After(2 * time.Second):
		t.Fatal("Snapshot blocked behind a download")
	}

	close(release)
	<-done
}

// A failing store never costs the wallet a good config.
func TestManager_Refresh_UsesAConfigTheStoreCannotPersist(t *testing.T) {
	w := newWorld(t, "test")
	opts := w.options()
	opts.Store = failingStore{}
	m, err := NewManager(opts)
	require.NoError(t, err)
	w.publish(t, w.config(1))

	changed, err := m.Refresh(context.Background())
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, uint64(1), m.Snapshot().Config.Version)
}

type failingStore struct{}

func (failingStore) Get(string) ([]byte, bool) { return nil, false }
func (failingStore) Put(string, []byte) error  { return errors.New("disk full") }

func TestManager_WithoutAStoreKeepsConfigsInMemoryOnly(t *testing.T) {
	w := newWorld(t, "test")
	opts := w.options()
	opts.Store = nil
	m, err := NewManager(opts)
	require.NoError(t, err)
	w.publish(t, w.config(1))

	_, err = m.Refresh(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(1), m.Snapshot().Config.Version)

	again, err := NewManager(opts)
	require.NoError(t, err)
	require.Nil(t, again.Snapshot().Config, "a new manager starts over")
}

// twoWorlds is a wallet build that knows production and staging, each with its
// own config CA, server and stored config.
func twoWorlds(t *testing.T) (*world, *world, *Manager) {
	t.Helper()
	production := newWorld(t, "production")
	staging := newWorld(t, "staging")
	staging.clock, staging.store = production.clock, production.store
	production.stored(t, production.config(10))
	staging.stored(t, staging.config(20))

	m, err := NewManager(Options{
		Environments: []Environment{production.env, staging.env},
		Active:       "production",
		Store:        production.store,
		HTTPClient:   production.server.Client(),
		Now:          production.clock.Now,
	})
	require.NoError(t, err)
	return production, staging, m
}

func TestManager_SwitchEnvironment_LoadsThatEnvironmentsConfig(t *testing.T) {
	_, _, m := twoWorlds(t)
	require.Equal(t, "production", m.Snapshot().Environment.Name)
	require.Equal(t, uint64(10), m.Snapshot().Config.Version)

	require.NoError(t, m.SwitchEnvironment("staging"))
	snapshot := m.Snapshot()
	require.Equal(t, "staging", snapshot.Environment.Name)
	require.Equal(t, "staging", snapshot.Config.Environment)
	require.Equal(t, uint64(20), snapshot.Config.Version)

	require.NoError(t, m.SwitchEnvironment("production"))
	require.Equal(t, uint64(10), m.Snapshot().Config.Version)
}

// Staging uses staging anchors only. A document under the production root filed
// as staging's — which only a tampered store could produce — anchors nothing.
func TestManager_SwitchEnvironment_NeverMixesRoots(t *testing.T) {
	production, staging, m := twoWorlds(t)
	require.NoError(t, staging.store.Put("staging", production.signer.Sign(t, staging.config(21))))

	require.NoError(t, m.SwitchEnvironment("staging"))
	require.Equal(t, "staging", m.Snapshot().Environment.Name)
	require.Nil(t, m.Snapshot().Config)
}

func TestManager_SwitchEnvironment_RejectsAnUnknownName(t *testing.T) {
	_, _, m := twoWorlds(t)
	require.ErrorContains(t, m.SwitchEnvironment("demo"), `"demo" is not one of the configured environments`)
	require.Equal(t, "production", m.Snapshot().Environment.Name)
}

func TestManager_SwitchEnvironment_ToTheActiveOneIsANoOp(t *testing.T) {
	_, _, m := twoWorlds(t)
	before := m.Snapshot()
	require.NoError(t, m.SwitchEnvironment("production"))
	require.Same(t, before.Config, m.Snapshot().Config)
}

// The switch is a fetch trigger: what the wallet has for the new environment may
// be old, and the throttle from the previous environment must not stand in the
// way.
func TestManager_SwitchEnvironment_ResetsTheThrottle(t *testing.T) {
	production, staging, m := twoWorlds(t)
	production.server.SetBody(production.signer.Sign(t, production.config(10)))
	staging.server.SetBody(staging.signer.Sign(t, staging.config(20)))

	_, err := m.RefreshIfDue(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, production.server.Hits())

	require.NoError(t, m.SwitchEnvironment("staging"))
	_, err = m.RefreshIfDue(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, staging.server.Hits())
	require.Equal(t, 1, production.server.Hits())
}

func TestManager_Refresh_DiscardsAConfigFetchedForAnEnvironmentSwitchedAway(t *testing.T) {
	production, _, m := twoWorlds(t)
	started, release := make(chan struct{}), make(chan struct{})
	body := production.signer.Sign(t, production.config(11))
	hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = w.Write(body)
	}))
	t.Cleanup(hanging.Close)
	// Rebuild with production pointed at the hanging server.
	production.env.ConfigURL = hanging.URL
	m, err := NewManager(Options{
		Environments: []Environment{production.env, {Name: "staging", ConfigURL: "https://unused.example/", SigningRoot: production.signer.Root}},
		Active:       "production",
		Store:        production.store,
		Now:          production.clock.Now,
	})
	require.NoError(t, err)

	result := make(chan error, 1)
	go func() {
		_, err := m.Refresh(context.Background())
		result <- err
	}()
	<-started
	require.NoError(t, m.SwitchEnvironment("staging"))
	close(release)

	require.ErrorContains(t, <-result, "environment switched")
	require.Equal(t, "staging", m.Snapshot().Environment.Name)
	require.Nil(t, m.Snapshot().Config)

	require.NoError(t, m.SwitchEnvironment("production"))
	require.Equal(t, uint64(10), m.Snapshot().Config.Version, "the late arrival did not reach the store either")
}
