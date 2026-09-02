package walletconfig

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// DefaultRefreshInterval is how long RefreshIfDue leaves a fresh config alone
// after the last attempt: the throttle for app-start and foreground triggers.
const DefaultRefreshInterval = time.Hour

// Options is what a Manager needs. Only Environments and Active have no default.
type Options struct {
	// Environments is every world this build can live in. Validated by
	// ValidateEnvironments.
	Environments []Environment

	// Active names the environment to start in. Must be one of Environments.
	Active string

	// Store persists verified configs. Nil keeps them in memory only, so the
	// wallet starts from its bundled config every time.
	Store Store

	// HTTPClient downloads configs. Nil falls back to http.DefaultClient, bounded
	// by the package's own fetch timeout.
	HTTPClient *http.Client

	// Now is the clock. Nil falls back to time.Now.
	Now func() time.Time

	// Logger is where fail-soft notes go. Nil discards them.
	Logger *logrus.Logger

	// RefreshInterval is the throttle RefreshIfDue applies to a fresh config.
	// Zero means DefaultRefreshInterval.
	RefreshInterval time.Duration
}

// Manager holds the wallet's current verified config and keeps it current.
//
// It never fetches on the read path: [Manager.Snapshot] returns what it already
// holds, immediately, so a session is never slowed down or failed by the state
// of the config server. Downloading is [Manager.Refresh]'s job.
//
// A Manager is safe for concurrent use.
type Manager struct {
	environments    map[string]Environment
	store           Store
	httpClient      *http.Client
	now             func() time.Time
	logger          *logrus.Logger
	refreshInterval time.Duration

	// refreshMu serializes downloads, so two triggers landing together — the
	// ticker and a foreground event — fetch once.
	refreshMu sync.Mutex

	mu     sync.RWMutex
	active Environment
	// held is the config in force for the active environment, or nil when the
	// wallet has none it can verify. Reset on an environment switch.
	held *Verified
	// lastAttempt is when the active environment was last fetched, successfully
	// or not, for the throttle.
	lastAttempt time.Time
}

// Snapshot is what a session evaluates against: the active environment and the
// config held for it, pinned at one moment. Config is nil when the wallet holds
// none that verifies; consumers must treat it as read-only.
type Snapshot struct {
	Environment Environment
	Config      *Config
	Freshness   Freshness
}

// NewManager validates opts and loads the active environment's config from what
// the wallet already has — the bundled copy, the persisted copy, whichever is
// newer — without touching the network. Having no usable config is not an
// error: the manager starts empty and the first Refresh fills it.
func NewManager(opts Options) (*Manager, error) {
	if err := ValidateEnvironments(opts.Environments); err != nil {
		return nil, err
	}
	environments := make(map[string]Environment, len(opts.Environments))
	for _, env := range opts.Environments {
		environments[env.Name] = env
	}
	active, ok := environments[opts.Active]
	if !ok {
		return nil, fmt.Errorf("active environment %q is not one of the configured environments", opts.Active)
	}

	m := &Manager{
		environments:    environments,
		store:           opts.Store,
		httpClient:      opts.HTTPClient,
		now:             opts.Now,
		logger:          opts.Logger,
		refreshInterval: opts.RefreshInterval,
		active:          active,
	}
	if m.store == nil {
		m.store = NewMemoryStore()
	}
	if m.httpClient == nil {
		m.httpClient = http.DefaultClient
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.logger == nil {
		m.logger = discardingLogger()
	}
	if m.refreshInterval <= 0 {
		m.refreshInterval = DefaultRefreshInterval
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadLocked(active)
	return m, nil
}

var discardingLogger = sync.OnceValue(func() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logger
})

// Snapshot pins the state one session evaluates against. It never blocks on the
// network and never fails.
func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	snapshot := Snapshot{Environment: m.active}
	if m.held != nil {
		snapshot.Config = m.held.Config
		snapshot.Freshness = m.held.Config.FreshnessAt(m.now())
	}
	return snapshot
}

// Refresh downloads the active environment's config and adopts it if it holds
// up: verifies under the environment's root, is for that environment, and does
// not roll back what is held. A failure leaves the held config in force; the
// error is for the caller's log, never a session-facing failure.
//
// changed reports whether the app may be showing trust information that is now
// out of date: the trust content differs, or the held config had expired and
// this one revives it. A re-issue saying the same thing is silent.
func (m *Manager) Refresh(ctx context.Context) (changed bool, err error) {
	return m.refresh(ctx, true)
}

// RefreshIfDue is Refresh with the throttle: it fetches when the wallet holds no
// config, when the held one is past its next_update, or when the last attempt
// was at least RefreshInterval ago. Otherwise it does nothing and reports no
// change. This is what app start and foreground events call.
func (m *Manager) RefreshIfDue(ctx context.Context) (changed bool, err error) {
	return m.refresh(ctx, false)
}

func (m *Manager) refresh(ctx context.Context, force bool) (bool, error) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	m.mu.Lock()
	env := m.active
	if !force && !m.dueLocked() {
		m.mu.Unlock()
		return false, nil
	}
	m.lastAttempt = m.now()
	m.mu.Unlock()

	raw, err := Fetch(ctx, m.httpClient, env.ConfigURL)
	if err != nil {
		return false, fmt.Errorf("fetch %s: %w", env.ConfigURL, err)
	}
	verified, err := Verify(raw, env, m.now())
	if err != nil {
		return false, fmt.Errorf("config from %s: %w", env.ConfigURL, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.installLocked(env, verified, true)
}

// dueLocked decides whether RefreshIfDue fetches. Called with m.mu held.
func (m *Manager) dueLocked() bool {
	if m.held == nil {
		return true
	}
	now := m.now()
	if m.held.Config.FreshnessAt(now) != Fresh {
		return true
	}
	return !now.Before(m.lastAttempt.Add(m.refreshInterval))
}

// SwitchEnvironment makes name the active environment and loads what the
// wallet already has for it, without touching the network; the caller triggers
// a Refresh. The switch is atomic: no snapshot ever sees one environment's
// descriptor with another's config. Switching to the active environment does
// nothing.
func (m *Manager) SwitchEnvironment(name string) error {
	env, ok := m.environments[name]
	if !ok {
		return fmt.Errorf("environment %q is not one of the configured environments", name)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active.Name == name {
		return nil
	}
	m.active = env
	m.held = nil
	m.lastAttempt = time.Time{}
	m.loadLocked(env)
	return nil
}

// loadLocked installs the best config the wallet already has for env: the copy
// bundled with the release or the one persisted from an earlier fetch, whichever
// is newer. Both are verified against env's root exactly as a download is; one
// that no longer verifies is dropped. Called with m.mu held.
func (m *Manager) loadLocked(env Environment) {
	var bundled, stored *Verified

	if env.BundledConfigPath != "" {
		raw, err := os.ReadFile(env.BundledConfigPath)
		if err != nil {
			m.logger.Warnf("walletconfig: reading the bundled config for %q: %v", env.Name, err)
		} else if verified, err := Verify(raw, env, m.now()); err != nil {
			m.logger.Warnf("walletconfig: the bundled config for %q does not verify: %v", env.Name, err)
		} else {
			bundled = verified
		}
	}

	if raw, ok := m.store.Get(env.Name); ok {
		if verified, err := Verify(raw, env, m.now()); err != nil {
			m.logger.Warnf("walletconfig: the stored config for %q no longer verifies, dropping it: %v", env.Name, err)
		} else {
			stored = verified
		}
	}

	best, persist := stored, false
	if bundled != nil && (stored == nil || compareIssue(bundled.Config, stored.Config) > 0) {
		// A release ships a config newer than what this wallet last fetched.
		// Persisting it makes the store the single rollback floor.
		best, persist = bundled, true
	}
	if best == nil {
		m.logger.Warnf("walletconfig: no usable config for environment %q", env.Name)
		return
	}
	if _, err := m.installLocked(env, best, persist); err != nil {
		m.logger.Warnf("walletconfig: installing the config for %q: %v", env.Name, err)
	}
}

// installLocked makes verified the held config, if env is still the active one
// and verified does not roll back what is held. Reports whether the trust
// content the app may be showing changed. Called with m.mu held.
func (m *Manager) installLocked(env Environment, verified *Verified, persist bool) (bool, error) {
	if m.active.Name != env.Name {
		return false, fmt.Errorf("environment switched from %q to %q meanwhile", env.Name, m.active.Name)
	}

	previous := m.held
	if previous != nil {
		switch compareIssue(verified.Config, previous.Config) {
		case -1:
			return false, fmt.Errorf("version %d issued %s rolls back the held version %d issued %s",
				verified.Config.Version, verified.Config.IssuedAt.Format(time.RFC3339),
				previous.Config.Version, previous.Config.IssuedAt.Format(time.RFC3339))
		case 0:
			// The same issue, already held and persisted. Checked before the store
			// write, which is the expensive half.
			if bytes.Equal(verified.Raw, previous.Raw) {
				return false, nil
			}
		}
	}

	if persist {
		if err := m.store.Put(env.Name, verified.Raw); err != nil {
			// The config is good; only persisting it failed. Use it for this run.
			m.logger.Warnf("walletconfig: persisting the config for %q: %v", env.Name, err)
		}
	}
	m.held = verified

	if previous == nil {
		return true, nil
	}
	// A held config past its grace period had stopped conferring list trust, so
	// a re-issue revives every listing even when the entries are the same.
	if previous.Config.FreshnessAt(m.now()) == Expired {
		return true, nil
	}
	return !sameTrustContent(previous.Config, verified.Config), nil
}

// compareIssue orders two issues of a config: by version, then by issued_at, so
// a re-signing of the same version with a later issue date is newer, and an
// earlier one is a replay.
func compareIssue(a, b *Config) int {
	if a.Version != b.Version {
		return cmp.Compare(a.Version, b.Version)
	}
	return a.IssuedAt.Compare(b.IssuedAt.Time)
}

// sameTrustContent reports whether two configs say the same thing about
// parties and policy. Version, issue date and freshness window are not
// compared: a re-issue carries new values for those without changing a
// verdict. A mere reorder of entities reads as a change, which is the cheap
// side of the trade: a spurious redraw against a stale badge.
func sameTrustContent(a, b *Config) bool {
	return bytes.Equal(trustContent(a), trustContent(b))
}

func trustContent(c *Config) []byte {
	content, err := json.Marshal(struct {
		Policy          Policy
		TrustedEntities []TrustedEntity
		MinimumAppBuild int64
	}{c.Policy, c.TrustedEntities, c.MinimumAppBuild})
	if err != nil {
		// A config that marshalled once marshals again; treat the impossible as a
		// change so nothing stale is left showing.
		return nil
	}
	return content
}
