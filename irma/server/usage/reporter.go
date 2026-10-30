package usage

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-errors/errors"
	irmago "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irma"
	"github.com/sirupsen/logrus"
)

const (
	// DefaultPortalURL is the usage directory of the Yivi Portal.
	DefaultPortalURL = "https://portal.yivi.app/usage/v1/directory"
	// DefaultInterval is how often the open counts are sealed into a report.
	DefaultInterval = 5 * time.Minute

	// maxOutbox caps the reports waiting to be sent: one week at the default interval.
	// When it is full, counts keep accumulating in the open interval instead.
	maxOutbox = 2016

	minBackoff = 30 * time.Second
	maxBackoff = time.Hour
	// notRegisteredRetry is how often a key the Portal does not (or no longer) know is checked again.
	notRegisteredRetry = time.Hour
	stopFlushTimeout   = 10 * time.Second
	startupTimeout     = 10 * time.Second
	outboxDirName      = "outbox"
)

// Settings configures usage reporting.
type Settings struct {
	// Disabled turns usage reporting off, also in production mode. Meant for Yivi's own services.
	Disabled bool `json:"disabled" mapstructure:"disabled"`
	// PortalURL is the Portal's usage directory URL (default DefaultPortalURL).
	PortalURL string `json:"portal_url" mapstructure:"portal_url"`
	// Interval after which the open counts are sealed into a report (default DefaultInterval).
	Interval time.Duration `json:"interval" mapstructure:"interval"`
	// StateDir optionally holds the account key and the reports waiting to be sent, so both
	// survive a restart.
	StateDir string `json:"state_dir" mapstructure:"state_dir"`
	// AccountKeyFile is a PEM file with the ES256 account key, e.g. a mounted secret.
	// If empty, the key is kept in StateDir.
	AccountKeyFile string `json:"account_key_file" mapstructure:"account_key_file"`
	// ServerInstance distinguishes replicas of one server (default the hostname).
	ServerInstance string `json:"server_instance" mapstructure:"server_instance"`
	// CountIssuance also counts issuance sessions. Off by default: billing is per disclosure.
	CountIssuance bool `json:"count_issuance" mapstructure:"count_issuance"`
}

// Reporter counts session events and sends them to the Portal as signed delta reports.
type Reporter struct {
	settings Settings
	logger   *logrus.Logger
	key      *ecdsa.PrivateKey
	client   *portalClient
	tally    *tally
	runID    string

	// Only touched by the reporting goroutine, and by Stop after that goroutine has ended.
	sequence    uint64
	periodStart time.Time
	kid         string
	backoff     time.Duration
	nextAttempt time.Time
	lastLogged  time.Time

	mu     sync.Mutex
	outbox []*Report

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

// New loads (or creates) the account key and checks with the Portal that it is registered.
// Neither an unregistered key nor an unreachable Portal stops the server: both are logged, and
// the check is repeated before reports are sent. Counts are kept until the key is registered.
func New(settings Settings, logger *logrus.Logger) (*Reporter, error) {
	if settings.PortalURL == "" {
		settings.PortalURL = DefaultPortalURL
	}
	if settings.Interval <= 0 {
		settings.Interval = DefaultInterval
	}
	if settings.ServerInstance == "" {
		settings.ServerInstance, _ = os.Hostname()
	}

	key, err := LoadOrCreateKey(settings.AccountKeyFile, settings.StateDir)
	if err != nil {
		return nil, err
	}

	r := &Reporter{
		settings:    settings,
		logger:      logger,
		key:         key,
		client:      newPortalClient(settings.PortalURL, key),
		tally:       newTally(),
		runID:       randomID(),
		periodStart: time.Now().UTC(),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	if err := r.loadOutbox(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	switch kid, err := r.client.lookupAccount(ctx); {
	case err == nil:
		r.kid = kid
		logger.WithField("thumbprint", Thumbprint(key)).Info("Usage reporting account key is registered in the Yivi Portal")
	case errors.Is(err, ErrNotRegistered):
		pub, _ := PublicKeyPEM(key)
		r.lastLogged = time.Now()
		logger.Errorf("%s. Register this public key with your organisation in the Yivi Portal "+
			"(JWK thumbprint %s), or disable usage reporting if this is an internal Yivi service. "+
			"The server keeps running and sends its reports once the key is registered.\n%s",
			ErrNotRegistered.Error(), Thumbprint(key), pub)
	default:
		logger.WithError(err).Warn("Could not reach the Yivi Portal to check the usage reporting account key; continuing and retrying in the background")
	}

	go r.run()
	return r, nil
}

// Record counts a session that reached a final status. It never blocks on I/O.
func (r *Reporter) Record(e Event) {
	if e.Action == irma.ActionIssuing && !r.settings.CountIssuance {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	r.tally.record(e)
}

// Stop seals the open interval as the final report of this run and tries to send all pending
// reports for a short while. Reports that could not be sent stay in the state dir, if any.
func (r *Reporter) Stop() {
	r.stopOnce.Do(func() {
		close(r.stop)
		<-r.done
		r.seal(time.Now().UTC(), true)
		ctx, cancel := context.WithTimeout(context.Background(), stopFlushTimeout)
		defer cancel()
		r.nextAttempt = time.Time{}
		r.flush(ctx)
	})
}

func (r *Reporter) run() {
	defer close(r.done)
	ticker := time.NewTicker(min(r.settings.Interval, 10*time.Second))
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case now := <-ticker.C:
			if now.UTC().Sub(r.periodStart) >= r.settings.Interval {
				r.seal(now.UTC(), false)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			r.flush(ctx)
			cancel()
		}
	}
}

// seal turns the open counts into a report in the outbox. While the outbox is full, the counts
// stay in the open interval, so nothing is dropped and the sequence has no false gaps.
func (r *Reporter) seal(now time.Time, final bool) {
	r.mu.Lock()
	full := len(r.outbox) >= maxOutbox
	r.mu.Unlock()
	if full && !final {
		return
	}
	// An empty interval is skipped, except for the final report that tells the Portal this run
	// ended cleanly.
	if r.tally.empty() && !final {
		r.periodStart = now
		return
	}

	disclosures, sessions := r.tally.take()
	r.sequence++
	report := &Report{
		Schema:         ReportSchema,
		ReportID:       randomID(),
		ServerInstance: r.settings.ServerInstance,
		RunID:          r.runID,
		Sequence:       r.sequence,
		Final:          final,
		IrmagoVersion:  irmago.Version,
		Period:         Period{From: r.periodStart, To: now},
		Disclosures:    disclosures,
		Sessions:       sessions,
	}
	r.periodStart = now

	if err := r.storeReport(report); err != nil {
		r.logger.WithError(err).Warn("Failed to store usage report in the state dir; it is kept in memory only")
	}
	r.mu.Lock()
	r.outbox = append(r.outbox, report)
	r.mu.Unlock()
}

// flush sends the outbox in order until it is empty or a send fails.
func (r *Reporter) flush(ctx context.Context) {
	if time.Now().Before(r.nextAttempt) {
		return
	}
	for {
		r.mu.Lock()
		if len(r.outbox) == 0 {
			r.mu.Unlock()
			return
		}
		report := r.outbox[0]
		r.mu.Unlock()

		err := r.send(ctx, report)
		var rejected *rejectedError
		switch {
		case err == nil, errors.As(err, &rejected):
			if err != nil {
				r.logger.WithError(err).WithField("report", report.ReportID).Error("Dropping usage report the Yivi Portal rejected")
			} else {
				r.logger.WithFields(logrus.Fields{
					"report": report.ReportID, "sequence": report.Sequence, "sessions": len(report.Sessions),
				}).Info("Sent usage report to the Yivi Portal")
			}
			r.removeReport(report)
			r.backoff = 0
		case errors.Is(err, ErrNotRegistered):
			// The key is unknown or was deactivated: keep serving sessions, keep the reports, and
			// check again later.
			r.kid = ""
			r.nextAttempt = time.Now().Add(notRegisteredRetry)
			if time.Since(r.lastLogged) >= notRegisteredRetry {
				r.lastLogged = time.Now()
				r.logger.Error("Usage reports cannot be sent: the account key is not registered in the Yivi Portal, or was deactivated. Sessions keep working; register the key to resume reporting.")
			}
			return
		default:
			r.retryLater(err)
			return
		}
	}
}

func (r *Reporter) send(ctx context.Context, report *Report) error {
	if r.kid == "" {
		kid, err := r.client.lookupAccount(ctx)
		if err != nil {
			return err
		}
		r.kid = kid
	}
	return r.client.postReport(ctx, r.kid, report)
}

func (r *Reporter) retryLater(err error) {
	if r.backoff == 0 {
		r.backoff = minBackoff
	} else if r.backoff *= 2; r.backoff > maxBackoff {
		r.backoff = maxBackoff
	}
	wait := r.backoff
	var retryAfter *retryAfterError
	if errors.As(err, &retryAfter) && retryAfter.after > wait {
		wait = retryAfter.after
	}
	r.nextAttempt = time.Now().Add(wait)
	r.logger.WithError(err).Warnf("Failed to send usage report to the Yivi Portal, retrying in %s", wait)
}

func (r *Reporter) outboxDir() string {
	if r.settings.StateDir == "" {
		return ""
	}
	return filepath.Join(r.settings.StateDir, outboxDirName)
}

func reportFileName(report *Report) string {
	return fmt.Sprintf("%s-%010d.json", report.RunID, report.Sequence)
}

func (r *Reporter) storeReport(report *Report) error {
	dir := r.outboxDir()
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	bts, err := json.Marshal(report)
	if err != nil {
		return err
	}
	// Write and rename, so a crash never leaves a half-written report behind.
	tmp := filepath.Join(dir, reportFileName(report)+".tmp")
	if err := os.WriteFile(tmp, bts, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, reportFileName(report)))
}

func (r *Reporter) removeReport(report *Report) {
	r.mu.Lock()
	if len(r.outbox) > 0 && r.outbox[0] == report {
		r.outbox = r.outbox[1:]
	}
	r.mu.Unlock()
	if dir := r.outboxDir(); dir != "" {
		if err := os.Remove(filepath.Join(dir, reportFileName(report))); err != nil && !os.IsNotExist(err) {
			r.logger.WithError(err).Warn("Failed to remove sent usage report from the state dir")
		}
	}
}

// loadOutbox picks up reports of earlier runs that were sealed but not yet sent.
func (r *Reporter) loadOutbox() error {
	dir := r.outboxDir()
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return errors.WrapPrefix(err, "failed to read usage report outbox", 0)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		bts, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return errors.WrapPrefix(err, "failed to read usage report", 0)
		}
		report := &Report{}
		if err := json.Unmarshal(bts, report); err != nil {
			r.logger.WithError(err).Warnf("Ignoring unreadable usage report %s", entry.Name())
			continue
		}
		r.outbox = append(r.outbox, report)
	}
	sort.SliceStable(r.outbox, func(i, j int) bool {
		a, b := r.outbox[i], r.outbox[j]
		if !a.Period.To.Equal(b.Period.To) {
			return a.Period.To.Before(b.Period.To)
		}
		return a.Sequence < b.Sequence
	})
	if len(r.outbox) > 0 {
		r.logger.Infof("Found %d unsent usage reports from earlier runs", len(r.outbox))
	}
	return nil
}

func randomID() string {
	bts := make([]byte, 16)
	_, _ = rand.Read(bts)
	return hex.EncodeToString(bts)
}
