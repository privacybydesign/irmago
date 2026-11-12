// Package walletunit is the wallet's side of its wallet provider: it asks the
// user for the PIN and turns it into an unlocked wallet unit (CONTEXT.md,
// "Unlock"), activating the wallet unit first where that is allowed.
//
// The OpenID4VC protocols never see it. The client gives each session a
// Session, carried in the session's context, and the key services behind the
// protocols' holder key seams (eudi/services) unlock through it when they are
// asked to use a key in the provider's HSM.
package walletunit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/privacybydesign/irmago/walletprovider"
)

var (
	// ErrCancelled is returned when the user declined to enter their PIN.
	ErrCancelled = errors.New("walletunit: PIN entry cancelled")
	// ErrNoSession is returned when a wallet provider key is needed outside a
	// session that can ask for the PIN.
	ErrNoSession = errors.New("walletunit: no session to ask for the PIN in")
)

// Prompter is how a session asks its user for the PIN.
type Prompter interface {
	// RequestPin asks for the PIN and blocks until the user answers.
	// remainingAttempts is nil on the first ask and the attempts left after a
	// wrong PIN otherwise. ok is false when the user declined.
	RequestPin(remainingAttempts *int) (pin string, ok bool)
	// PinBlocked tells the user the PIN is blocked for duration.
	PinBlocked(duration time.Duration)
}

// Session is the wallet unit as one session uses it: it asks for the PIN at
// most once per purpose, and keeps the unlocked wallet unit until Close.
type Session struct {
	provider walletprovider.WalletProvider
	prompter Prompter

	// unlocking serialises unlocks, so two uses of one purpose never prompt
	// twice. It is held while the user is being asked; mu never is, so Close
	// can run while a prompt is open (the session being dismissed from it).
	unlocking sync.Mutex

	mu       sync.Mutex
	closed   bool
	unlocked map[walletprovider.Purpose]walletprovider.UnlockedWalletUnit
}

// NewSession starts a session with the provider that asks for the PIN through
// prompter.
func NewSession(provider walletprovider.WalletProvider, prompter Prompter) *Session {
	return &Session{
		provider: provider,
		prompter: prompter,
		unlocked: map[walletprovider.Purpose]walletprovider.UnlockedWalletUnit{},
	}
}

type sessionKey struct{}

// WithSession returns ctx carrying s.
func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// SessionFrom returns the session ctx carries, or nil.
func SessionFrom(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionKey{}).(*Session)
	return s
}

// Unlocked returns the wallet unit unlocked for scope's purpose, asking for
// the PIN the first time and again after every wrong PIN. The first unlock
// for a purpose fixes its scope for the rest of the session.
//
// It returns ErrCancelled when the user declines, *walletprovider.PinBlockedError
// when the PIN is blocked (having told the user), and
// walletprovider.ErrNotActivated when there is no wallet unit and activate is
// false. With activate set, a wallet unit that is not activated yet is
// activated with the PIN first (decision 2 of
// docs/plans/wallet-provider-integration.md). The PIN is not checked against
// the keyshare PIN: a mistyped one is bound as entered, an accepted risk for
// now.
func (s *Session) Unlocked(ctx context.Context, scope walletprovider.Scope, activate bool) (walletprovider.UnlockedWalletUnit, error) {
	s.unlocking.Lock()
	defer s.unlocking.Unlock()

	if u, err := s.cached(scope.Purpose); u != nil || err != nil {
		return u, err
	}

	u, err := s.unlock(ctx, scope, activate)
	if blocked, ok := errors.AsType[*walletprovider.PinBlockedError](err); ok {
		s.prompter.PinBlocked(blocked.Duration)
	}
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		// Closed while the user was being asked: the session is over.
		u.Close()
		return nil, ErrCancelled
	}
	s.unlocked[scope.Purpose] = u
	return u, nil
}

// cached returns the unlock already made for purpose, or ErrCancelled when
// the session is closed.
func (s *Session) cached(purpose walletprovider.Purpose) (walletprovider.UnlockedWalletUnit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrCancelled
	}
	return s.unlocked[purpose], nil
}

func (s *Session) unlock(ctx context.Context, scope walletprovider.Scope, activate bool) (walletprovider.UnlockedWalletUnit, error) {
	state, err := s.provider.State(ctx)
	if err != nil {
		return nil, fmt.Errorf("wallet provider state: %w", err)
	}
	needsActivation := state != walletprovider.StateActive
	if needsActivation && (!activate || state == walletprovider.StateRevoked) {
		return nil, walletprovider.ErrNotActivated
	}

	var remaining *int
	for {
		pin, ok := s.prompter.RequestPin(remaining)
		if !ok {
			return nil, ErrCancelled
		}

		if needsActivation {
			if err := s.provider.Activate(ctx, pin); err != nil {
				return nil, fmt.Errorf("wallet unit activation failed: %w", err)
			}
			needsActivation = false
		}

		unlocked, err := s.provider.Unlock(ctx, pin, scope)
		if incorrect, ok := errors.AsType[*walletprovider.PinIncorrectError](err); ok {
			remaining = &incorrect.Remaining
			continue
		}
		if err != nil {
			return nil, err
		}
		return unlocked, nil
	}
}

// Close ends every unlock the session made, and any it is still making.
// Calling it more than once is harmless.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for purpose, u := range s.unlocked {
		u.Close()
		delete(s.unlocked, purpose)
	}
}
