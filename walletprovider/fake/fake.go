// Package fake is an in-process walletprovider.WalletProvider for tests: it
// keeps holder keys as software keys in the host's storage and simulates the
// PIN semantics of a real provider — attempt counting, blocking and unlock
// expiry. It is what irmago's own tests bind credentials with; it is not a
// wallet provider and never holds anything a real one would.
package fake

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/privacybydesign/irmago/walletprovider"
	"github.com/privacybydesign/irmago/walletprovider/providertest"
)

// Options tune the simulated PIN policy. The zero value of each field selects
// its default.
type Options struct {
	// MaxAttempts is how many consecutive wrong PINs block the wallet unit.
	// Default 3.
	MaxAttempts int
	// BlockDuration is how long a blocked wallet unit stays blocked. Default
	// one minute.
	BlockDuration time.Duration
	// UnlockIdle is how long an unlocked wallet unit stays usable without
	// being used. Default five minutes.
	UnlockIdle time.Duration
	// Now is the clock. Default time.Now.
	Now func() time.Time
	// NewPossessionKey makes the possession key of each provider the factory
	// builds. Default a fresh providertest.SoftwarePossessionKey.
	NewPossessionKey func() walletprovider.PossessionKey
	// AttestationCA signs the wallet instance attestations. Default a CA of
	// the factory's own; pass one to trust its root in a test issuer.
	AttestationCA *AttestationCA
	// ClientID is the sub of the wallet instance attestations. Default
	// "yivi-wallet".
	ClientID string
	// KeyProtection is what the key attestations claim. Default
	// iso_18045_high for both.
	KeyProtection *walletprovider.KeyProtection
}

// Provider is the fake wallet provider.
type Provider struct {
	host          walletprovider.Host
	possessionKey walletprovider.PossessionKey
	opts          Options

	mu                   sync.Mutex
	unlocks              []walletprovider.Scope
	signs                int
	revocations          int
	instanceAttestations int
	keyAttestations      int
}

var _ walletprovider.WalletProvider = (*Provider)(nil)

// New returns a factory for fake providers with the given options.
func New(opts Options) walletprovider.Factory {
	if opts.MaxAttempts == 0 {
		opts.MaxAttempts = 3
	}
	if opts.BlockDuration == 0 {
		opts.BlockDuration = time.Minute
	}
	if opts.UnlockIdle == 0 {
		opts.UnlockIdle = 5 * time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewPossessionKey == nil {
		opts.NewPossessionKey = func() walletprovider.PossessionKey { return &providertest.SoftwarePossessionKey{} }
	}
	if opts.ClientID == "" {
		opts.ClientID = "yivi-wallet"
	}
	if opts.KeyProtection == nil {
		opts.KeyProtection = &walletprovider.KeyProtection{
			KeyStorage:         []string{"iso_18045_high"},
			UserAuthentication: []string{"iso_18045_high"},
		}
	}
	var caErr error
	if opts.AttestationCA == nil {
		opts.AttestationCA, caErr = NewAttestationCA()
	}
	return func(host walletprovider.Host) (walletprovider.WalletProvider, error) {
		if caErr != nil {
			return nil, caErr
		}
		if host == nil || host.Storage() == nil {
			return nil, errors.New("fake wallet provider: host needs storage")
		}
		return &Provider{host: host, possessionKey: opts.NewPossessionKey(), opts: opts}, nil
	}
}

// Unlocks returns the scope of every successful unlock so far, oldest first.
func (p *Provider) Unlocks() []walletprovider.Scope {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.unlocks)
}

// SignCount returns how many signatures the provider has made.
func (p *Provider) SignCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.signs
}

// Revocations returns how often Revoke was called. Unlike the provider's
// state, it survives the wallet wiping the storage the fake keeps it in.
func (p *Provider) Revocations() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revocations
}

// InstanceAttestations returns how many wallet instance attestations the
// provider has issued.
func (p *Provider) InstanceAttestations() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.instanceAttestations
}

// KeyAttestations returns how many key attestations the provider has issued.
func (p *Provider) KeyAttestations() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keyAttestations
}

// KeyCount returns how many holder keys the provider holds.
func (p *Provider) KeyCount() (int, error) {
	st, err := p.load()
	if err != nil {
		return 0, err
	}
	return len(st.Keys), nil
}

const stateKey = "fake/state"

// state is everything the fake persists, as one JSON document.
type state struct {
	Activated     bool              `json:"activated"`
	Revoked       bool              `json:"revoked"`
	PinSalt       []byte            `json:"pin_salt"`
	PinHash       []byte            `json:"pin_hash"`
	Possession    []byte            `json:"possession"` // PKIX public key
	FailedPins    int               `json:"failed_pins"`
	BlockedUntil  time.Time         `json:"blocked_until"`
	Keys          map[string][]byte `json:"keys"` // ref → SEC 1 private key
	NextKeyNumber int               `json:"next_key_number"`
	Log           []logEntry        `json:"log"` // oldest first
}

type logEntry struct {
	Operation    walletprovider.Operation `json:"operation"`
	Failed       bool                     `json:"failed,omitempty"`
	Purpose      walletprovider.Purpose   `json:"purpose,omitempty"`
	Counterparty string                   `json:"counterparty,omitempty"`
	Time         time.Time                `json:"time"`
}

// logFailure appends a failed operation to the transaction log.
func (p *Provider) logFailure(st *state, op walletprovider.Operation) {
	st.Log = append(st.Log, logEntry{Operation: op, Failed: true, Time: p.opts.Now()})
}

// logOperation appends to the transaction log.
func (p *Provider) logOperation(st *state, op walletprovider.Operation, scope walletprovider.Scope) {
	entry := logEntry{Operation: op, Time: p.opts.Now()}
	if op == walletprovider.OperationSign {
		entry.Purpose = scope.Purpose
		if scope.Purpose == walletprovider.PurposeIssuancePoP {
			entry.Counterparty = scope.Counterparty
		}
	}
	st.Log = append(st.Log, entry)
}

func (p *Provider) load() (*state, error) {
	raw, err := p.host.Storage().Get(stateKey)
	if errors.Is(err, walletprovider.ErrNotFound) {
		return &state{Keys: map[string][]byte{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("fake wallet provider: corrupt state: %w", err)
	}
	if st.Keys == nil {
		st.Keys = map[string][]byte{}
	}
	return &st, nil
}

// update loads the state, lets fn change it and persists the result
// atomically. Serialised by p.mu so read-modify-write cycles cannot interleave.
func (p *Provider) update(fn func(st *state) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.host.Storage().Update(func(tx walletprovider.StorageTx) error {
		st := &state{Keys: map[string][]byte{}}
		raw, err := tx.Get(stateKey)
		switch {
		case errors.Is(err, walletprovider.ErrNotFound):
		case err != nil:
			return err
		default:
			if err := json.Unmarshal(raw, st); err != nil {
				return fmt.Errorf("fake wallet provider: corrupt state: %w", err)
			}
			if st.Keys == nil {
				st.Keys = map[string][]byte{}
			}
		}
		if err := fn(st); err != nil {
			return err
		}
		out, err := json.Marshal(st)
		if err != nil {
			return err
		}
		return tx.Put(stateKey, out)
	})
}

func (p *Provider) State(context.Context) (walletprovider.State, error) {
	st, err := p.load()
	if err != nil {
		return "", err
	}
	switch {
	case st.Revoked:
		return walletprovider.StateRevoked, nil
	case st.Activated:
		return walletprovider.StateActive, nil
	default:
		return walletprovider.StateNotActivated, nil
	}
}

func hashPin(salt []byte, pin string) []byte {
	h := sha256.Sum256(append(slices.Clone(salt), pin...))
	return h[:]
}

func (p *Provider) Activate(ctx context.Context, pin string) error {
	if pin == "" {
		return errors.New("fake wallet provider: empty PIN")
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	pub, _, err := p.possessionKey.Create(ctx, challenge)
	if err != nil {
		return fmt.Errorf("fake wallet provider: create possession key: %w", err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	if _, _, err := p.possessionKey.AppAttestation(ctx, challenge); err != nil {
		return fmt.Errorf("fake wallet provider: app attestation: %w", err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	return p.update(func(st *state) error {
		*st = state{
			Activated:  true,
			PinSalt:    salt,
			PinHash:    hashPin(salt, pin),
			Possession: pkix,
			Keys:       map[string][]byte{},
		}
		p.logOperation(st, walletprovider.OperationActivate, walletprovider.Scope{})
		return nil
	})
}

// proveVerifyPossession has the possession key sign a fresh challenge and
// checks it against the key recorded at activation, as a real provider's
// server would on every instruction.
func (p *Provider) proveVerifyPossession(st *state) error {
	recorded, err := x509.ParsePKIXPublicKey(st.Possession)
	if err != nil {
		return fmt.Errorf("fake wallet provider: recorded possession key: %w", err)
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	digest := sha256.Sum256(challenge)
	sig, err := p.possessionKey.SignDigest(digest[:])
	if err != nil {
		return fmt.Errorf("fake wallet provider: possession key: %w", err)
	}
	if !ecdsa.VerifyASN1(recorded.(*ecdsa.PublicKey), digest[:], sig) {
		return errors.New("fake wallet provider: possession key does not match the wallet unit")
	}
	return nil
}

func (p *Provider) Unlock(_ context.Context, pin string, scope walletprovider.Scope) (walletprovider.UnlockedWalletUnit, error) {
	var result error
	err := p.update(func(st *state) error {
		if !st.Activated || st.Revoked {
			return walletprovider.ErrNotActivated
		}
		now := p.opts.Now()
		if now.Before(st.BlockedUntil) {
			return &walletprovider.PinBlockedError{Duration: st.BlockedUntil.Sub(now)}
		}
		if err := p.proveVerifyPossession(st); err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(hashPin(st.PinSalt, pin), st.PinHash) != 1 {
			// Persist the failed attempt, so the error is reported after the
			// update commits rather than aborting it.
			p.logFailure(st, walletprovider.OperationRejected)
			st.FailedPins++
			if st.FailedPins >= p.opts.MaxAttempts {
				st.FailedPins = 0
				st.BlockedUntil = now.Add(p.opts.BlockDuration)
				result = &walletprovider.PinBlockedError{Duration: p.opts.BlockDuration}
			} else {
				result = &walletprovider.PinIncorrectError{Remaining: p.opts.MaxAttempts - st.FailedPins}
			}
			return nil
		}
		st.FailedPins = 0
		p.logOperation(st, walletprovider.OperationUnlock, scope)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if result != nil {
		return nil, result
	}

	p.mu.Lock()
	p.unlocks = append(p.unlocks, scope)
	p.mu.Unlock()
	return &unlocked{provider: p, scope: scope, lastUse: p.opts.Now()}, nil
}

func (p *Provider) RemoveKeys(_ context.Context, refs []string) error {
	return p.update(func(st *state) error {
		for _, ref := range refs {
			if _, ok := st.Keys[ref]; ok {
				delete(st.Keys, ref)
				p.logOperation(st, walletprovider.OperationRemoveKeys, walletprovider.Scope{})
			}
		}
		return nil
	})
}

func (p *Provider) Revoke(context.Context) error {
	p.mu.Lock()
	p.revocations++
	p.mu.Unlock()
	return p.update(func(st *state) error {
		*st = state{Revoked: true, Keys: map[string][]byte{}}
		return nil
	})
}

func (u *unlocked) InstanceAttestation(_ context.Context, key *ecdsa.PublicKey) ([]byte, error) {
	if err := u.use(); err != nil {
		return nil, err
	}
	return u.provider.instanceAttestation(key)
}

func (p *Provider) instanceAttestation(key *ecdsa.PublicKey) ([]byte, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, errors.New("fake wallet provider: an instance attestation binds a P-256 key")
	}
	err := p.update(func(st *state) error {
		if !st.Activated || st.Revoked {
			return walletprovider.ErrNotActivated
		}
		if p.opts.Now().Before(st.BlockedUntil) {
			return walletprovider.ErrAttestationRefused
		}
		if err := p.proveVerifyPossession(st); err != nil {
			return err
		}
		p.logOperation(st, walletprovider.OperationAttestInstance, walletprovider.Scope{})
		return nil
	})
	if err != nil {
		return nil, err
	}
	now := p.opts.Now()
	wia, err := p.opts.AttestationCA.sign(providertest.InstanceAttestationType, map[string]any{
		"iss":         "https://fake-wallet-provider.invalid",
		"sub":         p.opts.ClientID,
		"iat":         now.Unix(),
		"exp":         now.Add(time.Hour).Unix(),
		"cnf":         map[string]any{"jwk": providertest.JWK(key)},
		"wallet_name": "Yivi",
		"wallet_link": "https://yivi.app",
		"client_status": map[string]any{
			"status": map[string]any{"status_list": map[string]any{
				"idx": randomIndex(),
				"uri": "https://fake-wallet-provider.invalid/status/wia",
			}},
			"exp": now.Add(31 * 24 * time.Hour).Unix(),
		},
	})
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.instanceAttestations++
	p.mu.Unlock()
	return []byte(wia), nil
}

func (p *Provider) KeyProtection(context.Context) (walletprovider.KeyProtection, error) {
	return *p.opts.KeyProtection, nil
}

// keyAttestation is a KA over keys, as a real provider's would be: the keys,
// the nonce, the claimed protection and a status reference.
func (p *Provider) keyAttestation(keys []walletprovider.HolderKey, nonce string) ([]byte, error) {
	now := p.opts.Now()
	attested := make([]any, len(keys))
	for i, k := range keys {
		attested[i] = providertest.JWK(k.Public)
	}
	status := map[string]any{"status_list": map[string]any{
		"idx": randomIndex(),
		"uri": "https://fake-wallet-provider.invalid/status/ka",
	}}
	claims := map[string]any{
		"iat":           now.Unix(),
		"exp":           now.Add(time.Hour).Unix(),
		"attested_keys": attested,
		"status":        status,
		"key_storage_status": map[string]any{
			"status": status,
			"exp":    now.Add(365 * 24 * time.Hour).Unix(),
		},
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if levels := p.opts.KeyProtection.KeyStorage; len(levels) > 0 {
		claims["key_storage"] = levels
	}
	if levels := p.opts.KeyProtection.UserAuthentication; len(levels) > 0 {
		claims["user_authentication"] = levels
	}
	ka, err := p.opts.AttestationCA.sign(providertest.KeyAttestationType, claims)
	if err != nil {
		return nil, err
	}
	return []byte(ka), nil
}

// unlocked is the fake's unlocked wallet unit.
type unlocked struct {
	provider *Provider
	scope    walletprovider.Scope

	mu      sync.Mutex
	closed  bool
	lastUse time.Time
}

// use checks the unlock is still live and records the use.
func (u *unlocked) use() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.provider.opts.Now()
	if u.closed || now.Sub(u.lastUse) > u.provider.opts.UnlockIdle {
		u.closed = true
		return walletprovider.ErrUnlockExpired
	}
	u.lastUse = now
	return nil
}

func (u *unlocked) GenerateKeys(_ context.Context, n int, attest *walletprovider.KeyAttestationRequest) ([]walletprovider.HolderKey, []byte, error) {
	if err := u.use(); err != nil {
		return nil, nil, err
	}
	if u.scope.Purpose != walletprovider.PurposeIssuancePoP {
		return nil, nil, fmt.Errorf("fake wallet provider: key generation is not allowed for purpose %q", u.scope.Purpose)
	}
	if n < 1 {
		return nil, nil, fmt.Errorf("fake wallet provider: cannot generate %d keys", n)
	}
	keys := make([]walletprovider.HolderKey, 0, n)
	err := u.provider.update(func(st *state) error {
		for range n {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			der, err := x509.MarshalECPrivateKey(priv)
			if err != nil {
				return err
			}
			st.NextKeyNumber++
			ref := fmt.Sprintf("fake-key-%d-%s", st.NextKeyNumber, randomHex(4))
			st.Keys[ref] = der
			keys = append(keys, walletprovider.HolderKey{Ref: ref, Public: &priv.PublicKey})
			u.provider.logOperation(st, walletprovider.OperationGenerateKeys, u.scope)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if attest == nil {
		return keys, nil, nil
	}
	ka, err := u.provider.keyAttestation(keys, attest.Nonce)
	if err != nil {
		return nil, nil, err
	}
	u.provider.mu.Lock()
	u.provider.keyAttestations++
	u.provider.mu.Unlock()
	return keys, ka, nil
}

func (u *unlocked) Sign(_ context.Context, reqs []walletprovider.SignRequest) ([][]byte, error) {
	if err := u.use(); err != nil {
		return nil, err
	}
	st, err := u.provider.load()
	if err != nil {
		return nil, err
	}
	sigs := make([][]byte, len(reqs))
	for i, req := range reqs {
		der, ok := st.Keys[req.Ref]
		if !ok {
			return nil, fmt.Errorf("fake wallet provider: unknown key %q", req.Ref)
		}
		priv, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(req.SigningInput)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			return nil, err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		sigs[i] = sig
	}
	u.provider.mu.Lock()
	u.provider.signs += len(reqs)
	u.provider.mu.Unlock()
	if err := u.provider.update(func(st *state) error {
		for range reqs {
			u.provider.logOperation(st, walletprovider.OperationSign, u.scope)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return sigs, nil
}

func (u *unlocked) Transactions(_ context.Context, before time.Time, max int) ([]walletprovider.Transaction, error) {
	if err := u.use(); err != nil {
		return nil, err
	}
	st, err := u.provider.load()
	if err != nil {
		return nil, err
	}
	var out []walletprovider.Transaction
	for i := len(st.Log) - 1; i >= 0 && len(out) < max; i-- {
		e := st.Log[i]
		if !before.IsZero() && !e.Time.Before(before) {
			continue
		}
		out = append(out, walletprovider.Transaction{
			ID:           fmt.Sprintf("fake-tx-%d", i),
			Time:         e.Time,
			Operation:    e.Operation,
			Purpose:      e.Purpose,
			Counterparty: e.Counterparty,
			Succeeded:    !e.Failed,
		})
	}
	return out, nil
}

func (u *unlocked) ChangePin(_ context.Context, newPin string) error {
	if err := u.use(); err != nil {
		return err
	}
	if newPin == "" {
		return errors.New("fake wallet provider: empty PIN")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	err := u.provider.update(func(st *state) error {
		st.PinSalt = salt
		st.PinHash = hashPin(salt, newPin)
		st.FailedPins = 0
		u.provider.logOperation(st, walletprovider.OperationChangePin, walletprovider.Scope{})
		return nil
	})
	u.Close()
	return err
}

func (u *unlocked) Close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closed = true
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
