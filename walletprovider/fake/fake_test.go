package fake_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/walletprovider"
	"github.com/privacybydesign/irmago/walletprovider/fake"
	"github.com/privacybydesign/irmago/walletprovider/providertest"
)

func TestFakeConforms(t *testing.T) {
	providertest.Run(t, fake.New(fake.Options{}), "12345", "54321")
}

func TestFakeUnlockExpiresWhenIdle(t *testing.T) {
	now := time.Now()
	p, err := fake.New(fake.Options{UnlockIdle: time.Minute, Now: func() time.Time { return now }})(providertest.NewHost())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := p.Activate(ctx, "12345"); err != nil {
		t.Fatal(err)
	}
	u, err := p.Unlock(ctx, "12345", walletprovider.Scope{Purpose: walletprovider.PurposeIssuancePoP})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := u.GenerateKeys(ctx, 1); !errors.Is(err, walletprovider.ErrUnlockExpired) {
		t.Fatalf("got %v, want ErrUnlockExpired", err)
	}
}

func TestFakeBlockLifts(t *testing.T) {
	now := time.Now()
	p, err := fake.New(fake.Options{MaxAttempts: 1, BlockDuration: time.Minute, Now: func() time.Time { return now }})(providertest.NewHost())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := p.Activate(ctx, "12345"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Unlock(ctx, "00000", walletprovider.Scope{}); !isBlocked(err) {
		t.Fatalf("got %v, want *PinBlockedError", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := p.Unlock(ctx, "12345", walletprovider.Scope{}); err != nil {
		t.Fatalf("unlock after block lifted: %v", err)
	}
}

func isBlocked(err error) bool {
	_, ok := errors.AsType[*walletprovider.PinBlockedError](err)
	return ok
}
