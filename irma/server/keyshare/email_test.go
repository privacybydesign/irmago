package keyshare

import (
	"bytes"
	"net"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func TestParseEmailTemplates(t *testing.T) {
	lang := "en"
	testdataPath := test.FindTestdataFolder(t)

	_, err := ParseEmailTemplates(
		map[string]string{},
		map[string]string{lang: "subject"},
		lang,
	)
	require.Error(t, err)

	_, err = ParseEmailTemplates(
		map[string]string{lang: filepath.Join(testdataPath, "emailtemplate.html")},
		map[string]string{},
		lang,
	)
	require.Error(t, err)

	_, err = ParseEmailTemplates(
		map[string]string{lang: filepath.Join(testdataPath, "invalidemailtemplate.html")},
		map[string]string{lang: "subject"},
		lang,
	)
	require.Error(t, err)

	templ, err := ParseEmailTemplates(
		map[string]string{lang: filepath.Join(testdataPath, "emailtemplate.html")},
		map[string]string{lang: "subject"},
		lang,
	)
	require.NoError(t, err)
	require.Contains(t, templ, lang)

	var msg bytes.Buffer
	require.NoError(t, templ[lang].Execute(&msg, map[string]string{"VerificationURL": "123"}))
	require.Equal(t, "This is a test template 123", msg.String())
}

// mockDNSResolver implements DNSResolver for testing
type mockDNSResolver struct {
	mxRecords []*net.MX
	mxErr     error
	ipRecords []net.IP
	ipErr     error
}

func (m mockDNSResolver) LookupMX(host string) ([]*net.MX, error) {
	return m.mxRecords, m.mxErr
}

func (m mockDNSResolver) LookupIP(host string) ([]net.IP, error) {
	return m.ipRecords, m.ipErr
}

func TestVerifyMXRecordImplicitMX(t *testing.T) {
	// Save original resolver
	origResolver := DefaultDNSResolver
	defer func() {
		DefaultDNSResolver = origResolver
	}()

	// Mock: no MX records, but valid A record (implicit MX per RFC 5321 Section 5.1)
	DefaultDNSResolver = mockDNSResolver{
		mxRecords: nil,
		mxErr:     nil,
		ipRecords: []net.IP{net.ParseIP("192.0.2.1")},
		ipErr:     nil,
	}

	err := VerifyMXRecord("user@example.com")
	require.NoError(t, err)
}

// withMockResolver swaps in the given resolver for the duration of the test.
func withMockResolver(t *testing.T, r DNSResolver) {
	orig := DefaultDNSResolver
	t.Cleanup(func() { DefaultDNSResolver = orig })
	DefaultDNSResolver = r
}

// TestVerifyMXRecordNonExistentDomain is the regression test for the keyshare task
// infinitely retrying email sends to non-resolvable domains: a domain that does not
// exist (NXDOMAIN, signalled by net.DNSError.IsNotFound) must be rejected permanently
// with ErrInvalidEmailDomain so the address is not retried on every run.
func TestVerifyMXRecordNonExistentDomain(t *testing.T) {
	notFound := &net.DNSError{Err: "no such host", Name: "nonexistent.example", IsNotFound: true}

	// Both the MX and the fallback IP lookup report the domain as non-existent.
	withMockResolver(t, mockDNSResolver{
		mxErr: notFound,
		ipErr: notFound,
	})

	err := VerifyMXRecord("user@nonexistent.example")
	require.ErrorIs(t, err, ErrInvalidEmailDomain)

	// Even when only the MX lookup definitively reports NXDOMAIN, we must not fall
	// through to a network check and end up retrying forever.
	withMockResolver(t, mockDNSResolver{
		mxErr: notFound,
		ipErr: &net.DNSError{Err: "server misbehaving", IsTemporary: true},
	})
	require.ErrorIs(t, VerifyMXRecord("user@nonexistent.example"), ErrInvalidEmailDomain)
}

// TestVerifyMXRecordTransientFailure asserts that a genuine transient failure (DNS
// timeout / no active network connection) returns ErrNoNetwork, so the address keeps
// being retried instead of being permanently discarded as an invalid domain.
func TestVerifyMXRecordTransientFailure(t *testing.T) {
	cases := []struct {
		name string
		err  *net.DNSError
	}{
		{"timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}},
		// "server misbehaving" (SERVFAIL) is ambiguous and must be treated as transient,
		// not as a non-existent domain. It carries the deprecated IsTemporary flag, which
		// we explicitly do not rely on.
		{"server misbehaving", &net.DNSError{Err: "server misbehaving", IsTemporary: true}},
		{"generic network error", &net.DNSError{Err: "connection refused"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Both lookups fail transiently: the MX lookup error is not permanent, so we fall
			// through to the IP lookup, which is also a non-permanent failure.
			withMockResolver(t, mockDNSResolver{
				mxErr: tc.err,
				ipErr: tc.err,
			})

			require.ErrorIs(t, VerifyMXRecord("user@example.com"), ErrNoNetwork)
		})
	}
}

func TestParseEmailAddressRejectsHeaderInjection(t *testing.T) {
	// A valid address parses and exposes only the address part.
	addr, err := ParseEmailAddress("Barry Gibbs <bg@example.com>")
	require.NoError(t, err)
	require.Equal(t, "bg@example.com", addr.Address)

	// Addresses carrying CRLF (an attempt to inject extra SMTP headers) must be rejected,
	// which is what protects the "To:"/"From:" header construction in SendEmail.
	injections := []string{
		"victim@example.com\r\nBcc: attacker@evil.com",
		"victim@example.com\nBcc: attacker@evil.com",
		"victim@example.com\r\nSubject: spoofed",
	}
	for _, in := range injections {
		_, err := ParseEmailAddress(in)
		require.ErrorIs(t, err, ErrInvalidEmail, "input %q must be rejected", in)
	}

	// Even when the input parses, the extracted .Address used in the header must never
	// contain CR or LF, so it cannot break out of its header line.
	parsed, err := ParseEmailAddress("plain@example.com")
	require.NoError(t, err)
	require.NotContains(t, parsed.Address, "\r")
	require.NotContains(t, parsed.Address, "\n")
}
