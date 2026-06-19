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
