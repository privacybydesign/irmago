package keyshare

import (
	"bufio"
	"bytes"
	"net"
	"path/filepath"
	"strings"
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

func TestBuildRecipients(t *testing.T) {
	// Single plain address.
	got, err := buildRecipients([]string{"user@example.com"})
	require.NoError(t, err)
	require.Equal(t, []string{"user@example.com"}, got)

	// Display name is stripped, only the bare address is returned.
	got, err = buildRecipients([]string{"Alice <alice@example.com>"})
	require.NoError(t, err)
	require.Equal(t, []string{"alice@example.com"}, got)

	// Multiple recipients (BCC case): each address is included in the SMTP envelope.
	got, err = buildRecipients([]string{"alice@example.com", "bob@example.com"})
	require.NoError(t, err)
	require.Equal(t, []string{"alice@example.com", "bob@example.com"}, got)

	// Invalid address is rejected.
	_, err = buildRecipients([]string{"not-an-email"})
	require.ErrorIs(t, err, ErrInvalidEmail)

	// CR/LF injection is rejected.
	_, err = buildRecipients([]string{"victim@example.com\r\nBcc: attacker@evil.com"})
	require.ErrorIs(t, err, ErrInvalidEmail)
}

// fakeSMTPServer is a minimal in-process SMTP server that captures the envelope
// recipients (RCPT TO) and the raw message produced by SendEmail, without needing
// an external mail server. It speaks just enough of SMTP for net/smtp's SendMail:
// it greets, answers EHLO without advertising any extensions (so no STARTTLS/AUTH
// is attempted), and records MAIL FROM / RCPT TO / DATA before QUIT.
type fakeSMTPServer struct {
	listener net.Listener
	done     chan struct{}
	mailFrom string
	rcptTo   []string
	data     string
}

// startFakeSMTPServer starts the server on a random loopback port and arranges for
// it to be closed when the test finishes. It handles exactly one connection, which
// is all a single SendEmail call makes.
func startFakeSMTPServer(t *testing.T) *fakeSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &fakeSMTPServer{listener: ln, done: make(chan struct{})}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s
}

func (s *fakeSMTPServer) addr() string { return s.listener.Addr().String() }

func (s *fakeSMTPServer) serve() {
	defer close(s.done)
	conn, err := s.listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	reply := func(line string) {
		_, _ = w.WriteString(line + "\r\n")
		_ = w.Flush()
	}

	reply("220 fakesmtp ready")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
			// Single 250 line => no advertised extensions => SendMail skips STARTTLS/AUTH.
			reply("250 fakesmtp")
		case strings.HasPrefix(line, "MAIL FROM"):
			s.mailFrom = line
			reply("250 OK")
		case strings.HasPrefix(line, "RCPT TO"):
			s.rcptTo = append(s.rcptTo, line)
			reply("250 OK")
		case line == "DATA":
			reply("354 End data with <CR><LF>.<CR><LF>")
			var body strings.Builder
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if dl == ".\r\n" || dl == ".\n" {
					break
				}
				body.WriteString(dl)
			}
			s.data = body.String()
			reply("250 OK")
		case line == "QUIT":
			reply("221 Bye")
			return
		default:
			reply("250 OK")
		}
	}
}

// TestSendEmailEnvelopeAndHeaders is the happy-path counterpart to
// TestBuildRecipients / TestParseEmailAddressRejectsHeaderInjection: it asserts that
// SendEmail, after the switch to recipients built from the parsed addresses, still
// delivers a valid message to the expected SMTP envelope recipient(s). It covers the
// behavioural change end-to-end, including the single-recipient (To: header present)
// and multi-recipient (BCC, To: header omitted) cases.
func TestSendEmailEnvelopeAndHeaders(t *testing.T) {
	lang := "en"
	testdataPath := test.FindTestdataFolder(t)
	templates, err := ParseEmailTemplates(
		map[string]string{lang: filepath.Join(testdataPath, "emailtemplate.html")},
		map[string]string{lang: "Test subject"},
		lang,
	)
	require.NoError(t, err)
	subjects := map[string]string{lang: "Test subject"}
	templateData := map[string]string{"VerificationURL": "123"}

	t.Run("single recipient sets To header and envelope recipient", func(t *testing.T) {
		srv := startFakeSMTPServer(t)
		conf := EmailConfiguration{
			EmailServer:     srv.addr(),
			EmailFrom:       "sender@example.com",
			DefaultLanguage: lang,
		}

		// A display name must be stripped to the bare address in the envelope.
		err := conf.SendEmail(templates, subjects, templateData, []string{"Alice <alice@example.com>"}, lang)
		require.NoError(t, err)
		<-srv.done

		require.Contains(t, srv.mailFrom, "<sender@example.com>")
		require.Equal(t, []string{"alice@example.com"}, envelopeAddresses(srv.rcptTo))
		require.Contains(t, srv.data, "To: alice@example.com\r\n")
		require.Contains(t, srv.data, "From: sender@example.com\r\n")
		require.Contains(t, srv.data, "Subject: Test subject\r\n")
		require.Contains(t, srv.data, "This is a test template 123")
	})

	t.Run("multiple recipients are BCC and omit the To header", func(t *testing.T) {
		srv := startFakeSMTPServer(t)
		conf := EmailConfiguration{
			EmailServer:     srv.addr(),
			EmailFrom:       "sender@example.com",
			DefaultLanguage: lang,
		}

		err := conf.SendEmail(
			templates, subjects, templateData,
			[]string{"alice@example.com", "Bob <bob@example.com>"},
			lang,
		)
		require.NoError(t, err)
		<-srv.done

		// Both addresses are delivered as envelope recipients, regardless of the To header.
		require.Equal(t, []string{"alice@example.com", "bob@example.com"}, envelopeAddresses(srv.rcptTo))
		// No To header is rendered for multi-recipient (BCC) mail.
		require.NotContains(t, srv.data, "To: ")
		require.Contains(t, srv.data, "This is a test template 123")
	})

	t.Run("invalid recipient is rejected before sending", func(t *testing.T) {
		conf := EmailConfiguration{
			EmailServer:     "127.0.0.1:0", // never dialled: parsing fails first
			EmailFrom:       "sender@example.com",
			DefaultLanguage: lang,
		}
		err := conf.SendEmail(templates, subjects, templateData, []string{"not-an-email"}, lang)
		require.ErrorIs(t, err, ErrInvalidEmail)
	})
}

// envelopeAddresses extracts the bare addresses from captured "RCPT TO:<addr>" lines.
func envelopeAddresses(rcptTo []string) []string {
	addrs := make([]string, 0, len(rcptTo))
	for _, line := range rcptTo {
		start := strings.IndexByte(line, '<')
		end := strings.IndexByte(line, '>')
		if start >= 0 && end > start {
			addrs = append(addrs, line[start+1:end])
		}
	}
	return addrs
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
