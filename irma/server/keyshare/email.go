package keyshare

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/irma/server"
)

// DNSResolver is an interface for DNS lookups, allowing injection of test doubles.
type DNSResolver interface {
	LookupMX(host string) ([]*net.MX, error)
	LookupIP(host string) ([]net.IP, error)
}

// netDNSResolver is the default implementation using the net package.
type netDNSResolver struct{}

func (netDNSResolver) LookupMX(host string) ([]*net.MX, error) {
	return net.LookupMX(host)
}

func (netDNSResolver) LookupIP(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

// DefaultDNSResolver is the default DNS resolver used by VerifyMXRecord.
var DefaultDNSResolver DNSResolver = netDNSResolver{}

type EmailConfiguration struct {
	EmailServer     string `json:"email_server" mapstructure:"email_server"`
	EmailHostname   string `json:"email_hostname" mapstructure:"email_hostname"`
	EmailFrom       string `json:"email_from" mapstructure:"email_from"`
	DefaultLanguage string `json:"default_language" mapstructure:"default_language"`
	EmailAuth       smtp.Auth
}

func ParseEmailTemplates(files, subjects map[string]string, defaultLanguage string) (map[string]*template.Template, error) {
	if _, ok := files[defaultLanguage]; !ok {
		return nil, errors.New("missing email file for default language")
	}
	if _, ok := subjects[defaultLanguage]; !ok {
		return nil, errors.New("missing email subject for default language")
	}

	templates := map[string]*template.Template{}
	var err error
	for lang, file := range files {
		templates[lang], err = template.ParseFiles(file)
		if err != nil {
			return nil, err
		}
	}

	return templates, nil
}

func (conf EmailConfiguration) TranslateString(strings map[string]string, lang string) string {
	s, ok := strings[lang]
	if ok {
		return s
	}
	server.Logger.WithField("lang", common.SanitizeForLog(lang)).
		Warn("email string translation requested for unknown language, falling back to default")
	return strings[conf.DefaultLanguage]
}

func (conf EmailConfiguration) translateTemplate(templates map[string]*template.Template, lang string) *template.Template {
	t, ok := templates[lang]
	if ok {
		return t
	}
	server.Logger.WithField("lang", common.SanitizeForLog(lang)).
		Warn("email template translation requested for unknown language, falling back to default")
	return templates[conf.DefaultLanguage]
}

// buildRecipients parses to into bare email addresses suitable for use as SMTP envelope recipients.
// mail.ParseAddressList rejects control characters, so the returned addresses cannot contain CR/LF.
func buildRecipients(to []string) ([]string, error) {
	parsedTo, err := mail.ParseAddressList(strings.Join(to, ","))
	if err != nil {
		return nil, ErrInvalidEmail
	}
	recipients := make([]string, len(parsedTo))
	for i, addr := range parsedTo {
		recipients[i] = addr.Address
	}
	return recipients, nil
}

// sanitizeEmailHeaderValue removes CR/LF to prevent header injection when rendering mail headers.
func sanitizeEmailHeaderValue(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// SendEmail sends a templated email to the supplied email address(es).
// When multiple recipients are specified, the email is sent as a BCC email.
func (conf EmailConfiguration) SendEmail(
	templates map[string]*template.Template,
	subjects map[string]string,
	templateData map[string]string,
	to []string,
	lang string,
) error {
	var content bytes.Buffer
	if err := conf.translateTemplate(templates, lang).Execute(&content, templateData); err != nil {
		server.Logger.WithField("error", err).Error("Could not generate email from template")
		return err
	}

	from, err := ParseEmailAddress(conf.EmailFrom)
	if err != nil {
		// Email address comes from configuration, so this is a server error.
		server.Logger.WithField("error", err).Error("From address in configuration is invalid")
		return err
	}

	if len(to) == 0 {
		return errors.New("no to address specified")
	}

	recipients, err := buildRecipients(to)
	if err != nil {
		return err
	}

	message := bytes.Buffer{}

	// When single recipient, add the To header. Otherwise it is excluded, making this a BCC email.
	// mail.ParseAddressList already rejects CR/LF in addresses; this is defence-in-depth for header rendering.
	if len(to) == 1 {
		fmt.Fprintf(&message, "To: %s\r\n", sanitizeEmailHeaderValue(recipients[0]))
	}

	fmt.Fprintf(&message, "From: %s\r\n", from.Address)
	fmt.Fprintf(&message, "Subject: %s\r\n", conf.TranslateString(subjects, lang))
	fmt.Fprintf(&message, "Content-Type: text/html; charset=UTF-8\r\n")
	fmt.Fprintf(&message, "\r\n")
	fmt.Fprint(&message, content.String())

	// buildRecipients calls mail.ParseAddressList, which rejects CR/LF, making header injection
	// impossible. SanitizeForLog provides defence-in-depth. The taint from user input is broken
	// by the address parsing; CodeQL cannot model this sanitization on source-defined functions.
	// codeql[go/email-injection]
	if err := smtp.SendMail(conf.EmailServer, conf.EmailAuth, from.Address, recipients, message.Bytes()); err != nil {
		server.Logger.WithField("error", err).Error("Could not send email")
		return err
	}

	return nil
}

// ParseEmailAddress parses a single RFC 5322 address, e.g. "Barry Gibbs <bg@example.com>"
func ParseEmailAddress(email string) (*mail.Address, error) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return nil, ErrInvalidEmail
	}

	return addr, nil
}

func (conf EmailConfiguration) VerifyEmailServer() error {
	if conf.EmailServer == "" {
		return nil
	}

	// smtp.Dial does not support timeouts, so we use net.DialTimeout instead.
	conn, err := net.DialTimeout("tcp", conf.EmailServer, 10*time.Second)
	if err != nil {
		return errors.Errorf("failed to connect to email server: %v", err)
	}
	conn.Close()

	client, err := smtp.Dial(conf.EmailServer)
	if err != nil {
		return errors.Errorf("failed to connect to email server: %v", err)
	}
	if conf.EmailHostname != "" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.Errorf("email hostname is specified but email server does not support STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: conf.EmailHostname}); err != nil {
			return errors.Errorf("failed to start TLS on connection to email server: %v", err)
		}
	}
	if conf.EmailAuth != nil {
		if conf.EmailHostname == "" && !strings.HasPrefix(conf.EmailServer, "localhost:") {
			return errors.Errorf("email authentication is enabled but email server is neither using TLS nor running on localhost")
		}
		if err = client.Auth(conf.EmailAuth); err != nil {
			return errors.Errorf("failed to authenticate to email server: %v", err)
		}
	}
	if err = client.Close(); err != nil {
		return errors.Errorf("failed to close connection to email server: %v", err)
	}
	return nil
}

// isPermanentDNSError reports whether err is a DNS lookup failure that will not
// resolve on a retry, i.e. the host definitively does not exist (NXDOMAIN / "no such
// host"). Such failures must yield ErrInvalidEmailDomain so the address is rejected
// instead of being retried on every task run.
//
// Transient failures (timeouts, "server misbehaving"/SERVFAIL, no active network) are
// deliberately NOT treated as permanent so the caller can retry later. We rely on the
// IsNotFound flag only; the IsTemporary flag is populated from net.DNSError's deprecated
// Temporary() method and is intentionally not consulted.
func isPermanentDNSError(err error) bool {
	derr, ok := err.(*net.DNSError)
	return ok && derr.IsNotFound
}

// VerifyMXRecord checks if the given email address has a valid MX record. If none is found, it alternatively
// looks for a valid A or AAAA record as this is used as fallback by mailservers (implicit MX per RFC 5321
// Section 5.1).
//
// It distinguishes a permanent failure (the domain does not exist) from a transient one (no network, DNS
// timeout, server misbehaving): the former returns ErrInvalidEmailDomain so the address is not retried on
// every run, while the latter returns ErrNoNetwork so it is retried later.
func VerifyMXRecord(email string) error {
	if email == "" {
		return ErrInvalidEmail
	}

	host := email[strings.LastIndex(email, "@")+1:]

	records, err := DefaultDNSResolver.LookupMX(host)

	if err != nil || len(records) == 0 {
		// A definitive "no such host" means the domain does not exist and never will on a
		// retry, so reject it permanently rather than mistaking it for a network problem.
		if isPermanentDNSError(err) {
			return ErrInvalidEmailDomain
		}

		// No usable MX records (and no permanent error yet). Look for a valid A or AAAA
		// record, which mailservers use as a fallback when no MX records are present. This
		// IP lookup doubles as the authoritative reachability check: only if it also fails
		// with a non-permanent error do we conclude there is no active network connection.
		ipRecords, ipErr := DefaultDNSResolver.LookupIP(host)
		if ipErr == nil && len(ipRecords) > 0 {
			return nil
		}
		if isPermanentDNSError(ipErr) {
			return ErrInvalidEmailDomain
		}
		if ipErr != nil {
			server.Logger.WithField("error", ipErr).Error("No active network connection")
			return ErrNoNetwork
		}

		// No error but no records either: nothing to deliver mail to.
		return ErrInvalidEmailDomain
	}

	hasValidHost := false
	for _, h := range records {
		// Check if host specified at MX record is valid
		if addr, err := net.LookupHost(h.Host); err == nil && len(addr) > 0 {
			hasValidHost = true
			break
		}
	}

	if !hasValidHost {
		return ErrInvalidEmailDomain
	}

	return nil
}
