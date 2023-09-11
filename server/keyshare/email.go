package keyshare

import (
	"bytes"
	"fmt"
	"html/template"
	"net"
	"net/mail"
	"net/smtp"
	"strings"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/server"
)

type EmailConfiguration struct {
	EmailServer     string `json:"email_server" mapstructure:"email_server"`
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
	server.Logger.WithField("lang", lang).
		Warn("email string translation requested for unknown language, falling back to default")
	return strings[conf.DefaultLanguage]
}

func (conf EmailConfiguration) translateTemplate(templates map[string]*template.Template, lang string) *template.Template {
	t, ok := templates[lang]
	if ok {
		return t
	}
	server.Logger.WithField("lang", lang).
		Warn("email template translation requested for unknown language, falling back to default")
	return templates[conf.DefaultLanguage]
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

	if _, err = mail.ParseAddressList(strings.Join(to, ",")); err != nil {
		return ErrInvalidEmail
	}

	message := bytes.Buffer{}

	// When single recipient, add the To header. Otherwise it is excluded, making this a BCC email
	if len(to) == 1 {
		fmt.Fprintf(&message, "To: %s\r\n", to[0])
	}

	fmt.Fprintf(&message, "From: %s\r\n", from.Address)
	fmt.Fprintf(&message, "Subject: %s\r\n", conf.TranslateString(subjects, lang))
	fmt.Fprintf(&message, "Content-Type: text/html; charset=UTF-8\r\n")
	fmt.Fprintf(&message, "\r\n")
	fmt.Fprint(&message, content.String())

	if err := smtp.SendMail(conf.EmailServer, conf.EmailAuth, from.Address, to, message.Bytes()); err != nil {
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

	client, err := smtp.Dial(conf.EmailServer)
	if err != nil {
		return errors.Errorf("failed to connect to email server: %v", err)
	}
	if conf.EmailAuth != nil {
		if err = client.Auth(conf.EmailAuth); err != nil {
			return errors.Errorf("failed to authenticate to email server: %v", err)
		}
	}
	if err = client.Close(); err != nil {
		return errors.Errorf("failed to close connection to email server: %v", err)
	}
	return nil
}

// VerifyMXRecord checks if the given email address has a valid MX record. If none is found, it alternatively
// looks for a valid A or AAAA record as this is used as fallback by mailservers
func VerifyMXRecord(email string) error {
	if email == "" {
		return ErrInvalidEmail
	}

	host := email[strings.LastIndex(email, "@")+1:]

	if records, err := net.LookupMX(host); err != nil || len(records) == 0 {
		if err != nil {
			if derr, ok := err.(*net.DNSError); ok && (derr.IsTemporary || derr.IsTimeout) {
				// When DNS is not resolving or there is no active network connection
				server.Logger.WithField("error", err).Error("No active network connection")
				return ErrNoNetwork
			}
		}

		// Check if there is a valid A or AAAA record which is used as fallback by mailservers
		// when there are no MX records present
		if records, err := net.LookupIP(host); err != nil || len(records) == 0 {
			return ErrInvalidEmailDomain
		}
		return nil
	}
	return nil
}
