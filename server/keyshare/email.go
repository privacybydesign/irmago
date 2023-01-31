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

var ErrInvalidEmail = errors.New("invalid email address")

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

func (conf EmailConfiguration) SendEmail(
	templates map[string]*template.Template,
	subjects map[string]string,
	templateData map[string]string,
	to []string,
	lang string,
) error {
	var msg bytes.Buffer
	err := conf.translateTemplate(templates, lang).Execute(&msg, templateData)
	if err != nil {
		server.Logger.WithField("error", err).Error("could not generate email from template")
		return err
	}

	// Do validation on email address fields.
	if len(to) == 0 {
		return errors.New("no email address")
	}

	if _, err = mail.ParseAddressList(strings.Join(to, ",")); err != nil {
		return ErrInvalidEmail
	}

	from, err := mail.ParseAddress(conf.EmailFrom)
	if err != nil {
		// Email address comes from configuration, so this is a server error.
		return err
	}

	headers := bytes.NewBuffer(nil)

	// When single recipient, add the To header. Otherwise it is excluded, making this a BCC email
	if len(to) == 1 {
		headers.WriteString(fmt.Sprintf("To: %s\r\n", to[0]))
	}

	headers.WriteString(fmt.Sprintf("From: %s\r\n", from.Address))
	headers.WriteString(fmt.Sprintf("Subject: %s\r\n", conf.TranslateString(subjects, lang)))
	headers.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	headers.WriteString("Content-Transfer-Encoding: binary\r\n")
	headers.WriteString("\r\n")

	err = smtp.SendMail(conf.EmailServer, conf.EmailAuth, from.Address, to, append(headers.Bytes(), msg.Bytes()...))

	if err != nil {
		server.Logger.WithField("error", err).Error("Could not send email")
		return err
	}

	return nil
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

// VerifyMXRecord checks for present and valid MX records on the domain name part of the supplied email address
func VerifyMXRecord(email string) error {

	at := strings.LastIndex(email, "@")
	if at < 0 {
		return errors.Errorf("no '@'-sign found in %v", email)
	}
	records, err := net.LookupMX(email[at+1:])
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return errors.Errorf("no domain part found in %v", email)
	}
	return nil
}
