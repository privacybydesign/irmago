package keyshare

import (
	"bytes"
	"html/template"
	"net/smtp"

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
	return strings[conf.DefaultLanguage]
}

func (conf EmailConfiguration) translateTemplate(templates map[string]*template.Template, lang string) *template.Template {
	t, ok := templates[lang]
	if ok {
		return t
	}
	return templates[conf.DefaultLanguage]
}

func (conf EmailConfiguration) SendEmail(
	templates map[string]*template.Template,
	subjects map[string]string,
	templateData map[string]string,
	emails []string,
	lang string,
) error {
	var msg bytes.Buffer
	err := conf.translateTemplate(templates, lang).Execute(&msg, templateData)
	if err != nil {
		server.Logger.WithField("error", err).Error("Could not generate email from template")
		return err
	}

	for _, email := range emails {
		err = sendHTMLEmail(
			conf.EmailServer,
			conf.EmailAuth,
			conf.EmailFrom,
			email,
			conf.TranslateString(subjects, lang),
			msg.Bytes(),
		)
		if err != nil {
			server.Logger.WithField("error", err).Error("Could not send email")
			return err
		}
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

func sendHTMLEmail(addr string, a smtp.Auth, from, to, subject string, msg []byte) error {
	headers := []byte("To: " + to + "\r\n" +
		"From: " + from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"Content-Transfer-Encoding: binary\r\n" +
		"\r\n")
	return smtp.SendMail(addr, a, from, []string{to}, append(headers, msg...))
}
