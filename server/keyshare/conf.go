package keyshare

import "net/smtp"

type EmailConfiguration struct {
	EmailServer     string `json:"email_server" mapstructure:"email_server"`
	EmailFrom       string `json:"email_from" mapstructure:"email_from"`
	DefaultLanguage string `json:"default_language" mapstructure:"default_language"`
	EmailAuth       smtp.Auth
}
