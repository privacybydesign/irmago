package server

import "net/smtp"

func SendHTMLMail(addr string, a smtp.Auth, from, to, subject string, msg []byte) error {
	headers := []byte("To: " + to + "\r\n" +
		"From: " + from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"Content-Transfer-Encoding: binary\r\n" +
		"\r\n")
	return smtp.SendMail(addr, a, from, []string{to}, append(headers, msg...))
}
