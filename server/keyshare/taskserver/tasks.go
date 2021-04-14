package taskserver

import (
	"bytes"
	"database/sql"
	"time"

	_ "github.com/jackc/pgx/stdlib"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"
)

type TaskHandler struct {
	conf *Configuration
	db   *sql.DB
}

func New(conf *Configuration) (*TaskHandler, error) {
	err := processConfiguration(conf)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", conf.DBConnstring)
	if err != nil {
		return nil, err
	}

	return &TaskHandler{
		db:   db,
		conf: conf,
	}, nil
}

// Remove email addresses marked for deletion long enough ago
func (t *TaskHandler) CleanupEmails() {
	_, err := t.db.Exec("DELETE FROM irma.emails WHERE delete_on < $1", time.Now().Unix())
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove email addresses marked for deletion")
	}
}

// Remove old login and email verifciation tokens
func (t *TaskHandler) CleanupTokens() {
	_, err := t.db.Exec("DELETE FROM irma.email_login_tokens WHERE expiry < $1", time.Now().Unix())
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove email login tokens that have expired")
		return
	}
	_, err = t.db.Exec("DELETE FROM irma.email_verification_tokens WHERE expiry < $1", time.Now().Unix())
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove email verification tokens that have expired")
	}
}

// Cleanup accounts disabled long enough ago.
func (t *TaskHandler) CleanupAccounts() {
	_, err := t.db.Exec("DELETE FROM irma.users WHERE delete_on < $1 AND (coredata IS NULL OR last_seen < delete_on - $2)",
		time.Now().Unix(),
		t.conf.DeleteDelay*24*60*60)
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove accounts scheduled for deletion")
	}
}

func (t *TaskHandler) sendExpiryEmails(id int64, username, lang string) error {
	// Fetch user's email addresses
	emailRes, err := t.db.Query("SELECT email FROM irma.emails WHERE user_id = $1", id)
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not retrieve user's email addresses")
		return err
	}

	// And send emails to each of them.
	for emailRes.Next() {
		var email string
		err = emailRes.Scan(&email)
		if err != nil {
			t.conf.Logger.WithField("error", err).Error("Could not retrieve email address")
			return err
		}

		// Prepare email body
		template, ok := t.conf.DeleteExpiredAccountTemplate[lang]
		if !ok {
			template = t.conf.DeleteExpiredAccountTemplate[t.conf.DefaultLanguage]
		}
		subject, ok := t.conf.DeleteExpiredAccountSubject[lang]
		if !ok {
			subject = t.conf.DeleteExpiredAccountSubject[t.conf.DefaultLanguage]
		}
		var emsg bytes.Buffer
		err = template.Execute(&emsg, map[string]string{"Username": username, "Email": email})
		if err != nil {
			t.conf.Logger.WithField("error", err).Error("Could not render email")
			return err
		}

		// And send
		err = server.SendHTMLMail(
			t.conf.EmailServer,
			t.conf.EmailAuth,
			t.conf.EmailFrom,
			email,
			subject,
			emsg.Bytes())
		if err != nil {
			t.conf.Logger.WithField("error", err).Error("Could not send email")
			return err
		}
	}

	return nil
}

// Mark old unused accounts for deletion, and inform their owners.
func (t *TaskHandler) ExpireAccounts() {
	// Disable this task when email server is not given
	if t.conf.EmailServer == "" {
		t.conf.Logger.Warning("Expiring accounts is disabled, as no email server is configured")
		return
	}

	// Select users we havent seen in ExpiryDelay days, and which have a registered email.
	// We ignore (and thus keep alive) accounts without email addresses, as we cant inform their owners.
	res, err := t.db.Query(`SELECT id, username, language 
							FROM irma.users 
							WHERE last_seen < $1 
								AND (
										SELECT count(*) 
										FROM irma.emails 
										WHERE irma.users.id = irma.emails.user_id
									) > 0 
							LIMIT 10`,
		time.Now().Add(time.Duration(-24*t.conf.ExpiryDelay)*time.Hour).Unix())
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not query for accounts that have expired")
		return
	}
	defer common.Close(res)

	// Send emails and mark for deletion each of the found inactive accounts.
	for res.Next() {
		var id int64
		var username string
		var lang string
		err = res.Scan(&id, &username, &lang)
		if err != nil {
			t.conf.Logger.WithField("error", err).Error("Could not retrieve expired account information")
			return
		}

		// Send emails
		err = t.sendExpiryEmails(id, username, lang)
		if err != nil {
			// already logged, just abort
			return
		}

		// Finally, do marking for deletion
		del, err := t.db.Exec("UPDATE irma.users SET delete_on = $2 WHERE id = $1", id,
			time.Now().Add(time.Duration(24*t.conf.DeleteDelay)*time.Hour).Unix())
		if err != nil {
			t.conf.Logger.WithField("error", err).WithField("id", id).Error("Could not mark user account for deletion")
			return
		}
		aff, err := del.RowsAffected()
		if err != nil {
			t.conf.Logger.WithField("error", err).WithField("id", id).Error("Could not mark user account for deletion")
			return
		}
		if aff != 1 {
			t.conf.Logger.WithField("error", err).WithField("id", id).Error("Could not mark user account for deletion")
			return
		}
	}
	err = res.Err()
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Error during iteration over accounts to be deleted")
	}
}
