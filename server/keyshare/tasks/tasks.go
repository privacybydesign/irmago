package tasks

import (
	"database/sql"
	"strconv"
	"time"

	"github.com/go-errors/errors"
	_ "github.com/jackc/pgx/stdlib"
	"github.com/lib/pq"
	"github.com/privacybydesign/irmago/server/keyshare"
)

type taskHandler struct {
	conf *Configuration
	db   keyshare.DB
}

func newHandler(conf *Configuration) (*taskHandler, error) {
	err := processConfiguration(conf)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", conf.DBConnStr)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, errors.Errorf("failed to connect to database: %v", err)
	}

	task := &taskHandler{db: keyshare.DB{DB: db}, conf: conf}
	return task, nil
}

func Do(conf *Configuration) error {
	task, err := newHandler(conf)
	if err != nil {
		return err
	}

	task.cleanupEmails()
	task.cleanupTokens()
	task.cleanupAccounts()
	task.expireAccounts()
	task.warnForUpcomingAccountDeletion()

	return nil
}

// Remove email addresses marked for deletion long enough ago
func (t *taskHandler) cleanupEmails() {
	_, err := t.db.Exec("DELETE FROM irma.emails WHERE delete_on < $1", time.Now().Unix())
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove email addresses marked for deletion")
	}
}

// Remove old login and email verification tokens
func (t *taskHandler) cleanupTokens() {
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
func (t *taskHandler) cleanupAccounts() {
	_, err := t.db.Exec("DELETE FROM irma.users WHERE delete_on < $1 AND (coredata IS NULL OR last_seen < delete_on - $2)",
		time.Now().Unix(),
		t.conf.DeleteDelay*24*60*60)
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove accounts scheduled for deletion")
	}
}

// expireAccounts marks inactive accounts having one or more registered email addresses for deletion.
func (t *taskHandler) expireAccounts() {

	// Disable this task when email server is not given
	if t.conf.EmailServer == "" {
		t.conf.Logger.Warning("Expiring accounts is disabled, as no email server is configured")
		return
	}

	_, err := t.db.Exec(`UPDATE irma.users 
		SET delete_on = $1
		WHERE last_seen < $2 AND (
			SELECT count(*)
			FROM irma.emails
			WHERE irma.users.id = irma.emails.user_id
		) > 0`,
		time.Now().Add(time.Duration(24*t.conf.DeleteDelay)*time.Hour).Unix(),
		time.Now().Add(time.Duration(-24*t.conf.ExpiryDelay)*time.Hour).Unix())

	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not update accounts set to expire")
		return
	}
}

// warnForUpcomingAccountDeletion processes marked inactive accounts, handling the sending of expiry mails
func (t *taskHandler) warnForUpcomingAccountDeletion() {

	// Disable this task when email server is not given
	if t.conf.EmailServer == "" {
		t.conf.Logger.Warning("Warning accounts for upcoming deletion is disabled, as no email server is configured")
		return
	}

	// Retry delay is set hardcoded to 15 days. Make sure
	retryUntil := time.Now().Add(time.Duration(24*15) * time.Hour).Unix()
	deleteAfter := time.Now().Add(time.Duration(24*t.conf.DeleteDelay) * time.Hour).Unix()
	expiredAfter := time.Now().Add(time.Duration(-24*t.conf.ExpiryDelay) * time.Hour).Unix()

	// Get all users within the boundary having one or more e-mail addresses.
	// Max 10 per run to prevent flooding of the mailserver.
	rows, err := t.db.Query(`
		SELECT u.id, u.username, u.language, u.delete_on, array_agg(e.email) AS emails
		FROM irma.users AS u
		LEFT JOIN irma.emails AS e ON e.user_id = u.id 
		WHERE u.delete_on < $1 
		AND u.last_seen < $2 AND (
			SELECT count(*)
			FROM irma.emails 
			WHERE irma.emails.user_id = u.id 
		) > 0
		GROUP BY u.id
		LIMIT 10`,
		deleteAfter,
		expiredAfter)

	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not query accounts to warn for upcoming deletion")
		return
	}

	defer rows.Close()

	for rows.Next() {
		var (
			id        int64
			username  string
			lang      string
			delete_on int64
			emails    []string
		)

		mailAndUpdate := func(addr []string) bool {
			err = t.conf.SendEmail(
				t.conf.deleteExpiredAccountTemplate,
				t.conf.DeleteExpiredAccountSubjects,
				map[string]string{"Username": username, "Email": addr[0], "Delay": strconv.Itoa(t.conf.DeleteDelay)},
				addr,
				lang,
			)

			if err != nil {
				t.conf.Logger.WithField("error", err).Error("Could not send account expiry warning email")
				return false
			}

			_, err = t.db.Exec(`UPDATE irma.users 
				SET last_seen = $1, delete_on = $2
				WHERE irma.users.id = $3`,
				time.Now().Unix(),
				deleteAfter,
				id)

			if err != nil {
				t.conf.Logger.WithField("error", err).Error("Could not update last_seen and delete_on for user")
				return false
			}

			return true
		}

		if err := rows.Scan(&id, &username, &lang, &delete_on, (*pq.StringArray)(&emails)); err != nil {
			t.conf.Logger.WithField("error", err).Error("Could not scan row")
			continue
		}

		if delete_on > retryUntil && delete_on < deleteAfter {
			// Normal try: only send an e-mail if within the boundary and all users' e-mail addresses work

			if len(keyshare.GetValidEmails(emails)) != len(emails) {
				continue
			}

			if !mailAndUpdate(emails) {
				continue
			}

		} else if delete_on < retryUntil && delete_on > time.Now().Unix() {
			// Forced try: send an e-mail to the user if at least one e-mail address works

			validEmails := keyshare.GetValidEmails(emails)

			if len(validEmails) == 0 {
				continue
			}

			if !mailAndUpdate(validEmails) {
				continue
			}
		}
	}
}
