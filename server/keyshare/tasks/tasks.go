package tasks

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"github.com/go-errors/errors"
	_ "github.com/jackc/pgx/stdlib"
	"github.com/privacybydesign/irmago/server/keyshare"
)

const dbQueryTimeout = 10 * time.Second

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

	return nil
}

// Remove email addresses marked for deletion long enough ago
func (t *taskHandler) cleanupEmails() {
	ctx, cancel := context.WithTimeout(context.Background(), dbQueryTimeout)
	defer cancel()
	_, err := t.db.ExecContext(ctx, "DELETE FROM irma.emails WHERE delete_on < $1", time.Now().Unix())
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove email addresses marked for deletion")
	}
}

// Remove old login and email verification tokens
func (t *taskHandler) cleanupTokens() {
	ctxLoginTokens, cancelLoginTokens := context.WithTimeout(context.Background(), dbQueryTimeout)
	defer cancelLoginTokens()
	_, err := t.db.ExecContext(ctxLoginTokens, "DELETE FROM irma.email_login_tokens WHERE expiry < $1", time.Now().Unix())
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove email login tokens that have expired")
		return
	}
	ctxVerificationTokens, cancelVerificationTokens := context.WithTimeout(context.Background(), dbQueryTimeout)
	defer cancelVerificationTokens()
	_, err = t.db.ExecContext(ctxVerificationTokens, "DELETE FROM irma.email_verification_tokens WHERE expiry < $1", time.Now().Unix())
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove email verification tokens that have expired")
	}
}

// Cleanup accounts disabled long enough ago.
func (t *taskHandler) cleanupAccounts() {
	ctx, cancel := context.WithTimeout(context.Background(), dbQueryTimeout)
	defer cancel()
	_, err := t.db.ExecContext(ctx, "DELETE FROM irma.users WHERE delete_on < $1 AND (coredata IS NULL OR last_seen < delete_on - $2)",
		time.Now().Unix(),
		t.conf.DeleteDelay*24*60*60)
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove accounts scheduled for deletion")
	}
}

func (t *taskHandler) sendExpiryEmails(id int64, username, lang string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbQueryTimeout)
	defer cancel()
	// Fetch user's email addresses
	err := t.db.QueryIterateContext(ctx, "SELECT email FROM irma.emails WHERE user_id = $1",
		func(emailRes *sql.Rows) error {
			var email string
			err := emailRes.Scan(&email)
			if err != nil {
				return err
			}

			// And send
			err = t.conf.SendEmail(
				t.conf.deleteExpiredAccountTemplate,
				t.conf.DeleteExpiredAccountSubjects,
				map[string]string{"Username": username, "Email": email, "Delay": strconv.Itoa(t.conf.DeleteDelay)},
				email,
				lang,
			)
			return err
		},
		id,
	)
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not retrieve user's email addresses")
		return err
	}
	return nil
}

// Mark old unused accounts for deletion, and inform their owners.
func (t *taskHandler) expireAccounts() {
	// Disable this task when email server is not given
	if t.conf.EmailServer == "" {
		t.conf.Logger.Warning("Expiring accounts is disabled, as no email server is configured")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbQueryTimeout)
	defer cancel()

	// Iterate over users we havent seen in ExpiryDelay days, and which have a registered email.
	// We ignore (and thus keep alive) accounts without email addresses, as we can't inform their owners.
	// (Note that for such accounts we store no email addresses, i.e. no personal data whatsoever.)
	// We do this for only 10 users at a time to prevent us from sending out lots of emails
	// simultaneously, which could lead to our email server being flagged as sending spam.
	// The users excluded by this limit will get their email next time this task is executed.
	err := t.db.QueryIterateContext(ctx, `
		SELECT id, username, language
		FROM irma.users
		WHERE last_seen < $1 AND (
			SELECT count(*)
			FROM irma.emails
			WHERE irma.users.id = irma.emails.user_id
		) > 0 AND delete_on IS NULL
		LIMIT 10`,
		func(res *sql.Rows) error {
			var id int64
			var username string
			var lang string
			err := res.Scan(&id, &username, &lang)
			if err != nil {
				return err
			}

			// Send emails
			err = t.sendExpiryEmails(id, username, lang)
			// FIXME: 'return nil' will prevent abortion of 'expireAccounts()'
			// but will not take care of the actual problem of handling the invalid email
			if err == keyshare.ErrInvalidEmail {
				return nil
			}
			if err != nil {
				return err // already logged, just abort
			}

			ctxMarkDeletion, cancelMarkDeletion := context.WithTimeout(context.Background(), dbQueryTimeout)
			defer cancelMarkDeletion()

			// Finally, do marking for deletion
			err = t.db.ExecUserContext(ctxMarkDeletion, "UPDATE irma.users SET delete_on = $2 WHERE id = $1", id,
				time.Now().Add(time.Duration(24*t.conf.DeleteDelay)*time.Hour).Unix())
			if err != nil {
				return err
			}
			return nil
		},
		time.Now().Add(time.Duration(-24*t.conf.ExpiryDelay)*time.Hour).Unix(),
	)
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not query for accounts that have expired")
		return
	}
}
