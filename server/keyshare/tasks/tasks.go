package tasks

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/go-errors/errors"
	_ "github.com/jackc/pgx/stdlib"
	"github.com/privacybydesign/irmago/server/keyshare"
)

const taskTimeout = 30 * time.Second

type taskHandler struct {
	conf           *Configuration
	db             keyshare.DB
	revalidateMail bool
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

	keyshareDB := keyshare.DB{DB: db}

	task := &taskHandler{
		db:             keyshareDB,
		conf:           conf,
		revalidateMail: hasEmailRevalidation(conf, &keyshareDB),
	}

	return task, nil
}

func Do(conf *Configuration) error {
	task, err := newHandler(conf)
	if err != nil {
		return err
	}

	tasks := map[string]func(context.Context){
		"cleanupEmails":   task.cleanupEmails,
		"cleanupTokens":   task.cleanupTokens,
		"cleanupAccounts": task.cleanupAccounts,
		"expireAccounts":  task.expireAccounts,
		"revalidateMails": task.revalidateMails,
	}

	for taskName, taskFunc := range tasks {
		err := runWithTimeout(taskFunc)
		if err != nil {
			conf.Logger.WithField("error", err).Errorf("Task %s exceeded its context deadline", taskName)
		}
	}

	return nil
}

func runWithTimeout(fn func(ctx context.Context)) error {
	ctx, cancel := context.WithTimeout(context.Background(), taskTimeout)
	defer cancel()

	fn(ctx)
	return ctx.Err()
}

func hasEmailRevalidation(conf *Configuration, db *keyshare.DB) bool {
	ctx, cancel := context.WithTimeout(context.Background(), taskTimeout)
	defer cancel()

	c, err := db.ExecCountContext(ctx, "SELECT true FROM information_schema.columns where table_schema='irma' AND table_name='emails' AND column_name='revalidate_on'")
	if err != nil {
		conf.Logger.WithField("error", err).Error("Could not query the schema for column emails.revalidate_on, therefore revalidation is disabled")
		return false
	}

	if c == 0 {
		conf.Logger.Warning("Email address revalidation is disabled because the emails.revalidate_on column is not present in the schema")
		return false
	}

	return true
}

// Remove email addresses marked for deletion long enough ago
func (t *taskHandler) cleanupEmails(ctx context.Context) {
	_, err := t.db.ExecContext(ctx, "DELETE FROM irma.emails WHERE delete_on < $1", time.Now().Unix())
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove email addresses marked for deletion")
	}
}

// Remove old login and email verification tokens
func (t *taskHandler) cleanupTokens(ctx context.Context) {
	_, err := t.db.ExecContext(ctx, "DELETE FROM irma.email_login_tokens WHERE expiry < $1", time.Now().Unix())
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove email login tokens that have expired")
		return
	}
	_, err = t.db.ExecContext(ctx, "DELETE FROM irma.email_verification_tokens WHERE expiry < $1", time.Now().Unix())
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove email verification tokens that have expired")
	}
}

// Cleanup accounts disabled long enough ago.
func (t *taskHandler) cleanupAccounts(ctx context.Context) {
	_, err := t.db.ExecContext(ctx, "DELETE FROM irma.users WHERE delete_on < $1 AND (coredata IS NULL OR last_seen < delete_on - $2)",
		time.Now().Unix(),
		t.conf.DeleteDelay*24*60*60)
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not remove accounts scheduled for deletion")
	}
}

// sendExpiryEmails sends an email to the user informing them their account is expiring in DeleteDelay.
// If sending is not possible due to a (temporary) invalid e-mail address or network error it is marked
// for revalidation.
func (t *taskHandler) sendExpiryEmails(ctx context.Context, id int64, username, lang string) error {
	// Fetch user's email addresses
	err := t.db.QueryIterateContext(ctx, "SELECT id, email FROM irma.emails WHERE user_id = $1",
		func(res *sql.Rows) error {
			var id int64
			var email string
			err := res.Scan(&id, &email)
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

			if err != nil {

				if !t.revalidateMail || err == keyshare.ErrNoNetwork {
					t.conf.Logger.WithField("error", err).Error("Could not send expiry mail")
					return err
				}

				// When email revalidation is enabled and sending was impossible because of
				// (temporary) MX / A record issues at the domain or an invalid email address,
				// we mark the record to be revalidated in 5 days from now.
				if err = t.db.ExecUserContext(ctx, "UPDATE irma.emails SET revalidate_on = $1 WHERE id = $2",
					time.Now().AddDate(0, 0, 5).Unix(),
					id); err != nil {
					t.conf.Logger.WithField("error", err).Error("Could not update email address to set revalidate_on")
					return err
				}
			}
			return nil
		},
		id,
	)
	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not retrieve user's email addresses")
		return err
	}
	return nil
}

// expireAccounts marks old unused accounts for deletion and informs their owners.
// When email revalidation is enabled, email addresses which where marked for revalidation are skipped
// because these will be processed separately inside revalidateEmails.
func (t *taskHandler) expireAccounts(ctx context.Context) {
	// Disable this task when email server is not given
	if t.conf.EmailServer == "" {
		t.conf.Logger.Warning("Expiring accounts is disabled, as no email server is configured")
		return
	}

	query := `
		SELECT id, username, language
		FROM irma.users
		WHERE last_seen < $1 AND (
			SELECT count(*)
			FROM irma.emails
			WHERE irma.users.id = irma.emails.user_id
			{{revalidate}}
		) > 0 AND delete_on IS NULL
		LIMIT 10`

	if t.revalidateMail {
		query = strings.ReplaceAll(query, "{{revalidate}}", "AND irma.emails.revalidate_on IS NULL")
	} else {
		query = strings.ReplaceAll(query, "{{revalidate}}", "")
	}

	// Iterate over users we have not seen in ExpiryDelay days, and which have a registered email.
	// We ignore (and thus keep alive) accounts without email addresses, as we can't inform their owners.
	// (Note that for such accounts we store no email addresses, i.e. no personal data whatsoever.)
	// We do this for only 10 users at a time to prevent us from sending out lots of emails
	// simultaneously, which could lead to our email server being flagged as sending spam.
	// The users excluded by this limit will get their email next time this task is executed.
	err := t.db.QueryIterateContext(ctx, query,
		func(res *sql.Rows) error {
			var id int64
			var username string
			var lang string
			err := res.Scan(&id, &username, &lang)
			if err != nil {
				return err
			}

			// Send emails
			if err := t.sendExpiryEmails(ctx, id, username, lang); err != nil {

				// To have the exact same behavior as before email revalidation functionality,
				// we return nil when the error is ErrInvalidEmail
				if !t.revalidateMail && err == keyshare.ErrInvalidEmail {
					return nil
				}
				return err // already logged, just abort
			}

			// Finally, do marking for deletion
			if err := t.db.ExecUserContext(ctx, "UPDATE irma.users SET delete_on = $2 WHERE id = $1",
				id,
				time.Now().Add(time.Duration(24*t.conf.DeleteDelay)*time.Hour).Unix()); err != nil {
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

// revalidateMails revalidates, when enabled, email addresses which where
// flagged in expireAccounts due to being (temporary) invalid.
func (t *taskHandler) revalidateMails(ctx context.Context) {

	if !t.revalidateMail {
		return
	}

	// Select only 100 records to prevent a potential storm of DNS requests
	err := t.db.QueryIterateContext(ctx, `
		SELECT e.id, e.email
		FROM irma.emails AS e
		WHERE e.revalidate_on < $1 
		LIMIT 100`,
		func(res *sql.Rows) error {
			var id int64
			var email string
			err := res.Scan(&id, &email)
			if err != nil {
				return err
			}

			addr, err := keyshare.ParseEmailAddress(email)

			if err != nil {
				return err
			}

			if err := keyshare.VerifyMXRecord(addr.Host); err != nil {
				if err == keyshare.ErrNoNetwork {
					t.conf.Logger.WithField("error", err).Error("Could not revalidate email address because there is no active network connection")
				} else {
					// When email address still doesn't work, we can assume it's a permanent problem and delete it
					if _, err = t.db.ExecContext(ctx, "DELETE FROM irma.emails WHERE id = $1", id); err != nil {
						t.conf.Logger.WithField("error", err).Error("Could not delete revalidated and still invalid email address")
					}
				}
			} else {
				// When email address works again, clear revalidate_on to prevent unwanted deletion
				if _, err = t.db.ExecContext(ctx, "UPDATE irma.emails SET revalidate_on = NULL WHERE id = $1", id); err != nil {
					t.conf.Logger.WithField("error", err).Error("Could not reset revalidation for email address")
				}
			}

			return nil
		},
		time.Now().Unix())

	if err != nil {
		t.conf.Logger.WithField("error", err).Error("Could not query email addresses for revalidation")
		return
	}
}
