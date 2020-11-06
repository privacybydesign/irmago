package keysharemigrate

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/sirupsen/logrus"
)

type Converter struct {
	source_db *sql.DB
	target_db *sql.DB

	core *keysharecore.KeyshareCore

	logger *logrus.Logger
}

func (c *Converter) ConvertUsers() {
	users, err := c.source_db.Query("SELECT id, username, lastSeen, pin, pinCounter, pinBlockDate, keyshare, enrolled, enabled, language, expiryWarning FROM irma.users")

	if err != nil {
		c.logger.WithField("error", err).Fatal("Could not query database for users")
	}

	defer common.Close(users)

	for users.Next() {
		var source_id int
		var username, pin, keyshare string
		var language *string
		var lastseen, pinBlockDate, expiryWarning *int64
		var pinCounter *int
		var enrolled, enabled bool

		err = users.Scan(&source_id, &username, &lastseen, &pin, &pinCounter, &pinBlockDate, &keyshare, &enrolled, &enabled, &language, &expiryWarning)
		if err != nil {
			c.logger.WithField("error", err).Fatal("Could not scan user row")
		}

		if !enabled || !enrolled {
			// "Delete" user
			continue
		}

		// Ensure language has value as new server uses empty string for missing language
		if language == nil {
			language = new(string)
			*language = ""
		}

		// Ensure we start with a 0 value for lastseen if not provided (we special-case on this later)
		if lastseen == nil {
			lastseen = new(int64)
			*lastseen = 0
		}

		// Ensure pinCounter and pinBlockData have values
		if pinCounter == nil {
			pinCounter = new(int)
			*pinCounter = 0
		}
		if pinBlockDate == nil {
			pinBlockDate = new(int64)
			*pinBlockDate = 0
		}

		// Adjust expiryWarning value if present
		if expiryWarning != nil {
			*expiryWarning += 60 * 60 * 24 * 30 // 30 days wait period
		}

		// Build keyshare core object
		secret, ok := new(big.Int).SetString(keyshare, 16)
		if !ok {
			c.logger.Fatal("Could not convert keyshare secret to big integer")
		}
		coredata, err := c.core.DangerousBuildKeyshareSecret(pin, secret)

		// create user
		var target_id int64
		create_res, err := c.target_db.Query("INSERT INTO irma.users (username, language, coredata, last_seen, pin_counter, pin_block_date, delete_on) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING irma.users.id", username, *language, coredata[:], *lastseen, *pinCounter, *pinBlockDate, expiryWarning)
		if err != nil {
			c.logger.WithField("error", err).Fatal("Problem creating user in new database")
		}
		defer common.Close(create_res)

		if !create_res.Next() {
			c.logger.WithField("error", create_res.Err()).Fatal("Could not retrieve ID of created user")
		}
		err = create_res.Scan(&target_id)
		if err != nil {
			c.logger.WithField("error", err).Fatal("Could not retrieve ID of created user")
		}

		// Convert emails
		emails, err := c.source_db.Query("SELECT email FROM irma.email_addresses WHERE user_id = $1", source_id)
		if err != nil {
			c.logger.WithField("error", err).Fatal("Could not retrieve user email addresses")
		}
		defer common.Close(emails)

		for emails.Next() {
			var email string
			err = emails.Scan(&email)
			if err != nil {
				c.logger.WithField("error", err).Fatal("Could not scan user email row")
			}

			_, err := c.target_db.Exec("INSERT INTO irma.emails (user_id, email) VALUES ($1, $2)", target_id, email)
			if err != nil {
				c.logger.WithField("error", err).Fatal("Could not add email address to user")
			}
		}

		err = emails.Err()
		if err != nil {
			c.logger.WithField("error", err).Fatal("Error during iteration over emails")
		}

		// Convert log entries
		logs, err := c.source_db.Query("SELECT time, event, param FROM irma.log_entry_records WHERE user_id = $1", source_id)
		if err != nil {
			c.logger.WithField("error", err).Fatal("Could not retrieve user email addresses")
		}
		defer common.Close(logs)

		for logs.Next() {
			var time int64
			var event string
			var param int

			err = logs.Scan(&time, &event, &param)
			if err != nil {
				c.logger.WithField("error", err).Fatal("Error scanning log entry row")
			}

			if *lastseen < time {
				*lastseen = time
			}

			params := fmt.Sprintf("%v", param)

			_, err = c.target_db.Exec("INSERT INTO irma.log_entry_records (time, event, param, user_id) VALUES ($1, $2, $3, $4)", time, event, params, target_id)
			if err != nil {
				c.logger.WithField("error", err).Fatal("Error storing log entry in new database")
			}
		}

		err = logs.Err()
		if err != nil {
			c.logger.WithField("error", err).Fatal("Error during iteration over log entries")
		}

		// update lastseen
		if *lastseen == 0 {
			*lastseen = time.Now().Unix()
		}
		_, err = c.target_db.Exec("UPDATE irma.users SET last_seen = $1 WHERE id = $2", *lastseen, target_id)
		if err != nil {
			c.logger.WithField("error", err).Fatal("Could not update lastseen of user")
		}

		// Convert email verification records
		emver, err := c.source_db.Query("SELECT (time_created+timeout) AS expiry_time, email, token FROM irma.email_verification_records WHERE user_id = $1 AND time_verified IS NULL", source_id)
		if err != nil {
			c.logger.WithField("error", err).Fatal("Could not fetch email verification records")
		}
		defer common.Close(emver)

		for emver.Next() {
			var expiry int64
			var email, token string
			err = emver.Scan(&expiry, &email, &token)
			if err != nil {
				c.logger.WithField("error", err).Fatal("Error scanning email verification record row")
			}

			_, err = c.target_db.Exec("INSERT INTO irma.email_verification_tokens (expiry, email, token, user_id) VALUES ($1, $2, $3, $4)", expiry, email, token, source_id)
			if err != nil {
				c.logger.WithField("error", err).Fatal("Could not create email verification record for user")
			}
		}
	}

	err = users.Err()
	if err != nil {
		c.logger.WithField("error", err).Fatal("Error iterating over users from database")
	}
}
