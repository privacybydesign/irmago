package myirmaserver

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/go-errors/errors"
	_ "github.com/jackc/pgx/stdlib"
	"github.com/privacybydesign/irmago/server"
)

type myirmaPostgresDB struct {
	db *sql.DB
}

const EMAIL_TOKEN_VALIDITY = 60 // Ammount of time an email login token is valid (in minutes)

func NewPostgresDatabase(connstring string) (MyirmaDB, error) {
	db, err := sql.Open("pgx", connstring)
	if err != nil {
		return nil, err
	}
	return &myirmaPostgresDB{
		db: db,
	}, nil
}

func (db *myirmaPostgresDB) GetUserID(username string) (int64, error) {
	res, err := db.db.Query("SELECT id FROM irma.users WHERE username = $1", username)
	if err != nil {
		return 0, err
	}
	defer res.Close()
	if !res.Next() {
		return 0, ErrUserNotFound
	}
	var id int64
	err = res.Scan(&id)
	return id, err
}

func (db *myirmaPostgresDB) VerifyEmailToken(token string) (int64, error) {
	res, err := db.db.Query("SELECT user_id, email FROM irma.email_verification_tokens WHERE token = $1 AND expiry >= $2", token, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	defer res.Close()
	if !res.Next() {
		return 0, ErrUserNotFound
	}
	var email string
	var id int64
	err = res.Scan(&id, &email)
	if err != nil {
		return 0, err
	}

	addres, err := db.db.Exec("INSERT INTO irma.email_addresses (user_id, emailAddress) VALUES ($1, $2)", id, email)
	if err != nil {
		return 0, err
	}
	aff, err := addres.RowsAffected()
	if err != nil {
		return 0, err
	}
	if aff != 1 {
		return 0, errors.Errorf("Unexpected number of affected rows for email addition %d", aff)
	}

	// Beyond this point, errors are no longer relevant for frontend, so only log
	delres, err := db.db.Exec("DELETE FROM irma.email_verification_tokens WHERE token = $1", token)
	if err != nil {
		server.LogError(err)
		return id, nil
	}
	aff, err = delres.RowsAffected()
	if err != nil {
		server.LogError(err)
		return id, nil
	}
	if aff != 1 {
		server.LogError(errors.Errorf("Unexpected number of deleted records %d for token", aff))
		return id, nil
	}
	return id, nil
}

func (db *myirmaPostgresDB) RemoveUser(id int64) error {
	res, err := db.db.Exec("DELETE FROM irma.users WHERE id = $1", id)
	if err != nil {
		return err
	}
	aff, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if aff == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (db *myirmaPostgresDB) AddEmailLoginToken(email, token string) error {
	// Check if email address exists in database
	eres, err := db.db.Query("SELECT 1 FROM irma.email_addresses WHERE emailAddress = $1 LIMIT 1", email)
	if err != nil {
		return err
	}
	defer eres.Close()
	if !eres.Next() {
		return ErrUserNotFound
	}

	// insert and verify
	res, err := db.db.Exec("INSERT INTO irma.email_login_tokens (token, email, expiry) VALUES ($1, $2, $3)",
		token,
		email,
		time.Now().Add(EMAIL_TOKEN_VALIDITY*time.Minute).Unix())
	fmt.Println(time.Now().Add(EMAIL_TOKEN_VALIDITY*time.Minute).Unix(), " ", time.Now().Unix())
	if err != nil {
		return err
	}
	aff, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if aff != 1 {
		return errors.Errorf("Unexpected number of affected rows %d on token insert", aff)
	}

	return nil
}

func (db *myirmaPostgresDB) LoginTokenGetCandidates(token string) ([]LoginCandidate, error) {
	res, err := db.db.Query(`SELECT username, lastseen FROM irma.users WHERE id IN
							     (SELECT user_id FROM irma.email_addresses WHERE
									 email_addresses.emailAddress = (SELECT email FROM irma.email_login_tokens WHERE token = $1 AND expiry >= $2))`,
		token, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer res.Close()
	candidates := []LoginCandidate{}
	for res.Next() {
		candidate := LoginCandidate{}
		err = res.Scan(&candidate.Username, &candidate.LastActive)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		return nil, ErrUserNotFound
	}
	return candidates, nil
}

func (db *myirmaPostgresDB) LoginTokenGetEmail(token string) (string, error) {
	res, err := db.db.Query("SELECT email FROM irma.email_login_tokens WHERE token = $1 AND expiry >= $2", token, time.Now().Unix())
	if err != nil {
		return "", err
	}
	defer res.Close()
	if !res.Next() {
		return "", ErrUserNotFound
	}
	var email string
	err = res.Scan(&email)
	return email, err
}

func (db *myirmaPostgresDB) TryUserLoginToken(token, username string) (bool, error) {
	res, err := db.db.Query(`SELECT 1 FROM irma.users INNER JOIN irma.email_addresses ON users.id = email_addresses.user_id WHERE
								 username = $1 AND
								 emailAddress = (SELECT email FROM irma.email_login_tokens WHERE token = $2 AND expiry >= $3)`,
		username, token, time.Now().Unix())
	if err != nil {
		return false, err
	}
	defer res.Close()
	if !res.Next() {
		return false, ErrUserNotFound
	}

	// Successfull deletion of the token can only occur once, so we use that to signal ok to login
	delres, err := db.db.Exec("DELETE FROM irma.email_login_tokens WHERE token = $1", token)
	if err != nil {
		return false, err
	}
	aff, err := delres.RowsAffected()
	if err != nil {
		return false, err
	}
	if aff != 1 {
		return false, nil
	}
	return true, nil
}

func (db *myirmaPostgresDB) GetUserInformation(id int64) (UserInformation, error) {
	var result UserInformation

	// fetch username
	res, err := db.db.Query("SELECT username FROM irma.users WHERE id = $1", id)
	if err != nil {
		return UserInformation{}, err
	}
	defer res.Close()
	if !res.Next() {
		return UserInformation{}, ErrUserNotFound
	}
	err = res.Scan(&result.Username)
	if err != nil {
		return UserInformation{}, err
	}

	// fetch email addresses
	rese, err := db.db.Query("SELECT emailAddress FROM irma.email_addresses WHERE user_id = $1", id)
	if err != nil {
		return UserInformation{}, err
	}
	defer res.Close()
	for rese.Next() {
		var email string
		err = rese.Scan(&email)
		if err != nil {
			return UserInformation{}, err
		}
		result.Emails = append(result.Emails, email)
	}

	return result, nil
}

func (db *myirmaPostgresDB) GetLogs(id int64, offset, ammount int) ([]LogEntry, error) {
	res, err := db.db.Query("SELECT time, event, param FROM irma.log_entry_records WHERE user_id = $1 ORDER BY time DESC OFFSET $2 LIMIT $3",
		id, offset, ammount)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	var result []LogEntry
	for res.Next() {
		var curEntry LogEntry
		var param *string
		err = res.Scan(&curEntry.Timestamp, &curEntry.Event, &param)
		if err != nil {
			return nil, err
		}
		if param == nil {
			curEntry.Param = ""
		} else {
			curEntry.Param = *param
		}
		result = append(result, curEntry)
	}
	return result, nil
}

func (db *myirmaPostgresDB) AddEmail(id int64, email string) error {
	res, err := db.db.Exec("INSERT INTO irma.email_addresses (user_id, emailAddress) VALUES ($1, $2)", id, email)
	if err != nil {
		return err
	}
	aff, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if aff != 1 {
		return errors.Errorf("Unexpected number of affected rows %d for email addition", aff)
	}
	return nil
}

func (db *myirmaPostgresDB) RemoveEmail(id int64, email string) error {
	res, err := db.db.Exec("DELETE FROM irma.email_addresses WHERE id = $1 AND emailAddress = $2", id, email)
	if err != nil {
		return err
	}
	aff, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if aff != 1 {
		return ErrUserNotFound
	}
	return nil
}

func (db *myirmaPostgresDB) SetSeen(id int64) error {
	res, err := db.db.Exec("UPDATE irma.users SET lastSeen = $1 WHERE id = $2", time.Now().Unix(), id)
	if err != nil {
		return err
	}
	c, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if c != 1 {
		return ErrUserNotFound
	}
	return nil
}
