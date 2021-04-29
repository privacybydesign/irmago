package keyshare

import (
	"database/sql"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/internal/common"
)

var ErrUserNotFound = errors.New("Could not find specified user")

type DB struct {
	*sql.DB
}

func (db *DB) ExecCount(query string, args ...interface{}) (int64, error) {
	res, err := db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (db *DB) ExecUser(query string, args ...interface{}) error {
	c, err := db.ExecCount(query, args...)
	if err != nil {
		return err
	}
	if c != 1 {
		return ErrUserNotFound
	}
	return nil
}

func (db *DB) QueryUser(query string, results []interface{}, args ...interface{}) error {
	res, err := db.Query(query, args...)
	if err != nil {
		return err
	}
	defer common.Close(res)
	if !res.Next() {
		return ErrUserNotFound
	}
	if results == nil {
		return nil
	}
	err = res.Scan(results...)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) QueryIterate(query string, f func(rows *sql.Rows) error, args ...interface{}) error {
	res, err := db.Query(query, args...)
	if err != nil {
		return err
	}
	defer common.Close(res)

	for res.Next() {
		if err = f(res); err != nil {
			return err
		}
	}
	return nil
}
