package keyshare

import (
	"context"
	"database/sql"

	"github.com/privacybydesign/irmago/internal/common"
)

type DB struct {
	*sql.DB
}

func (db *DB) ExecCountContext(ctx context.Context, query string, args ...interface{}) (int64, error) {
	res, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (db *DB) ExecUserContext(ctx context.Context, query string, args ...interface{}) error {
	c, err := db.ExecCountContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if c != 1 {
		return ErrUserNotFound
	}
	return nil
}

func (db *DB) QueryScanContext(ctx context.Context, query string, results []interface{}, args ...interface{}) error {
	res, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer common.Close(res)
	if !res.Next() {
		if err = res.Err(); err != nil {
			return err
		}
		return sql.ErrNoRows
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

func (db *DB) QueryUserContext(ctx context.Context, query string, results []interface{}, args ...interface{}) error {
	err := db.QueryScanContext(ctx, query, results, args...)
	if err == sql.ErrNoRows {
		return ErrUserNotFound
	}
	return err
}

func (db *DB) QueryIterateContext(ctx context.Context, query string, f func(rows *sql.Rows) error, args ...interface{}) error {
	res, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer common.Close(res)

	for res.Next() {
		if err = f(res); err != nil {
			return err
		}
	}
	return res.Err()
}
