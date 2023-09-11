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

// EmailRevalidation returns whether email address revalidation is enabled.
func (db *DB) EmailRevalidation(ctx context.Context) bool {
	c, err := db.ExecCountContext(ctx, "SELECT true FROM information_schema.columns WHERE table_schema='irma' AND table_name='emails' AND column_name='revalidate_on'")
	if err != nil {
		common.Logger.WithField("error", err).Error("Could not query the schema for column emails.revalidate_on, therefore revalidation is disabled")
		return false
	}

	if c == 0 {
		common.Logger.Warning("Email address revalidation is disabled because the emails.revalidate_on column is not present in the schema")
		return false
	}
	return true
}
