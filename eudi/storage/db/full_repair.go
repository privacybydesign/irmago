package db

import (
	"database/sql"
	"embed"
	"fmt"
	"strings"
)

//go:embed repair/*.sql
var fullRepairFiles embed.FS

// RunFullRepair executes the full-schema repair script (repair/full_schema_repair.sql)
// against db, creating any table, column or index that is missing compared to the
// canonical schema.
//
// Unlike RunMigrations, this is not tracked by schema_migrations: it can be run at any time
// to repair schema drift, such as a versioned migration that silently failed to apply (e.g.
// because the database was baselined incorrectly). It is idempotent, since every statement
// in the script is safe to run against a database that already has some or all of the
// schema in place.
func RunFullRepair(db *sql.DB) error {
	sqlBytes, err := fullRepairFiles.ReadFile("repair/full_schema_repair.sql")
	if err != nil {
		return fmt.Errorf("load full repair script: %w", err)
	}

	for _, stmt := range strings.Split(string(sqlBytes), ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" || isSQLCommentOnly(stmt) {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			// SQLite has no "ADD COLUMN IF NOT EXISTS"; this is the resulting error when the
			// script's ALTER TABLE statements are re-run against a column that already exists.
			if strings.Contains(err.Error(), "duplicate column name") {
				continue
			}
			return fmt.Errorf("execute %q: %w", stmt[:min(len(stmt), 60)], err)
		}
	}
	return nil
}

// isSQLCommentOnly reports whether stmt has no SQL left once "--" line comments are
// stripped. Splitting the script on ";" is naive: a ";" inside a comment (e.g. explaining
// that SQLite lacks "ADD COLUMN IF NOT EXISTS") produces a fragment that is comment-only.
// sqlite3_prepare_v2 accepts such a fragment (rc == SQLITE_OK) but returns a NULL statement,
// which the cgo driver does not guard against, so it must be filtered out before Exec.
func isSQLCommentOnly(stmt string) bool {
	for _, line := range strings.Split(stmt, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "--") {
			return false
		}
	}
	return true
}
