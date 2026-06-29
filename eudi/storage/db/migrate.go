package db

import (
	"database/sql"
	"embed"
	"fmt"
	"io"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// RunMigrations applies all pending SQL migrations to the given database connection.
// It is idempotent: already-applied migrations are skipped.
//
// For databases that were created before this migration system was introduced (i.e. via
// GORM AutoMigrate), baseline detection runs automatically: the current schema is
// inspected to determine which migrations have already been applied, and the
// schema_migrations table is seeded accordingly before any new migrations run.
func RunMigrations(db *sql.DB) error {
	src, err := iofs.New(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("load migration source: %w", err)
	}

	driver := &sqlcipherMigrateDriver{db: db}
	if err := driver.ensureMigrationsTable(); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}
	if err := driver.baselineIfNeeded(); err != nil {
		return fmt.Errorf("baseline existing database: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "sqlcipher", driver)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("run migrations: %w", err)
	}
	return nil
}

// baselineIfNeeded seeds schema_migrations for databases that were created before
// the migration system was introduced. It is a no-op on fresh databases and on
// databases that are already tracked.
//
// Detection logic:
//   - No tables at all → fresh database, let migrations run normally.
//   - credential_batches has a credential_type column → w3c-vcdm schema already applied;
//     baseline at version 2 (000002_w3c_vcdm_support).
//   - credential_batches exists but lacks that column → master baseline schema;
//     baseline at version 1 (000001_initial_schema).
func (d *sqlcipherMigrateDriver) baselineIfNeeded() error {
	version, _, err := d.Version()
	if err != nil {
		return err
	}
	if version != database.NilVersion {
		return nil // already tracked
	}

	// Use credential_batches as the presence sentinel: it is the central application table
	// that has existed since the first version of this schema.
	var credBatchExists int
	if err := d.db.QueryRow(
		"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='credential_batches'",
	).Scan(&credBatchExists); err != nil {
		return err
	}
	if credBatchExists == 0 {
		return nil // fresh database, let migrations run normally
	}

	var hasCredentialType int
	if err := d.db.QueryRow(
		"SELECT count(*) FROM pragma_table_info('credential_batches') WHERE name='credential_type'",
	).Scan(&hasCredentialType); err != nil {
		return err
	}

	if hasCredentialType > 0 {
		return d.SetVersion(2, false)
	}
	return d.SetVersion(1, false)
}

// sqlcipherMigrateDriver implements github.com/golang-migrate/migrate/v4/database.Driver
// using the existing SQLCipher *sql.DB connection, without introducing an additional CGO
// SQLite dependency.
type sqlcipherMigrateDriver struct {
	db *sql.DB
}

func (d *sqlcipherMigrateDriver) ensureMigrationsTable() error {
	_, err := d.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version  bigint NOT NULL,
		dirty    boolean NOT NULL,
		PRIMARY KEY (version)
	)`)
	return err
}

func (d *sqlcipherMigrateDriver) Open(url string) (database.Driver, error) {
	return nil, fmt.Errorf("Open is not supported; use migrate.NewWithInstance")
}

func (d *sqlcipherMigrateDriver) Close() error {
	return nil // the caller owns the connection
}

// Lock and Unlock are no-ops because the SQLCipher connection is configured with
// MaxOpenConns(1), so concurrent access is already serialized at the connection level.
func (d *sqlcipherMigrateDriver) Lock() error   { return nil }
func (d *sqlcipherMigrateDriver) Unlock() error { return nil }

// Run executes a migration file. The SQLCipher driver's Prepare uses sqlite3_prepare_v2
// which only compiles a single statement, so each statement must be executed separately.
func (d *sqlcipherMigrateDriver) Run(migration io.Reader) error {
	sqlBytes, err := io.ReadAll(migration)
	if err != nil {
		return err
	}
	for _, stmt := range strings.Split(string(sqlBytes), ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := d.db.Exec(stmt); err != nil {
			return fmt.Errorf("execute %q: %w", stmt[:min(len(stmt), 60)], err)
		}
	}
	return nil
}

func (d *sqlcipherMigrateDriver) SetVersion(version int, dirty bool) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec("DELETE FROM schema_migrations"); err != nil {
		return err
	}
	if version != database.NilVersion {
		if _, err := tx.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (?, ?)", version, dirty); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *sqlcipherMigrateDriver) Version() (int, bool, error) {
	var version int
	var dirty bool
	err := d.db.QueryRow("SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty)
	if err == sql.ErrNoRows {
		return database.NilVersion, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return version, dirty, nil
}

func (d *sqlcipherMigrateDriver) Steps(n int) error { return nil }

func (d *sqlcipherMigrateDriver) Drop() error {
	rows, err := d.db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, table := range tables {
		if _, err := d.db.Exec("DROP TABLE IF EXISTS `" + table + "`"); err != nil {
			return err
		}
	}
	return nil
}
