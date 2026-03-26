package storage

import (
	"database/sql"
	"fmt"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/callbacks"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/migrator"
	"gorm.io/gorm/schema"
)

// Dialector implements gorm.Dialector for SQLCipher.
type Dialector struct {
	DSN string
}

func (d Dialector) Name() string {
	return "sqlite"
}

func (d Dialector) Initialize(db *gorm.DB) error {
	// Register callbacks
	callbacks.RegisterDefaultCallbacks(db, &callbacks.Config{
		CreateClauses: []string{"INSERT", "VALUES", "ON CONFLICT"},
		UpdateClauses: []string{"UPDATE", "SET", "FROM", "WHERE"},
		DeleteClauses: []string{"DELETE", "FROM", "WHERE"},
	})

	sqlDB, err := sql.Open("sqlcipher", d.DSN)
	if err != nil {
		return err
	}
	// SQLite/SQLCipher requires a single connection to avoid issues with
	// in-memory databases (each connection gets its own database) and
	// to prevent concurrent access crashes.
	sqlDB.SetMaxOpenConns(1)
	db.ConnPool = sqlDB

	// Verify the connection works (triggers key validation)
	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("failed to verify database connection: %w", err)
	}

	return nil
}

func (d Dialector) Migrator(db *gorm.DB) gorm.Migrator {
	return &sqlcipherMigrator{
		Migrator: migrator.Migrator{
			Config: migrator.Config{
				DB:                          db,
				Dialector:                   d,
				CreateIndexAfterCreateTable: true,
			},
		},
	}
}

func (d Dialector) DataTypeOf(field *schema.Field) string {
	switch field.DataType {
	case schema.Bool:
		return "numeric"
	case schema.Int, schema.Uint:
		if field.AutoIncrement {
			return "integer PRIMARY KEY AUTOINCREMENT"
		}
		return "integer"
	case schema.Float:
		return "real"
	case schema.String:
		return "text"
	case schema.Time:
		return "datetime"
	case schema.Bytes:
		return "blob"
	default:
		return "text"
	}
}

func (d Dialector) DefaultValueOf(field *schema.Field) clause.Expression {
	return clause.Expr{SQL: "DEFAULT NULL"}
}

func (d Dialector) BindVarTo(writer clause.Writer, stmt *gorm.Statement, v interface{}) {
	writer.WriteByte('?')
}

func (d Dialector) QuoteTo(writer clause.Writer, str string) {
	writer.WriteByte('`')
	if strings.Contains(str, "`") {
		str = strings.ReplaceAll(str, "`", "``")
	}
	writer.WriteString(str)
	writer.WriteByte('`')
}

func (d Dialector) Explain(sql string, vars ...interface{}) string {
	return logger.ExplainSQL(sql, nil, `"`, vars...)
}

// sqlcipherMigrator extends the base GORM migrator with SQLite-specific behavior.
type sqlcipherMigrator struct {
	migrator.Migrator
}

func (m *sqlcipherMigrator) HasTable(value interface{}) bool {
	var count int64
	m.RunWithValue(value, func(stmt *gorm.Statement) error {
		return m.DB.Raw(
			"SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?",
			stmt.Table,
		).Row().Scan(&count)
	})
	return count > 0
}

func (m *sqlcipherMigrator) HasColumn(value interface{}, field string) bool {
	var count int64
	m.RunWithValue(value, func(stmt *gorm.Statement) error {
		name := field
		if f := stmt.Schema.LookUpField(field); f != nil {
			name = f.DBName
		}
		return m.DB.Raw(
			"SELECT count(*) FROM pragma_table_info(?) WHERE name=?",
			stmt.Table, name,
		).Row().Scan(&count)
	})
	return count > 0
}

func (m *sqlcipherMigrator) HasIndex(value interface{}, name string) bool {
	var count int64
	m.RunWithValue(value, func(stmt *gorm.Statement) error {
		if idx := stmt.Schema.LookIndex(name); idx != nil {
			name = idx.Name
		}
		return m.DB.Raw(
			"SELECT count(*) FROM sqlite_master WHERE type='index' AND name=? AND tbl_name=?",
			name, stmt.Table,
		).Row().Scan(&count)
	})
	return count > 0
}
