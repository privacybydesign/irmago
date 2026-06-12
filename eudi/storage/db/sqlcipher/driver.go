package sqlcipher

/*
#cgo !android,!windows pkg-config: sqlcipher
#cgo windows CFLAGS: -DSQLITE_HAS_CODEC -IC://msys64/mingw64/include/sqlcipher -Wno-builtin-declaration-mismatch
#cgo windows LDFLAGS: -LC://msys64/mingw64/lib -lsqlcipher -lcrypto -lws2_32
#cgo android LDFLAGS: -lsqlcipher -lcrypto
#include <stdlib.h>
#include <sqlite3.h>
*/
import "C"

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"time"
	"unsafe"
)

func init() {
	sql.Register("sqlcipher", &sqlcipherDriver{})
}

// --- driver.Driver ---

type sqlcipherDriver struct{}

func (d *sqlcipherDriver) Open(dsn string) (driver.Conn, error) {
	return (&Connector{Path: dsn}).Connect(context.Background())
}

// --- Connector ---

// Connector opens a SQLCipher database and sets the encryption key via
// PRAGMA key after the connection is established, keeping the key out of
// the DSN entirely.
type Connector struct {
	Path string
	key  []byte // raw key bytes; empty = no encryption
}

func NewConnector(path string, key []byte) *Connector {
	return &Connector{Path: path, key: key}
}

func (c *Connector) Connect(_ context.Context) (driver.Conn, error) {
	cPath := C.CString(c.Path)
	defer C.free(unsafe.Pointer(cPath))

	var handle *C.sqlite3
	rc := C.sqlite3_open(cPath, &handle)
	if rc != C.SQLITE_OK {
		msg := C.GoString(C.sqlite3_errmsg(handle))
		C.sqlite3_close(handle)
		return nil, fmt.Errorf("sqlite3_open: %s", msg)
	}

	conn := &sqlcipherConn{handle: handle}

	if len(c.key) > 0 {
		pragma := fmt.Sprintf("PRAGMA key = \"x'%x'\"", c.key)
		if err := conn.exec(pragma); err != nil {
			C.sqlite3_close(handle)
			return nil, fmt.Errorf("PRAGMA key: %w", err)
		}
		// Verify the key is correct by reading the database header.
		// SQLCipher defers decryption until the first real read.
		if err := conn.exec("SELECT count(*) FROM sqlite_master"); err != nil {
			C.sqlite3_close(handle)
			return nil, fmt.Errorf("key verification failed: %w", err)
		}
	}

	conn.exec("PRAGMA journal_mode=WAL")
	conn.exec("PRAGMA foreign_keys=ON")

	return conn, nil
}

func (c *Connector) Driver() driver.Driver {
	return &sqlcipherDriver{}
}

// --- driver.Conn ---

type sqlcipherConn struct {
	handle *C.sqlite3
}

func (c *sqlcipherConn) Prepare(query string) (driver.Stmt, error) {
	cSQL := C.CString(query)
	defer C.free(unsafe.Pointer(cSQL))

	var stmt *C.sqlite3_stmt
	rc := C.sqlite3_prepare_v2(c.handle, cSQL, -1, &stmt, nil)
	if rc != C.SQLITE_OK {
		return nil, fmt.Errorf("prepare: %s", C.GoString(C.sqlite3_errmsg(c.handle)))
	}

	numInput := int(C.sqlite3_bind_parameter_count(stmt))
	return &sqlcipherStmt{conn: c, stmt: stmt, numInput: numInput}, nil
}

func (c *sqlcipherConn) Close() error {
	rc := C.sqlite3_close(c.handle)
	if rc != C.SQLITE_OK {
		return fmt.Errorf("close: %s", C.GoString(C.sqlite3_errmsg(c.handle)))
	}
	return nil
}

func (c *sqlcipherConn) Begin() (driver.Tx, error) {
	if err := c.exec("BEGIN"); err != nil {
		return nil, err
	}
	return &sqlcipherTx{conn: c}, nil
}

func (c *sqlcipherConn) exec(sql string) error {
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))

	var errMsg *C.char
	rc := C.sqlite3_exec(c.handle, cSQL, nil, nil, &errMsg)
	if rc != C.SQLITE_OK {
		msg := C.GoString(errMsg)
		C.sqlite3_free(unsafe.Pointer(errMsg))
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// --- driver.Tx ---

type sqlcipherTx struct {
	conn *sqlcipherConn
}

func (tx *sqlcipherTx) Commit() error {
	return tx.conn.exec("COMMIT")
}

func (tx *sqlcipherTx) Rollback() error {
	return tx.conn.exec("ROLLBACK")
}

// --- driver.Stmt ---

type sqlcipherStmt struct {
	conn     *sqlcipherConn
	stmt     *C.sqlite3_stmt
	numInput int
}

func (s *sqlcipherStmt) Close() error {
	if s.stmt == nil {
		return nil
	}
	stmt := s.stmt
	s.stmt = nil
	// Reset the statement to release any locks or unread results before finalizing.
	C.sqlite3_reset(stmt)
	rc := C.sqlite3_finalize(stmt)
	if rc != C.SQLITE_OK {
		return fmt.Errorf("finalize: %s", C.GoString(C.sqlite3_errmsg(s.conn.handle)))
	}
	return nil
}

func (s *sqlcipherStmt) NumInput() int {
	return s.numInput
}

func (s *sqlcipherStmt) bind(args []driver.Value) error {
	C.sqlite3_reset(s.stmt)
	C.sqlite3_clear_bindings(s.stmt)

	for i, arg := range args {
		idx := C.int(i + 1)
		var rc C.int

		switch v := arg.(type) {
		case nil:
			rc = C.sqlite3_bind_null(s.stmt, idx)
		case int64:
			rc = C.sqlite3_bind_int64(s.stmt, idx, C.sqlite3_int64(v))
		case float64:
			rc = C.sqlite3_bind_double(s.stmt, idx, C.double(v))
		case bool:
			if v {
				rc = C.sqlite3_bind_int64(s.stmt, idx, 1)
			} else {
				rc = C.sqlite3_bind_int64(s.stmt, idx, 0)
			}
		case string:
			cStr := C.CString(v)
			rc = C.sqlite3_bind_text(s.stmt, idx, cStr, C.int(len(v)), (*[0]byte)(C.free))
		case time.Time:
			str := v.Format("2006-01-02 15:04:05.999999999-07:00")
			cStr := C.CString(str)
			rc = C.sqlite3_bind_text(s.stmt, idx, cStr, C.int(len(str)), (*[0]byte)(C.free))
		case []byte:
			if len(v) == 0 {
				rc = C.sqlite3_bind_zeroblob(s.stmt, idx, 0)
			} else {
				cBlob := C.CBytes(v)
				rc = C.sqlite3_bind_blob(s.stmt, idx, cBlob, C.int(len(v)), (*[0]byte)(C.free))
			}
		default:
			return fmt.Errorf("unsupported bind type: %T", arg)
		}

		if rc != C.SQLITE_OK {
			return fmt.Errorf("bind %d: %s", i, C.GoString(C.sqlite3_errmsg(s.conn.handle)))
		}
	}
	return nil
}

func (s *sqlcipherStmt) Exec(args []driver.Value) (driver.Result, error) {
	if err := s.bind(args); err != nil {
		return nil, err
	}

	rc := C.sqlite3_step(s.stmt)
	if rc != C.SQLITE_DONE && rc != C.SQLITE_ROW {
		return nil, fmt.Errorf("exec step: %s", C.GoString(C.sqlite3_errmsg(s.conn.handle)))
	}

	lastID := int64(C.sqlite3_last_insert_rowid(s.conn.handle))
	affected := int64(C.sqlite3_changes(s.conn.handle))

	return &sqlcipherResult{lastInsertID: lastID, rowsAffected: affected}, nil
}

func (s *sqlcipherStmt) Query(args []driver.Value) (driver.Rows, error) {
	if err := s.bind(args); err != nil {
		return nil, err
	}

	numCols := int(C.sqlite3_column_count(s.stmt))
	cols := make([]string, numCols)
	for i := range numCols {
		cols[i] = C.GoString(C.sqlite3_column_name(s.stmt, C.int(i)))
	}

	return &sqlcipherRows{stmt: s, cols: cols}, nil
}

// --- driver.Result ---

type sqlcipherResult struct {
	lastInsertID int64
	rowsAffected int64
}

func (r *sqlcipherResult) LastInsertId() (int64, error) {
	return r.lastInsertID, nil
}

func (r *sqlcipherResult) RowsAffected() (int64, error) {
	return r.rowsAffected, nil
}

// --- driver.Rows ---

type sqlcipherRows struct {
	stmt *sqlcipherStmt
	cols []string
}

func (r *sqlcipherRows) Columns() []string {
	return r.cols
}

func (r *sqlcipherRows) Close() error {
	return nil
}

func (r *sqlcipherRows) Next(dest []driver.Value) error {
	rc := C.sqlite3_step(r.stmt.stmt)
	if rc == C.SQLITE_DONE {
		return io.EOF
	}
	if rc != C.SQLITE_ROW {
		return fmt.Errorf("row step: %s", C.GoString(C.sqlite3_errmsg(r.stmt.conn.handle)))
	}

	for i := range dest {
		colType := C.sqlite3_column_type(r.stmt.stmt, C.int(i))
		switch colType {
		case C.SQLITE_NULL:
			dest[i] = nil
		case C.SQLITE_INTEGER:
			dest[i] = int64(C.sqlite3_column_int64(r.stmt.stmt, C.int(i)))
		case C.SQLITE_FLOAT:
			dest[i] = float64(C.sqlite3_column_double(r.stmt.stmt, C.int(i)))
		case C.SQLITE_TEXT:
			n := C.sqlite3_column_bytes(r.stmt.stmt, C.int(i))
			ptr := C.sqlite3_column_text(r.stmt.stmt, C.int(i))
			text := string(C.GoBytes(unsafe.Pointer(ptr), n))
			if t, err := parseDateTime(text); err == nil {
				dest[i] = t
			} else {
				dest[i] = text
			}
		case C.SQLITE_BLOB:
			n := C.sqlite3_column_bytes(r.stmt.stmt, C.int(i))
			blob := C.sqlite3_column_blob(r.stmt.stmt, C.int(i))
			dest[i] = C.GoBytes(blob, n)
		}
	}
	return nil
}

var timeFormats = []string{
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02T15:04:05.999999999-07:00",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

func parseDateTime(s string) (time.Time, error) {
	for _, f := range timeFormats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("not a datetime")
}
