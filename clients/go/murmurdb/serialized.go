package murmurdb

import (
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"strings"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

var errSQLTransactionControl = errors.New("murmurdb: use database/sql transactions instead of SQL transaction-control statements")

// SQLite prepares each script statement before we inspect its leading token.
// This lexer only distinguishes transaction controls, including comments/BOM;
// statement boundaries and SQL validity remain SQLite's responsibility.
func transactionControl(sql string) bool {
	for {
		sql = strings.TrimLeft(sql, " \t\r\n\f\v;\ufeff")
		if strings.HasPrefix(sql, "--") {
			at := strings.IndexByte(sql, '\n')
			if at < 0 {
				return false
			}
			sql = sql[at+1:]
			continue
		}
		if strings.HasPrefix(sql, "/*") {
			at := strings.Index(sql[2:], "*/")
			if at < 0 {
				return false
			}
			sql = sql[at+4:]
			continue
		}
		break
	}
	n := 0
	for n < len(sql) && ((sql[n] >= 'a' && sql[n] <= 'z') || (sql[n] >= 'A' && sql[n] <= 'Z')) {
		n++
	}
	switch strings.ToUpper(sql[:n]) {
	case "BEGIN", "COMMIT", "END", "ROLLBACK", "SAVEPOINT", "RELEASE":
		return true
	}
	return false
}

func (c *conn) frame(ctx context.Context, fn func() error) error {
	if c.inTx {
		if c.raw.Autocommit() {
			return errors.New("murmurdb: transaction was aborted; roll it back")
		}
		if err := c.raw.Exec("SAVEPOINT murmur_driver_statement"); err != nil {
			return err
		}
		complete := false
		defer func() {
			if !complete && !c.raw.Autocommit() {
				_ = c.raw.Exec("ROLLBACK TO murmur_driver_statement; RELEASE murmur_driver_statement")
			}
		}()
		if err := fn(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.raw.Exec("RELEASE murmur_driver_statement"); err != nil {
			return err
		}
		complete = true
		return nil
	}
	if err := c.beginTransaction(); err != nil {
		return err
	}
	defer func() {
		if c.inTx {
			_ = c.endTransaction(true)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := fn(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.endTransaction(false)
}

func (c *conn) execSerialized(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if strings.IndexByte(query, 0) >= 0 {
		return nil, errors.New("murmurdb: SQL contains NUL")
	}
	var out driver.Result
	err := c.frame(ctx, func() error {
		if len(args) > 0 {
			if transactionControl(query) {
				return errSQLTransactionControl
			}
			var err error
			out, err = c.execLocked(query, args)
			return err
		}
		rest := query
		for strings.TrimSpace(rest) != "" {
			head := rest
			st, tail, err := c.raw.PrepareTail(rest)
			if err != nil {
				return err
			}
			rest = tail
			if st == nil {
				continue
			}
			err = func() error {
				defer st.Close()
				if transactionControl(head) {
					return errSQLTransactionControl
				}
				for {
					if err := ctx.Err(); err != nil {
						return err
					}
					done, err := st.Step()
					if err != nil {
						return err
					}
					if done {
						return nil
					}
				}
			}()
			if err != nil {
				return err
			}
		}
		out = result{rows: c.raw.Changes(), id: c.raw.LastInsertRowID()}
		return nil
	})
	return out, err
}

type bufferedRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (r *bufferedRows) Columns() []string { return r.columns }
func (r *bufferedRows) Close() error      { r.values = nil; return nil }
func (r *bufferedRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}

func statementValues(st *sqlite.Stmt, n int) []driver.Value {
	out := make([]driver.Value, n)
	for i := range out {
		switch st.ColumnType(i) {
		case colInteger:
			out[i] = st.ColumnInt64(i)
		case colFloat:
			out[i] = st.ColumnFloat(i)
		case colText:
			out[i] = st.ColumnText(i)
		case colBlob:
			out[i] = st.ColumnBlob(i)
		}
	}
	return out
}

// Native-resource connections materialize each result inside its frame. No
// native statement or SQLite row pointer escapes into client iteration while
// replication threads can modify the same handle.
func (c *conn) querySerialized(ctx context.Context, query string, args []any) (driver.Rows, error) {
	if strings.IndexByte(query, 0) >= 0 {
		return nil, errors.New("murmurdb: SQL contains NUL")
	}
	if transactionControl(query) {
		return nil, errSQLTransactionControl
	}
	out := &bufferedRows{}
	err := c.frame(ctx, func() error {
		st, cached, err := c.checkout(query)
		if err != nil {
			return err
		}
		defer c.checkin(query, st, cached)
		if err := st.Bind(args...); err != nil {
			return err
		}
		n := st.ColumnCount()
		out.columns = make([]string, n)
		for i := range out.columns {
			out.columns[i] = st.ColumnName(i)
		}
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			done, err := st.Step()
			if err != nil {
				return err
			}
			if done {
				break
			}
			out.values = append(out.values, statementValues(st, n))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
