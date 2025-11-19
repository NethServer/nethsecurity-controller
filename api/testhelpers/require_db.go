package testhelpers

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// SkipIfNoDB pings the configured REPORT_DB_URI and skips the test if it's not reachable.
// This is conservative and intended to avoid failing DB-dependent tests when no DB is available.
func SkipIfNoDB(t *testing.T) {
	dsn := os.Getenv("REPORT_DB_URI")
	if dsn == "" {
		t.Skip("REPORT_DB_URI not set; skipping DB-dependent test")
		return
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Skipf("cannot open DB: %v; skipping DB-dependent test", err)
		return
	}
	defer db.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := db.Ping(); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}

	t.Skipf("DB not reachable at %s; skipping DB-dependent test", dsn)
}
