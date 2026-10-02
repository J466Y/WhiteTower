package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"

	"github.com/J466Y/WhiteTower/internal/platform/db/gen"
)

// The migrations, forward-only (requirement OPS-07), embedded in the binary.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

func migrations() fs.FS {
	sub, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		panic(err) // the directory is embedded
	}
	return sub
}

// ExpectedVersion returns the version of the newest migration in the binary:
// the schema it needs.
var ExpectedVersion = sync.OnceValue(func() int64 {
	entries, err := fs.ReadDir(migrations(), ".")
	if err != nil {
		panic(err)
	}
	var latest int64
	for _, e := range entries {
		v, err := goose.NumericComponent(e.Name())
		if err != nil {
			panic(fmt.Sprintf("migration %s: %v", e.Name(), err))
		}
		latest = max(latest, v)
	}
	return latest
})

var (
	// ErrSchemaBehind means that the database lacks migrations the binary
	// needs.
	ErrSchemaBehind = errors.New("the database schema is older than this binary: run whitetower migrate")
	// ErrSchemaAhead means that the database has migrations the binary does
	// not know.
	ErrSchemaAhead = errors.New("the database schema is newer than this binary")
)

// Version returns the version of the last migration applied to the
// database, or 0 if none has run yet.
func (db *DB) Version(ctx context.Context) (int64, error) {
	v, err := gen.New(db).SchemaVersion(ctx)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42P01" { // undefined_table: nothing migrated yet
		return 0, nil
	}
	return v, err
}

// CheckSchema returns nil when the database's schema is the one the binary
// needs, and otherwise an error that wraps ErrSchemaBehind or
// ErrSchemaAhead. It is the readiness check "schema": the server waits for
// whitetower migrate, and refuses to start on a newer schema.
func (db *DB) CheckSchema(ctx context.Context) error {
	v, err := db.Version(ctx)
	if err != nil {
		return fmt.Errorf("reading the schema version: %w", err)
	}
	switch want := ExpectedVersion(); {
	case v < want:
		return fmt.Errorf("%w (the database is at version %d, the binary needs %d)", ErrSchemaBehind, v, want)
	case v > want:
		return fmt.Errorf("%w (the database is at version %d, the binary knows up to %d); migrations are forward-only: run a newer release",
			ErrSchemaAhead, v, want)
	}
	return nil
}
