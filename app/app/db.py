"""Database access layer supporting both SQLite (default) and PostgreSQL.

Backend is chosen at runtime: if DATABASE_URL is set the app uses PostgreSQL
(psycopg), otherwise it uses a local SQLite file. A thin wrapper gives both a
uniform interface, and the app's queries use '?' placeholders throughout —
translated to '%s' for PostgreSQL.
"""
import sqlite3

from flask import current_app, g


class _DB:
    def __init__(self, conn, pg):
        self._conn = conn
        self.pg = pg

    def execute(self, sql, params=()):
        if self.pg:
            sql = sql.replace("?", "%s")
        return self._conn.execute(sql, params)

    def executescript(self, sql):
        return self._conn.executescript(sql)

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()


def _connect():
    url = current_app.config.get("DATABASE_URL")
    if url:
        import psycopg
        from psycopg.rows import dict_row
        return _DB(psycopg.connect(url, row_factory=dict_row), pg=True)
    conn = sqlite3.connect(current_app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return _DB(conn, pg=False)


def get_db():
    if "db" not in g:
        g.db = _connect()
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def insert_returning_id(db, base_sql, params):
    """Run an INSERT and return the new row's id, portably across backends."""
    if db.pg:
        return db.execute(base_sql + " RETURNING id", params).fetchone()["id"]
    return db.execute(base_sql, params).lastrowid


def integrity_errors():
    """Exception types raised on a unique/constraint violation, per backend."""
    errs = [sqlite3.IntegrityError]
    try:
        import psycopg
        errs.append(psycopg.errors.IntegrityError)
    except Exception:
        pass
    return tuple(errs)


def init_db():
    db = get_db()
    schema = "schema.postgres.sql" if db.pg else "schema.sql"
    with current_app.open_resource(schema) as f:
        sql = f.read().decode("utf-8")
    if db.pg:
        for stmt in sql.split(";"):
            if stmt.strip():
                db.execute(stmt)
    else:
        db.executescript(sql)
    db.commit()
