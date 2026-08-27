"""
SQLite connection handling.

Deliberately raw sqlite3 rather than an ORM: it keeps the dependency list
short, makes the SQL visible and explainable in a viva, and is easy to port
to MySQL later (swap the connector, keep the queries — see README).
"""

import sqlite3
from pathlib import Path
from flask import current_app, g


def get_db():
    """Return a request-scoped SQLite connection, creating one if needed."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    """Create tables from schema.sql if they do not already exist."""
    schema_path = Path(app.root_path) / "database" / "schema.sql"
    with app.app_context():
        db = get_db()
        with open(schema_path, "r", encoding="utf-8") as f:
            db.executescript(f.read())
        db.commit()


def register_db(app):
    app.teardown_appcontext(close_db)
