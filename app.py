"""
Digital Evidence Integrity Verification System — application entry point.

Run with:  flask run   (after `flask init-db` and `flask create-admin`)
See README.md for full setup instructions.
"""

import getpass
from pathlib import Path

from flask import Flask, render_template, session, redirect, url_for

from config import Config
import database
import models


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure runtime folders exist
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["REPORTS_FOLDER"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)

    database.register_db(app)

    from routes import auth, dashboard, evidence, verify, audit, reports
    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(evidence.bp)
    app.register_blueprint(verify.bp)
    app.register_blueprint(audit.bp)
    app.register_blueprint(reports.bp)

    @app.context_processor
    def inject_user():
        return {
            "current_user": {
                "id": session.get("user_id"),
                "username": session.get("username"),
                "full_name": session.get("full_name"),
                "role": session.get("role"),
            }
        }

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(413)
    def too_large(e):
        return render_template("404.html", message="File too large. See the size limit on the upload page."), 413

    register_cli(app)
    return app


def register_cli(app):
    @app.cli.command("init-db")
    def init_db_command():
        """Create database tables from database/schema.sql."""
        database.init_db(app)
        print(f"Database initialized at {app.config['DATABASE_PATH']}")

    @app.cli.command("create-admin")
    def create_admin_command():
        """Interactively create the first admin account (or another admin)."""
        with app.app_context():
            db = database.get_db()
            username = input("Admin username: ").strip()
            if models.username_exists(db, username):
                print(f"Username '{username}' already exists.")
                return
            full_name = input("Full name: ").strip()
            password = getpass.getpass("Password (min 8 chars): ")
            if len(password) < 8:
                print("Password must be at least 8 characters.")
                return
            models.create_user(db, username, password, full_name, role="admin")
            print(f"Admin account '{username}' created.")


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
