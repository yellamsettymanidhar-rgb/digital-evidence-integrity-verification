"""
Authentication and user management.

By design there is no public self-registration route: an investigator
account for a forensic tool should be provisioned by someone accountable
(an admin), not created by anyone who reaches the URL. The very first admin
account is created via the `flask create-admin` CLI command in app.py.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash

import models
from database import get_db
from utils.security import roles_required, login_required, current_user_id

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = models.verify_password(db, username, password)

        if user is None:
            models.log_audit(
                db, action="LOGIN_FAILED", details=f"username={username}",
                result="FAILURE", ip_address=request.remote_addr,
            )
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["full_name"] = user["full_name"]
        session["role"] = user["role"]

        models.log_audit(
            db, action="LOGIN", user_id=user["id"],
            details="Successful login", ip_address=request.remote_addr,
        )
        flash(f"Welcome back, {user['full_name']}.", "success")
        next_url = request.args.get("next") or url_for("dashboard.index")
        return redirect(next_url)

    return render_template("login.html")


@bp.route("/logout")
def logout():
    if "user_id" in session:
        db = get_db()
        models.log_audit(db, action="LOGOUT", user_id=session["user_id"], ip_address=request.remote_addr)
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/users", methods=["GET"])
@roles_required("admin")
def manage_users():
    db = get_db()
    users = models.list_users(db)
    return render_template("manage_users.html", users=users)


@bp.route("/users/create", methods=["POST"])
@roles_required("admin")
def create_user():
    db = get_db()
    username = request.form.get("username", "").strip()
    full_name = request.form.get("full_name", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "investigator")

    if role not in ("admin", "investigator"):
        role = "investigator"

    if not username or not full_name or len(password) < 8:
        flash("Username, full name are required and password must be at least 8 characters.", "danger")
        return redirect(url_for("auth.manage_users"))

    if models.username_exists(db, username):
        flash(f"Username '{username}' is already taken.", "danger")
        return redirect(url_for("auth.manage_users"))

    models.create_user(db, username, password, full_name, role)
    models.log_audit(
        db, action="USER_CREATED", user_id=current_user_id(),
        details=f"Created user '{username}' with role '{role}'", ip_address=request.remote_addr,
    )
    flash(f"User '{username}' created as {role}.", "success")
    return redirect(url_for("auth.manage_users"))


@bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@roles_required("admin")
def toggle_user_active(user_id):
    db = get_db()
    user = models.get_user_by_id(db, user_id)
    if user is None:
        flash("User not found.", "danger")
        return redirect(url_for("auth.manage_users"))
    if user["id"] == current_user_id():
        flash("You cannot deactivate your own account.", "warning")
        return redirect(url_for("auth.manage_users"))

    new_state = not bool(user["is_active"])
    models.set_user_active(db, user_id, new_state)
    models.log_audit(
        db, action="USER_STATUS_CHANGED", user_id=current_user_id(),
        details=f"Set user '{user['username']}' active={new_state}", ip_address=request.remote_addr,
    )
    flash(f"User '{user['username']}' {'activated' if new_state else 'deactivated'}.", "success")
    return redirect(url_for("auth.manage_users"))
