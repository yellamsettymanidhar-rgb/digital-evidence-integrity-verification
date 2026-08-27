"""
Security helpers: upload validation, safe filenames, and access-control
decorators used across every route module.
"""

import uuid
from functools import wraps
from pathlib import Path

from flask import current_app, session, redirect, url_for, flash, request, abort
from werkzeug.utils import secure_filename


def allowed_file(filename: str) -> bool:
    """Reject files with no extension or an extension not on the allow-list.
    This blocks obviously dangerous types (.exe, .sh, .php, ...) by omission —
    the allow-list only contains evidence-appropriate types."""
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in current_app.config["ALLOWED_EXTENSIONS"]


def build_stored_filename(original_filename: str) -> str:
    """
    Produce a filename that is safe to place on disk:
    - werkzeug's secure_filename() strips path separators and dangerous
      characters, neutralising path-traversal attempts (e.g. '../../etc/passwd').
    - A UUID4 prefix guarantees uniqueness even if two investigators upload
      files with the same original name, and stops filename guessing.
    The original, human-readable filename is preserved separately in the
    database (evidence.original_filename) for display and reporting.
    """
    safe_name = secure_filename(original_filename) or "evidence_file"
    ext = ""
    if "." in safe_name:
        safe_name, ext = safe_name.rsplit(".", 1)
        ext = "." + ext
    return f"{uuid.uuid4().hex}{ext}"


def safe_join_upload_path(stored_filename: str) -> str:
    """
    Join a stored filename to the upload folder and verify the result is
    still inside the upload folder. Defends against path traversal even if
    a stored_filename were somehow malformed (belt-and-braces on top of
    build_stored_filename already stripping it).
    """
    upload_dir = Path(current_app.config["UPLOAD_FOLDER"]).resolve()
    candidate = (upload_dir / stored_filename).resolve()
    if upload_dir not in candidate.parents:
        abort(400, "Invalid file path.")
    return str(candidate)


# --------------------------------------------------------------------------
# Access control
# --------------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    """Restrict a view to one or more roles, e.g. @roles_required('admin')."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in to continue.", "warning")
                return redirect(url_for("auth.login", next=request.path))
            if session.get("role") not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def current_user_id():
    return session.get("user_id")


def current_username():
    return session.get("username")


def current_role():
    return session.get("role")
