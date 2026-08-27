import os
from pathlib import Path

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash,
    current_app, send_from_directory, abort
)

import models
from database import get_db
from utils.hashing import compute_sha256_from_stream
from utils.security import (
    login_required, roles_required, allowed_file, build_stored_filename,
    safe_join_upload_path, current_user_id,
)

bp = Blueprint("evidence", __name__, url_prefix="/evidence")


@bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "GET":
        return render_template("upload.html")

    file = request.files.get("evidence_file")
    description = request.form.get("description", "").strip()
    case_reference = request.form.get("case_reference", "").strip()
    db = get_db()

    if file is None or file.filename == "":
        flash("Please choose a file to upload.", "danger")
        return redirect(url_for("evidence.upload"))

    if not allowed_file(file.filename):
        models.log_audit(
            db, action="UPLOAD_REJECTED", user_id=current_user_id(),
            details=f"Rejected file type: {file.filename}", result="FAILURE",
            ip_address=request.remote_addr,
        )
        flash("That file type is not permitted. See the allowed types list on this page.", "danger")
        return redirect(url_for("evidence.upload"))

    original_filename = file.filename
    file_type = original_filename.rsplit(".", 1)[1].lower()

    # Hash BEFORE saving, directly from the upload stream — the hash we
    # register is exactly what the investigator handed us, not a
    # re-read-from-disk copy.
    sha256_hash = compute_sha256_from_stream(file.stream, current_app.config["HASH_CHUNK_SIZE"])

    stored_filename = build_stored_filename(original_filename)
    dest_path = safe_join_upload_path(stored_filename)
    file.save(dest_path)
    file_size_bytes = os.path.getsize(dest_path)

    evidence_id, evidence_uid = models.create_evidence(
        db,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_type=file_type,
        file_size_bytes=file_size_bytes,
        sha256_hash=sha256_hash,
        description=description or None,
        case_reference=case_reference or None,
        uploaded_by=current_user_id(),
    )

    models.add_custody_entry(
        db, evidence_id=evidence_id, user_id=current_user_id(),
        action="Registered", remarks="Evidence registered and SHA-256 hash generated on upload.",
    )
    models.add_custody_entry(
        db, evidence_id=evidence_id, user_id=current_user_id(),
        action="Uploaded", remarks=f"File stored as '{stored_filename}'.",
    )
    models.log_audit(
        db, action="EVIDENCE_UPLOADED", user_id=current_user_id(), evidence_id=evidence_id,
        details=f"{evidence_uid}: {original_filename} ({file_size_bytes} bytes)",
        ip_address=request.remote_addr,
    )

    flash(f"Evidence {evidence_uid} registered. SHA-256 hash generated and stored.", "success")
    return redirect(url_for("evidence.detail", evidence_id=evidence_id))


@bp.route("/")
@login_required
def list_view():
    db = get_db()
    search = request.args.get("q", "").strip() or None
    status = request.args.get("status", "").strip() or None
    file_type = request.args.get("type", "").strip() or None
    items = models.list_evidence(db, search=search, status=status, file_type=file_type)
    return render_template(
        "evidence_list.html", items=items, search=search or "", status=status or "", file_type=file_type or ""
    )


@bp.route("/<int:evidence_id>")
@login_required
def detail(evidence_id):
    db = get_db()
    item = models.get_evidence(db, evidence_id)
    if item is None:
        abort(404)

    models.add_custody_entry(
        db, evidence_id=evidence_id, user_id=current_user_id(),
        action="Accessed", remarks="Evidence details viewed.",
    )
    models.log_audit(
        db, action="EVIDENCE_VIEWED", user_id=current_user_id(), evidence_id=evidence_id,
        ip_address=request.remote_addr,
    )

    custody_trail = models.get_custody_trail(db, evidence_id)
    verification_history = models.list_verification_logs(db, evidence_id=evidence_id)
    return render_template(
        "evidence_detail.html", item=item, custody_trail=custody_trail,
        verification_history=verification_history,
    )


@bp.route("/<int:evidence_id>/download")
@login_required
def download(evidence_id):
    db = get_db()
    item = models.get_evidence(db, evidence_id)
    if item is None:
        abort(404)

    models.add_custody_entry(
        db, evidence_id=evidence_id, user_id=current_user_id(),
        action="Downloaded", remarks="Original evidence file downloaded.",
    )
    models.log_audit(
        db, action="EVIDENCE_DOWNLOADED", user_id=current_user_id(), evidence_id=evidence_id,
        details=item["original_filename"], ip_address=request.remote_addr,
    )

    upload_dir = str(Path(current_app.config["UPLOAD_FOLDER"]).resolve())
    return send_from_directory(upload_dir, item["stored_filename"], as_attachment=True,
                                download_name=item["original_filename"])


@bp.route("/<int:evidence_id>/archive", methods=["POST"])
@roles_required("admin")
def archive(evidence_id):
    db = get_db()
    item = models.get_evidence(db, evidence_id)
    if item is None:
        abort(404)

    new_status = "archived" if item["status"] == "active" else "active"
    models.set_evidence_status(db, evidence_id, new_status)
    models.add_custody_entry(
        db, evidence_id=evidence_id, user_id=current_user_id(),
        action="Archived" if new_status == "archived" else "Reactivated",
        remarks=f"Status changed to {new_status} by admin.",
    )
    models.log_audit(
        db, action="EVIDENCE_STATUS_CHANGED", user_id=current_user_id(), evidence_id=evidence_id,
        details=f"Status set to {new_status}", ip_address=request.remote_addr,
    )
    flash(f"Evidence {item['evidence_uid']} marked {new_status}.", "success")
    return redirect(url_for("evidence.detail", evidence_id=evidence_id))
