from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, abort

import models
from database import get_db
from utils.hashing import compute_sha256_from_stream, hashes_match
from utils.security import login_required, current_user_id

bp = Blueprint("verify", __name__, url_prefix="/verify")


@bp.route("/", methods=["GET"])
@login_required
def select():
    db = get_db()
    items = models.list_evidence(db, status="active")
    preselect_id = request.args.get("evidence_id", type=int)
    return render_template("verify.html", items=items, preselect_id=preselect_id)


@bp.route("/run", methods=["POST"])
@login_required
def run():
    db = get_db()
    evidence_id = request.form.get("evidence_id", type=int)
    file = request.files.get("check_file")

    if not evidence_id or file is None or file.filename == "":
        flash("Select the evidence record and choose the file to check.", "danger")
        return redirect(url_for("verify.select"))

    item = models.get_evidence(db, evidence_id)
    if item is None:
        abort(404)

    current_hash = compute_sha256_from_stream(file.stream, current_app.config["HASH_CHUNK_SIZE"])
    original_hash = item["sha256_hash"]
    match = hashes_match(original_hash, current_hash)
    result = "MATCH" if match else "MISMATCH"

    log_id = models.create_verification_log(
        db, evidence_id=evidence_id, verified_by=current_user_id(),
        original_hash=original_hash, current_hash=current_hash, result=result,
        notes=f"Checked file: {file.filename}",
    )
    models.update_last_verification(db, evidence_id, "VERIFIED" if match else "COMPROMISED")
    models.add_custody_entry(
        db, evidence_id=evidence_id, user_id=current_user_id(),
        action="Verified",
        remarks=f"Integrity check result: {'VERIFIED' if match else 'COMPROMISED'}.",
    )
    models.log_audit(
        db, action="EVIDENCE_VERIFIED", user_id=current_user_id(), evidence_id=evidence_id,
        details=f"Result: {result}", result="SUCCESS" if match else "FAILURE",
        ip_address=request.remote_addr,
    )

    return redirect(url_for("verify.result", log_id=log_id))


@bp.route("/result/<int:log_id>")
@login_required
def result(log_id):
    db = get_db()
    log_row = models.get_verification_log(db, log_id)
    if log_row is None:
        abort(404)
    return render_template("verify_result.html", log=log_row)
