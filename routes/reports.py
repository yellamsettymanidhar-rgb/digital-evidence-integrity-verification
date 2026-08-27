from pathlib import Path

from flask import Blueprint, send_file, current_app, abort, request

import models
from database import get_db
from utils.pdf_report import build_verification_report
from utils.security import login_required, current_user_id, current_username

bp = Blueprint("reports", __name__, url_prefix="/reports")


@bp.route("/verification/<int:log_id>")
@login_required
def verification_report(log_id):
    db = get_db()
    log_row = models.get_verification_log(db, log_id)
    if log_row is None:
        abort(404)

    reports_dir = Path(current_app.config["REPORTS_FOLDER"])
    reports_dir.mkdir(parents=True, exist_ok=True)
    output_path = reports_dir / f"verification_report_{log_row['evidence_uid']}_{log_id}.pdf"

    build_verification_report(str(output_path), log_row=log_row, generated_by=current_username())

    models.log_audit(
        db, action="REPORT_GENERATED", user_id=current_user_id(), evidence_id=log_row["evidence_id"],
        details=f"Verification report for log #{log_id}", ip_address=request.remote_addr,
    )

    return send_file(
        str(output_path), as_attachment=True,
        download_name=f"{log_row['evidence_uid']}_verification_report.pdf",
        mimetype="application/pdf",
    )
