from flask import Blueprint, render_template, request, abort

import models
from database import get_db
from utils.security import login_required, roles_required

bp = Blueprint("audit", __name__)


@bp.route("/audit-logs")
@roles_required("admin", "investigator")
def audit_logs():
    db = get_db()
    search = request.args.get("q", "").strip() or None
    action = request.args.get("action", "").strip() or None
    result = request.args.get("result", "").strip() or None
    logs = models.list_audit_logs(db, search=search, action=action, result=result)
    return render_template("audit_logs.html", logs=logs, search=search or "", action=action or "", result=result or "")


@bp.route("/chain-of-custody/<int:evidence_id>")
@login_required
def chain_of_custody(evidence_id):
    db = get_db()
    item = models.get_evidence(db, evidence_id)
    if item is None:
        abort(404)
    trail = models.get_custody_trail(db, evidence_id)
    return render_template("chain_of_custody.html", item=item, trail=trail)
