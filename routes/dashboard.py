from flask import Blueprint, render_template

import models
from database import get_db
from utils.security import login_required

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    db = get_db()
    stats = models.dashboard_stats(db)
    return render_template("dashboard.html", stats=stats)
