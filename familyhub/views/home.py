from flask import Blueprint, g, render_template

from .. import forms
from ..db import get_db
from ..security import login_required
from . import reminders

bp = Blueprint("home", __name__)


@bp.get("/")
@login_required
def index():
    db = get_db()
    family_id = g.user["family_id"]
    events = db.execute(
        """SELECT id, title, starts_at FROM events
            WHERE family_id = ? AND archived = 0 AND COALESCE(ends_at, starts_at) >= ?
            ORDER BY starts_at LIMIT 5""",
        (family_id, forms.now_local()),
    ).fetchall()
    my_todos = db.execute(
        """SELECT id, title, due_date FROM todos
            WHERE family_id = ? AND archived = 0 AND done = 0 AND assigned_to = ?
            ORDER BY due_date IS NULL, due_date, id LIMIT 10""",
        (family_id, g.user["id"]),
    ).fetchall()
    due_reminders = reminders.visible_due(forms.now_local())
    groceries_left = db.execute(
        "SELECT COUNT(*) FROM grocery_items WHERE family_id = ? AND checked = 0", (family_id,)
    ).fetchone()[0]
    return render_template(
        "home.html", events=events, my_todos=my_todos,
        due_reminders=due_reminders, groceries_left=groceries_left,
    )
