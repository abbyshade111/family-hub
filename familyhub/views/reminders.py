"""Reminders belong to the person who made them. They can share one with their family:
then everyone in the family sees it and can mark it done (for everyone), but only its
maker can unshare or delete it."""

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import forms, limits
from ..db import get_db
from ..security import login_required

bp = Blueprint("reminders", __name__, url_prefix="/reminders")

# Reminders this person may see: their own, and ones shared by someone in their family.
VISIBLE = """FROM reminders r JOIN users u ON u.id = r.user_id
            WHERE (r.user_id = :me OR (r.shared = 1 AND u.family_id = :family))"""


def _who():
    return {"me": g.user["id"], "family": g.user["family_id"]}


def visible_due(now):
    """Reminders due by `now` that this person should see, for the home page."""
    return get_db().execute(
        f"""SELECT r.id, r.text, r.remind_at, r.shared, u.display_name AS made_by, r.user_id = :me AS mine
            {VISIBLE} AND r.archived = 0 AND r.done = 0 AND r.remind_at <= :now ORDER BY r.remind_at""",
        {**_who(), "now": now},
    ).fetchall()


def _visible_or_404(reminder_id):
    reminder = get_db().execute(
        f"SELECT r.id {VISIBLE} AND r.id = :id", {**_who(), "id": reminder_id}
    ).fetchone()
    if reminder is None:
        abort(404)
    return reminder


def _own_or_404(reminder_id):
    reminder = get_db().execute(
        "SELECT id, shared, archived FROM reminders WHERE id = ? AND user_id = ?", (reminder_id, g.user["id"])
    ).fetchone()
    if reminder is None:
        abort(404)
    return reminder


def _list(archived=False):
    return get_db().execute(
        f"""SELECT r.id, r.text, r.remind_at, r.done, r.shared, r.archived, u.display_name AS made_by,
                   r.user_id = :me AS mine
            {VISIBLE} AND r.archived = :archived ORDER BY r.done, r.remind_at LIMIT :limit""",
        # own reminders are capped at REMINDERS_PER_PERSON; shared ones from others add to the list
        {**_who(), "archived": int(archived), "limit": limits.REMINDERS_PER_PERSON * 10},
    ).fetchall()


def _page(status=200, archived=False, **extra):
    extra.setdefault("values", {})
    return render_template(
        "reminders.html", reminders=_list(archived), now=forms.now_local(), archived=archived, **extra
    ), status


@bp.get("")
@login_required
def index():
    return _page()


@bp.get("/archived")
@login_required
def archived():
    return _page(archived=True)


@bp.post("")
@login_required
def create():
    f = forms.FormReader(request.form)
    values = {
        "text": f.text("text", "Reminder", 200),
        "remind_at": f.datetime("remind_at", "When"),
        "shared": request.form.get("shared") == "1",
    }
    if f.errors:
        return _page(400, values=values, errors=f.errors)
    db = get_db()
    limits.lock(db)
    try:
        limits.check_reminders(db, g.user["id"])
    except limits.LimitReached as reached:
        db.rollback()
        return _page(400, values=values, errors=[str(reached)])
    db.execute(
        "INSERT INTO reminders (user_id, text, remind_at, shared) VALUES (?, ?, ?, ?)",
        (g.user["id"], values["text"], values["remind_at"], int(values["shared"])),
    )
    db.commit()
    return redirect(url_for("reminders.index", done="added"))


@bp.post("/<id:reminder_id>/done")
@login_required
def toggle(reminder_id):
    # Anyone who can see it can mark it done; for a shared reminder that's done for everyone.
    _visible_or_404(reminder_id)
    db = get_db()
    db.execute("UPDATE reminders SET done = 1 - done WHERE id = ?", (reminder_id,))
    db.commit()
    if request.form.get("back") == "home":
        return redirect(url_for("home.index"))
    return redirect(url_for("reminders.index"))


@bp.post("/<id:reminder_id>/share")
@login_required
def share(reminder_id):
    reminder = _own_or_404(reminder_id)
    db = get_db()
    db.execute(
        "UPDATE reminders SET shared = ? WHERE id = ? AND user_id = ?",
        (0 if reminder["shared"] else 1, reminder_id, g.user["id"]),
    )
    db.commit()
    return redirect(url_for("reminders.index", done="unshared" if reminder["shared"] else "shared"))


@bp.post("/<id:reminder_id>/delete")
@login_required
def delete(reminder_id):
    reminder = _own_or_404(reminder_id)
    db = get_db()
    db.execute("DELETE FROM reminders WHERE id = ? AND user_id = ?", (reminder_id, g.user["id"]))
    db.commit()
    return redirect(url_for("reminders.archived" if reminder["archived"] else "reminders.index", done="deleted"))


@bp.post("/<id:reminder_id>/archive")
@login_required
def archive(reminder_id):
    """Archive or restore; like deleting, only the maker can. Archived reminders still count toward the limit."""
    reminder = _own_or_404(reminder_id)
    db = get_db()
    db.execute(
        "UPDATE reminders SET archived = 1 - archived WHERE id = ? AND user_id = ?", (reminder_id, g.user["id"])
    )
    db.commit()
    if reminder["archived"]:
        return redirect(url_for("reminders.archived", done="restored"))
    return redirect(url_for("reminders.index", done="archived"))
