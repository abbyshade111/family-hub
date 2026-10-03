from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import forms, limits
from ..db import get_db
from ..security import login_required

bp = Blueprint("calendar", __name__, url_prefix="/calendar")


def _event_or_404(event_id):
    event = get_db().execute(
        "SELECT * FROM events WHERE id = ? AND family_id = ?", (event_id, g.user["family_id"])
    ).fetchone()
    if event is None:
        abort(404)
    return event


def _read_event(form):
    f = forms.FormReader(form)
    values = {
        "title": f.text("title", "Title", 120),
        "starts_at": f.datetime("starts_at", "Start"),
        "ends_at": f.datetime("ends_at", "End", required=False),
        "notes": f.text("notes", "Notes", 1000, required=False, multiline=True),
    }
    if values["starts_at"] and values["ends_at"] and values["ends_at"] < values["starts_at"]:
        f.errors.append("End can't be before the start.")
    return values, f.errors


def _upcoming():
    return get_db().execute(
        """SELECT e.id, e.title, e.starts_at, e.ends_at, u.display_name AS added_by
             FROM events e LEFT JOIN users u ON u.id = e.created_by
            WHERE e.family_id = ? AND e.archived = 0 AND COALESCE(e.ends_at, e.starts_at) >= ?
            ORDER BY e.starts_at LIMIT ?""",
        (g.user["family_id"], forms.now_local(), limits.UPCOMING_EVENTS_PER_FAMILY),
    ).fetchall()


ARCHIVED_EVENTS_SHOWN = 500


def _archived():
    """Archived events, most recent first; returns (shown, how many more there are)."""
    db = get_db()
    shown = db.execute(
        """SELECT e.id, e.title, e.starts_at, e.ends_at, u.display_name AS added_by
             FROM events e LEFT JOIN users u ON u.id = e.created_by
            WHERE e.family_id = ? AND e.archived = 1
            ORDER BY e.starts_at DESC LIMIT ?""",
        (g.user["family_id"], ARCHIVED_EVENTS_SHOWN),
    ).fetchall()
    total = db.execute(
        "SELECT COUNT(*) FROM events WHERE family_id = ? AND archived = 1", (g.user["family_id"],)
    ).fetchone()[0]
    return shown, total - len(shown)


def _is_upcoming(starts_at, ends_at, now_local):
    return (ends_at or starts_at) >= now_local


def _check_room(db):
    """Take the write lock and refuse if the family's calendar is full. Returns an error message or None."""
    limits.lock(db)
    try:
        limits.check_upcoming_events(db, g.user["family_id"], forms.now_local())
    except limits.LimitReached as reached:
        db.rollback()
        return str(reached)
    return None


@bp.get("")
@login_required
def index():
    return render_template("calendar.html", events=_upcoming(), values={})


@bp.post("")
@login_required
def create():
    values, errors = _read_event(request.form)
    if errors:
        return render_template("calendar.html", events=_upcoming(), values=values, errors=errors), 400
    db = get_db()
    if _is_upcoming(values["starts_at"], values["ends_at"], forms.now_local()):
        full = _check_room(db)
        if full:
            return render_template("calendar.html", events=_upcoming(), values=values, errors=[full]), 400
    db.execute(
        "INSERT INTO events (family_id, title, starts_at, ends_at, notes, created_by) VALUES (?, ?, ?, ?, ?, ?)",
        (g.user["family_id"], values["title"], values["starts_at"], values["ends_at"], values["notes"], g.user["id"]),
    )
    db.commit()
    return redirect(url_for("calendar.index", done="added"))


@bp.get("/<id:event_id>")
@login_required
def show(event_id):
    event = _event_or_404(event_id)
    return render_template("event.html", event=event, values=dict(event))


@bp.post("/<id:event_id>")
@login_required
def update(event_id):
    event = _event_or_404(event_id)
    values, errors = _read_event(request.form)
    if errors:
        return render_template("event.html", event=event, values=values, errors=errors), 400
    db = get_db()
    now = forms.now_local()
    # moving a past event into the future adds to the upcoming count
    if _is_upcoming(values["starts_at"], values["ends_at"], now) and not _is_upcoming(
        event["starts_at"], event["ends_at"], now
    ):
        full = _check_room(db)
        if full:
            return render_template("event.html", event=event, values=values, errors=[full]), 400
    db.execute(
        "UPDATE events SET title = ?, starts_at = ?, ends_at = ?, notes = ? WHERE id = ? AND family_id = ?",
        (values["title"], values["starts_at"], values["ends_at"], values["notes"], event_id, g.user["family_id"]),
    )
    db.commit()
    return redirect(url_for("calendar.index", done="saved"))


@bp.post("/<id:event_id>/delete")
@login_required
def delete(event_id):
    event = _event_or_404(event_id)
    db = get_db()
    db.execute("DELETE FROM events WHERE id = ? AND family_id = ?", (event_id, g.user["family_id"]))
    db.commit()
    return redirect(url_for("calendar.archived" if event["archived"] else "calendar.index", done="deleted"))


@bp.get("/archived")
@login_required
def archived():
    events, hidden = _archived()
    return render_template("calendar_archived.html", events=events, hidden=hidden)


@bp.post("/<id:event_id>/archive")
@login_required
def archive(event_id):
    """Archive or restore. Archived events leave the calendar but are kept, and still count toward the limits."""
    event = _event_or_404(event_id)
    db = get_db()
    db.execute(
        "UPDATE events SET archived = 1 - archived WHERE id = ? AND family_id = ?", (event_id, g.user["family_id"])
    )
    db.commit()
    if event["archived"]:
        return redirect(url_for("calendar.archived", done="restored"))
    return redirect(url_for("calendar.index", done="archived"))
