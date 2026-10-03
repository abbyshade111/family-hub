from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import forms, limits
from ..db import get_db
from ..security import login_required

bp = Blueprint("todos", __name__, url_prefix="/todos")


def _members():
    return get_db().execute(
        "SELECT id, display_name FROM users WHERE family_id = ? ORDER BY display_name", (g.user["family_id"],)
    ).fetchall()


def _todo_or_404(todo_id):
    todo = get_db().execute(
        "SELECT * FROM todos WHERE id = ? AND family_id = ?", (todo_id, g.user["family_id"])
    ).fetchone()
    if todo is None:
        abort(404)
    return todo


def _read_todo(form, members):
    f = forms.FormReader(form)
    values = {
        "title": f.text("title", "To-do", 200),
        "notes": f.text("notes", "Notes", 1000, required=False, multiline=True),
        "assigned_to": f.member("assigned_to", "Who", {m["id"] for m in members}),
        "due_date": f.date("due_date", "Due date"),
    }
    return values, f.errors


def _page(status=200, archived=False, **extra):
    """The to-do list (or the archived one): every open to-do (at most OPEN_TODOS_PER_FAMILY) and the most
    recent done ones."""
    db = get_db()
    family_id = g.user["family_id"]
    columns = """SELECT t.id, t.title, t.due_date, t.done, t.archived, u.display_name AS assignee
                   FROM todos t LEFT JOIN users u ON u.id = t.assigned_to"""
    open_todos = db.execute(
        columns + """ WHERE t.family_id = ? AND t.archived = ? AND t.done = 0
                      ORDER BY t.due_date IS NULL, t.due_date, t.id DESC""",
        (family_id, int(archived)),
    ).fetchall()
    done_todos = db.execute(
        columns + " WHERE t.family_id = ? AND t.archived = ? AND t.done = 1 ORDER BY t.id DESC LIMIT ?",
        (family_id, int(archived), limits.DONE_TODOS_SHOWN),
    ).fetchall()
    done_total = db.execute(
        "SELECT COUNT(*) FROM todos WHERE family_id = ? AND archived = ? AND done = 1", (family_id, int(archived))
    ).fetchone()[0]
    extra.setdefault("members", _members())
    extra.setdefault("values", {})
    return render_template(
        "todos.html", todos=open_todos + done_todos, done_hidden=done_total - len(done_todos),
        archived=archived, **extra,
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
    members = _members()
    values, errors = _read_todo(request.form, members)
    if errors:
        return _page(400, members=members, values=values, errors=errors)
    db = get_db()
    limits.lock(db)
    try:
        limits.check_open_todos(db, g.user["family_id"])
    except limits.LimitReached as reached:
        db.rollback()
        return _page(400, members=members, values=values, errors=[str(reached)])
    todo_id = db.execute(
        "INSERT INTO todos (family_id, title, notes, assigned_to, due_date, created_by) VALUES (?, ?, ?, ?, ?, ?)",
        (g.user["family_id"], values["title"], values["notes"], values["assigned_to"], values["due_date"], g.user["id"]),
    ).lastrowid
    db.commit()
    return redirect(url_for("todos.show", todo_id=todo_id, done="added"))


@bp.get("/<id:todo_id>")
@login_required
def show(todo_id):
    todo = _todo_or_404(todo_id)
    return render_template("todo.html", todo=todo, values=dict(todo), members=_members())


@bp.post("/<id:todo_id>")
@login_required
def update(todo_id):
    todo = _todo_or_404(todo_id)
    members = _members()
    values, errors = _read_todo(request.form, members)
    if errors:
        return render_template("todo.html", todo=todo, values=values, members=members, errors=errors), 400
    db = get_db()
    db.execute(
        "UPDATE todos SET title = ?, notes = ?, assigned_to = ?, due_date = ? WHERE id = ? AND family_id = ?",
        (values["title"], values["notes"], values["assigned_to"], values["due_date"], todo_id, g.user["family_id"]),
    )
    db.commit()
    return redirect(url_for("todos.index", done="saved"))


@bp.post("/<id:todo_id>/toggle")
@login_required
def toggle(todo_id):
    todo = _todo_or_404(todo_id)
    db = get_db()
    if todo["done"]:
        # reopening adds to the open count
        limits.lock(db)
        try:
            limits.check_open_todos(db, g.user["family_id"])
        except limits.LimitReached as reached:
            db.rollback()
            return _page(400, errors=[str(reached)])
    db.execute(
        "UPDATE todos SET done = 1 - done WHERE id = ? AND family_id = ?", (todo_id, g.user["family_id"])
    )
    db.commit()
    return redirect(url_for("todos.archived" if todo["archived"] else "todos.index"))


@bp.post("/<id:todo_id>/delete")
@login_required
def delete(todo_id):
    todo = _todo_or_404(todo_id)
    db = get_db()
    db.execute("DELETE FROM todos WHERE id = ? AND family_id = ?", (todo_id, g.user["family_id"]))
    db.commit()
    return redirect(url_for("todos.archived" if todo["archived"] else "todos.index", done="deleted"))


@bp.post("/<id:todo_id>/archive")
@login_required
def archive(todo_id):
    """Archive or restore. Archived to-dos leave the main list but are kept, and still count toward the limits."""
    todo = _todo_or_404(todo_id)
    db = get_db()
    db.execute(
        "UPDATE todos SET archived = 1 - archived WHERE id = ? AND family_id = ?", (todo_id, g.user["family_id"])
    )
    db.commit()
    if todo["archived"]:
        return redirect(url_for("todos.archived", done="restored"))
    return redirect(url_for("todos.index", done="archived"))
