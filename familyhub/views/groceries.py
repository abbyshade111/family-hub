from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import forms, limits
from ..db import get_db
from ..security import login_required

bp = Blueprint("groceries", __name__, url_prefix="/groceries")


def _item_or_404(item_id):
    item = get_db().execute(
        "SELECT id FROM grocery_items WHERE id = ? AND family_id = ?", (item_id, g.user["family_id"])
    ).fetchone()
    if item is None:
        abort(404)
    return item


def _list():
    return get_db().execute(
        """SELECT i.id, i.name, i.quantity, i.checked, u.display_name AS added_by
             FROM grocery_items i LEFT JOIN users u ON u.id = i.added_by
            WHERE i.family_id = ?
            ORDER BY i.checked, i.id DESC LIMIT ?""",
        (g.user["family_id"], limits.GROCERY_ITEMS_PER_FAMILY),
    ).fetchall()


@bp.get("")
@login_required
def index():
    return render_template("groceries.html", items=_list(), values={})


@bp.post("")
@login_required
def create():
    f = forms.FormReader(request.form)
    values = {"name": f.text("name", "Item", 100), "quantity": f.text("quantity", "Quantity", 40, required=False)}
    if f.errors:
        return render_template("groceries.html", items=_list(), values=values, errors=f.errors), 400
    db = get_db()
    limits.lock(db)
    try:
        limits.check_grocery_items(db, g.user["family_id"])
    except limits.LimitReached as reached:
        db.rollback()
        return render_template("groceries.html", items=_list(), values=values, errors=[str(reached)]), 400
    db.execute(
        "INSERT INTO grocery_items (family_id, name, quantity, added_by) VALUES (?, ?, ?, ?)",
        (g.user["family_id"], values["name"], values["quantity"], g.user["id"]),
    )
    db.commit()
    return redirect(url_for("groceries.index", done="added"))


@bp.post("/<id:item_id>/toggle")
@login_required
def toggle(item_id):
    _item_or_404(item_id)
    db = get_db()
    db.execute(
        "UPDATE grocery_items SET checked = 1 - checked WHERE id = ? AND family_id = ?",
        (item_id, g.user["family_id"]),
    )
    db.commit()
    return redirect(url_for("groceries.index"))


@bp.post("/<id:item_id>/delete")
@login_required
def delete(item_id):
    _item_or_404(item_id)
    db = get_db()
    db.execute("DELETE FROM grocery_items WHERE id = ? AND family_id = ?", (item_id, g.user["family_id"]))
    db.commit()
    return redirect(url_for("groceries.index", done="deleted"))


@bp.post("/clear-checked")
@login_required
def clear_checked():
    db = get_db()
    db.execute("DELETE FROM grocery_items WHERE family_id = ? AND checked = 1", (g.user["family_id"],))
    db.commit()
    return redirect(url_for("groceries.index", done="deleted"))
