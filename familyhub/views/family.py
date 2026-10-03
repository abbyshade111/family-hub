"""Family settings, for the family's admin: its name, who is in it, and invite codes."""

import secrets

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import audit, forms, limits, security
from ..db import get_db
from ..security import admin_required
from .account import confirm_identity

bp = Blueprint("family", __name__, url_prefix="/family")

INVITE_DAYS = 7


def _page(status=200, **extra):
    db = get_db()
    members = db.execute(
        "SELECT id, display_name, email, role FROM users WHERE family_id = ? ORDER BY created_at, id",
        (g.user["family_id"],),
    ).fetchall()
    open_invites = db.execute(
        "SELECT COUNT(*) FROM invites WHERE family_id = ? AND expires_at > ?",
        (g.user["family_id"], security.now()),
    ).fetchone()[0]
    return render_template(
        "family.html", members=members, open_invites=open_invites, invite_days=INVITE_DAYS, **extra
    ), status


@bp.get("")
@admin_required
def index():
    return _page()


@bp.post("/rename")
@admin_required
def rename():
    f = forms.FormReader(request.form)
    name = f.text("name", "Family name", 80)
    if f.errors:
        return _page(400, errors=f.errors)
    db = get_db()
    db.execute("UPDATE families SET name = ? WHERE id = ?", (name, g.user["family_id"]))
    db.commit()
    return redirect(url_for("family.index", done="renamed"))


@bp.post("/invites")
@admin_required
def create_invite():
    code = secrets.token_urlsafe(12)
    db = get_db()
    limits.lock(db)
    try:
        limits.check_and_record_invite(db, g.user["family_id"], g.user["id"])
    except limits.LimitReached as reached:
        db.rollback()
        return _page(429, errors=[str(reached)])
    db.execute("DELETE FROM invites WHERE expires_at <= ?", (security.now(),))
    db.execute(
        "INSERT INTO invites (code_hash, family_id, created_by, expires_at) VALUES (?, ?, ?, ?)",
        (security.lookup_hash(code), g.user["family_id"], g.user["id"],
         security.now() + INVITE_DAYS * 24 * 3600),
    )
    db.commit()
    audit.event("invite_created")
    # Shown once, in this response only; only its hash is kept.
    return _page(new_invite=code)


@bp.post("/invites/revoke")
@admin_required
def revoke_invites():
    db = get_db()
    revoked = db.execute("DELETE FROM invites WHERE family_id = ?", (g.user["family_id"],)).rowcount
    db.commit()
    audit.event("invites_revoked", count=revoked)
    return redirect(url_for("family.index", done="deleted"))


@bp.post("/members/<id:member_id>/promote")
@admin_required
def promote(member_id):
    db = get_db()
    member = db.execute(
        "SELECT role FROM users WHERE id = ? AND family_id = ?", (member_id, g.user["family_id"])
    ).fetchone()
    if member is None:
        abort(404)
    if member["role"] == "admin":
        return redirect(url_for("family.index"))
    # Granting admin is sensitive: the admin confirms it's them, as for other sensitive changes.
    failed = confirm_identity(db, request.form.get("password", ""))
    if failed:
        return _page(failed[1], errors=[failed[0]])
    db.execute(
        "UPDATE users SET role = 'admin' WHERE id = ? AND family_id = ?", (member_id, g.user["family_id"])
    )
    db.commit()
    audit.event("admin_granted", target_user_id=member_id)
    return redirect(url_for("family.index", done="promoted"))
