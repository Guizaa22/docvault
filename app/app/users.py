from flask import Blueprint, g, jsonify

from .security import login_required

bp = Blueprint("users", __name__, url_prefix="/api")


@bp.get("/me")
@login_required
def me():
    return jsonify(
        id=g.user["id"], username=g.user["username"], role=g.user["role"]
    )
