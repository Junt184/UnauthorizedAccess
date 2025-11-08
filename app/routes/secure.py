from flask import Blueprint, jsonify, g
from ..utils.jwt import token_required


secure_bp = Blueprint("secure", __name__)


@secure_bp.get("/secure-data")
@token_required()  # 需要 access token
def secure_data():
    return jsonify({
        "message": "This is protected data",
        "user": g.identity,
    })