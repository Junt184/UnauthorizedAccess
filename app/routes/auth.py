from flask import Blueprint, request, jsonify, current_app, g
from ..utils.jwt import get_jwt_manager, token_required


auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/login")
def login():
    """示例登录接口：演示如何签发 access/refresh JWT。

    给新手的解释：
    - 正常项目里，登录会去验证“用户名 + 密码是否匹配数据库里的记录”。
    - 本示例为了简化，只要传入了 username 和 password，就当作登录成功。
    - 登录成功后，我们会生成两个令牌：
      * access_token：访问受保护接口用，过期时间较短；
      * refresh_token：用来换新的 access_token，过期时间较长。
    - 响应里返回这两个令牌，前端或页面可自行保存（示例站点使用 Cookie 保存）。
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    identity = {"user_id": 1, "username": username, "role": "user"}
    manager = get_jwt_manager()
    access = manager.encode_access_token(identity)
    refresh = manager.encode_refresh_token(identity)
    return jsonify({
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": current_app.config.get("JWT_ACCESS_TOKEN_EXPIRES", 3600),
    })


@auth_bp.post("/refresh")
@token_required(token_type="refresh")
def refresh():
    """使用 refresh_token 换发新的 access_token。

    给新手的解释：
    - access_token 有效期较短（例如 1 小时），过期后不能访问受保护资源。
    - 如果用户还在使用网站，我们可以用较长期的 refresh_token 来换一个新的 access_token。
    - 这个接口需要你在请求头里携带“Bearer <refresh_token>”。
    """
    identity = getattr(g, "identity", None)
    manager = get_jwt_manager()
    access = manager.encode_access_token(identity)
    return jsonify({"access_token": access, "token_type": "Bearer"})


@auth_bp.get("/me")
@token_required()  # 默认需要 access token
def me():
    """返回当前登录用户的身份信息。

    要求请求头里带上“Authorization: Bearer <access_token>”。
    """
    return jsonify({"identity": g.identity, "claims": getattr(g, "claims", None)})