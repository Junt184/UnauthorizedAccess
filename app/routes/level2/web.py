from urllib.parse import urlparse

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    make_response,
    g,
)

from .utils.jwt import get_jwt_manager, JWTError
from flags import LEVEL2_AFTER_FLAG


# Blueprint 定义：所有路由都挂载在 /level2 前缀下
level2_bp = Blueprint("level2", __name__, url_prefix="/level2")


def _get_identity_from_cookie() -> dict | None:
    """从 Cookie 中读取并校验关卡2的 access_token，返回用户身份。

    与关卡1类似，但使用 l2_* 的 Cookie 名称，并设置 path=/level2 实现隔离。
    """
    token = request.cookies.get("l2_access_token")
    if not token:
        return None
    manager = get_jwt_manager()
    try:
        data = manager.decode_token(token)
    except JWTError:
        return None
    if data.get("type") != "access":
        return None
    return data.get("sub")


def _safe_next_url(next_url: str | None) -> str | None:
    """仅允许相对路径的跳转，避免开放重定向。"""
    if not next_url:
        return None
    try:
        parsed = urlparse(next_url)
    except Exception:
        return None
    if parsed.scheme or parsed.netloc:
        return None
    return next_url


@level2_bp.get("/")
def index():
    """关卡2首页：显示登录状态并提供入口。"""
    g.identity = _get_identity_from_cookie()
    return render_template("level2/index.html", identity=g.identity)


@level2_bp.get("/login")
def login_page():
    """显示关卡2的登录页（支持 next 参数）。"""
    next_url = _safe_next_url(request.args.get("next"))
    return render_template("level2/login.html", next_url=next_url)


@level2_bp.post("/login")
def login_post():
    """处理登录，签发 JWT 并写入 Cookie（仅作用于 /level2 路径）。"""
    data = request.form or {}
    username = data.get("username")
    password = data.get("password")
    next_url = _safe_next_url(data.get("next"))

    if not username or not password:
        return render_template("level2/login.html", error="请输入用户名与密码", next_url=next_url), 400

    identity = {"user_id": 201, "username": username, "role": "user"}
    manager = get_jwt_manager()
    access = manager.encode_access_token(identity)
    refresh = manager.encode_refresh_token(identity)

    # 登录成功后，统一跳转到“登录后页面”
    resp = make_response(redirect(url_for("level2.after_login_page")))
    resp.set_cookie(
        "l2_access_token",
        access,
        max_age=int(manager.access_expires),
        httponly=True,
        samesite="Lax",
        secure=False,
        path="/level2",
    )
    resp.set_cookie(
        "l2_refresh_token",
        refresh,
        max_age=int(manager.refresh_expires),
        httponly=True,
        samesite="Lax",
        secure=False,
        path="/level2",
    )
    return resp


@level2_bp.get("/logout")
def logout():
    """退出登录：删除关卡2的 Cookie 令牌。"""
    resp = make_response(redirect(url_for("level2.index")))
    resp.delete_cookie("l2_access_token", path="/level2")
    resp.delete_cookie("l2_refresh_token", path="/level2")
    return resp


@level2_bp.get("/secure")
def secure_page():
    """受保护页面：仅当 l2_access_token 有效时可访问。"""
    identity = _get_identity_from_cookie()
    if not identity:
        return redirect(url_for("level2.login_page", next=request.path))
    g.identity = identity
    return render_template("level2/secure.html", identity=g.identity)


@level2_bp.get("/after")
def after_login_page():
    """登录后访问的页面：显示当前身份；如果是 admin，显示关卡2的 AFTER_FLAG。

    访问要求：需已登录；否则跳转到登录页并带回调参数 next。
    """
    identity = _get_identity_from_cookie()
    if not identity:
        return redirect(url_for("level2.login_page", next=request.path))
    g.identity = identity
    flag = LEVEL2_AFTER_FLAG if identity.get("username") == "admin" else None
    return render_template("level2/after.html", identity=g.identity, flag=flag)