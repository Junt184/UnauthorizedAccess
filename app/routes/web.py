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

from ..utils.jwt import get_jwt_manager, JWTError


web_bp = Blueprint("web", __name__)


def _get_identity_from_cookie() -> dict | None:
    """从浏览器 Cookie 中取出并校验 access_token，返回用户身份。

    给新手的解释：
    - 浏览器登录成功后，后端会把一个字符串（JWT 令牌）放到 Cookie 里，名字叫 access_token。
    - 每次你访问页面，浏览器都会把这个 Cookie 带上来。
    - 我们在这里把这个字符串拿出来，验证它是否有效（有没有被篡改、是否过期）。
    - 如果有效，我们就能知道你是谁（例如用户名、用户ID），然后把这些信息用于渲染页面。
    - 如果无效（过期/被改坏），就返回 None，表示“未登录”。
    """
    # 1) 从 Cookie 读取名为 access_token 的值（可能不存在）
    token = request.cookies.get("access_token")
    if not token:
        return None
    manager = get_jwt_manager()
    try:
        # 2) 验证并解码 token（检查签名与过期时间）
        data = manager.decode_token(token)
    except JWTError:
        return None
    # 3) 我们只接受“访问令牌”（access），而不是刷新令牌（refresh）
    if data.get("type") != "access":
        return None
    # 4) 返回令牌里的用户身份（例如 {"user_id": 1, "username": "alice"}）
    return data.get("sub")


def _safe_next_url(next_url: str | None) -> str | None:
    """仅允许“站内”跳转，避免开放重定向到外部网站。

    给新手的解释：
    - 有时登录页会带一个 next 参数，告诉登录成功后要跳到哪里。
    - 如果我们不检查这个参数，攻击者可能把它改成一个恶意网站的地址，造成“开放重定向”漏洞。
    - 这里做简单校验：只允许相对路径（例如 /secure），不允许带 http:// 或域名。
    """
    if not next_url:
        return None
    try:
        parsed = urlparse(next_url)
    except Exception:
        return None
    # 仅允许相对路径或同源路径
    if parsed.scheme or parsed.netloc:
        return None
    return next_url


@web_bp.get("/")
def index():
    """网站首页：显示当前是否已登录。

    逻辑：尝试从 Cookie 里读身份；如果存在，就把身份传给模板渲染。
    """
    g.identity = _get_identity_from_cookie()
    return render_template("index.html", identity=g.identity)


@web_bp.get("/login")
def login_page():
    """显示登录页面。

    如果有 next 参数（登录成功后要跳转的地址），先做安全校验。
    """
    next_url = _safe_next_url(request.args.get("next"))
    return render_template("login.html", next_url=next_url)


@web_bp.post("/login")
def login_post():
    """处理登录表单：签发 JWT，并把令牌放到 Cookie。

    给新手的解释：
    - 用户提交“用户名 + 密码”。这里为了演示，只要两者都有，就认为登录成功（实际项目要查数据库和验证密码）。
    - 成功后，我们生成两个令牌：access_token（访问受保护页面用）和 refresh_token（刷新 access 用）。
    - 然后把它们放进 Cookie（HttpOnly，防止被前端脚本读取），最后重定向到目标页面。
    """
    data = request.form or {}
    username = data.get("username")
    password = data.get("password")
    next_url = _safe_next_url(data.get("next"))

    if not username or not password:
        return render_template("login.html", error="请输入用户名与密码", next_url=next_url), 400

    identity = {"user_id": 1, "username": username, "role": "user"}
    manager = get_jwt_manager()
    access = manager.encode_access_token(identity)
    refresh = manager.encode_refresh_token(identity)

    resp = make_response(redirect(next_url or url_for("web.secure_page")))
    # 开发环境下 secure=False；生产建议 secure=True + https
    resp.set_cookie(
        "access_token",
        access,
        max_age=int(manager.access_expires),
        httponly=True,
        samesite="Lax",
        secure=False,
        path="/",
    )
    resp.set_cookie(
        "refresh_token",
        refresh,
        max_age=int(manager.refresh_expires),
        httponly=True,
        samesite="Lax",
        secure=False,
        path="/",
    )
    return resp


@web_bp.get("/logout")
def logout():
    """退出登录：删除 Cookie 中的令牌，然后返回首页。"""
    resp = make_response(redirect(url_for("web.index")))
    resp.delete_cookie("access_token", path="/")
    resp.delete_cookie("refresh_token", path="/")
    return resp


@web_bp.get("/secure")
def secure_page():
    """受保护页面：只有在 Cookie 中存在有效 access_token 时才能访问。

    如果没有登录（或令牌失效），就跳转到登录页。
    """
    identity = _get_identity_from_cookie()
    if not identity:
        # 未登录，跳转到登录页
        return redirect(url_for("web.login_page", next=request.path))
    g.identity = identity
    return render_template("secure.html", identity=g.identity)