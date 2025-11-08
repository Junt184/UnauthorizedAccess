from urllib.parse import urlparse

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    make_response,
    g,
    current_app,
    jsonify,
)

from .utils.jwt import get_jwt_manager, JWTError
from flags import LEVEL1_AFTER_FLAG
import jwt as pyjwt  # 仅用于调试端点的无签名解析


# Blueprint 定义：所有路由都挂载在 /level1 前缀下
level1_bp = Blueprint("level1", __name__, url_prefix="/level1")


# =====================
# 演示用的“用户数据库”
# =====================
# 使用 Python 字典存储用户名 => 密码（内存级，服务重启会丢失）。
# 漏洞点：不校验重复注册，第二次注册会直接覆盖已有用户的密码。
ACCOUNTS: dict[str, str] = {
    # 预置一个管理员账号，密码初始为不可知。选手可通过“覆盖注册”重置密码后登录拿 flag。
    "admin": "SuperSecret!123",
}

# 关卡 flag（仅 admin 登录后展示）
# flag 常量改为从根目录 flags.py 导入


def _get_identity_from_cookie() -> dict | None:
    """从 Cookie 中读取并校验关卡1的 access_token，返回用户身份。

    关卡1与根站点的区别：
    - Cookie 名称使用 l1_access_token / l1_refresh_token，避免与其他关卡或根站点冲突。
    - Cookie path 设置为 /level1，仅对该路径下的页面生效，实现“路径隔离”。
    """
    token = request.cookies.get("l1_access_token")
    if not token:
        return None
    manager = get_jwt_manager()
    # 与 /debug-token 保持一致的解码逻辑：不验证签名与时效，仅解析结构
    try:
        data = pyjwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
            },
            algorithms=[manager.algorithm],
        )
    except Exception as e:
        # 与调试端点一致的错误行为：记录未验证解析失败的原因
        try:
            current_app.logger.warning(f"[Level1] Unverified JWT decode failed: {e}")
        except Exception:
            pass
        return None
    if data.get("type") != "access":
        return None
    sub = data.get("sub")
    return sub if isinstance(sub, dict) else None


def _safe_next_url(next_url: str | None) -> str | None:
    """仅允许相对路径的跳转，防止开放重定向。"""
    if not next_url:
        return None
    try:
        parsed = urlparse(next_url)
    except Exception:
        return None
    if parsed.scheme or parsed.netloc:
        return None
    return next_url


@level1_bp.get("/")
def index():
    """关卡1首页：显示登录状态并提供入口。

    逻辑：
    - 从 l1_access_token Cookie 解析用户身份。
    - 将身份传入模板以便显示“已登录/未登录”。
    """
    g.identity = _get_identity_from_cookie()
    # 登录后默认跳转到的页面（也可通过 ?next= 自定义）
    next_url = _safe_next_url(request.args.get("next")) or url_for("level1.after_login_page")
    # 首页不再展示 flag，flag 仅在 /level1/after 页面显示
    return render_template("level1/index.html", identity=g.identity, next_url=next_url)


# ============
# 注册页面/接口
# ============
@level1_bp.get("/register")
def register_page():
    """显示注册页面。

    漏洞说明：不校验用户是否已存在，重复注册会覆盖旧密码。
    这意味着可以“重置”管理员 admin 的密码，然后再登录拿到 flag。
    """
    next_url = _safe_next_url(request.args.get("next"))
    return render_template("level1/register.html", next_url=next_url)


@level1_bp.post("/register")
def register_post():
    """处理注册表单（存在覆盖注册漏洞）。

    漏洞点：
    - 不检查用户名是否已存在，直接写入字典 ACCOUNTS[username] = password。
    - 如果 username=admin，则会把管理员密码覆盖成你填写的新密码。
    """
    data = request.form or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    next_url = _safe_next_url(data.get("next"))

    if not username or not password:
        return render_template(
            "level1/register.html",
            error="请填写用户名与密码",
            next_url=next_url,
        ), 400

    # 覆盖注册（漏洞）：不做任何检查，直接写入/覆盖
    ACCOUNTS[username] = password

    # 注册后返回首页，提示成功（登录表单在首页）
    return render_template(
        "level1/index.html",
        message=f"注册成功：{username}",
        identity=None,
        next_url=next_url,
    )


@level1_bp.get("/login")
def login_page():
    """按要求：登录页面与首页合并，访问 /login 时重定向到首页。"""
    return redirect(url_for("level1.index"))


@level1_bp.post("/login")
def login_post():
    """处理登录，签发 JWT 并写入 Cookie（仅作用于 /level1 路径）。

    新逻辑：使用内存字典 ACCOUNTS 校验用户名与密码（需先注册）。
    演示目的：结合“覆盖注册漏洞”，允许二次注册覆盖 admin 密码以获取 flag。
    """
    data = request.form or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    next_url = _safe_next_url(data.get("next"))

    if not username or not password:
        return render_template("level1/index.html", error="请输入用户名与密码", identity=None, next_url=next_url), 400

    # 使用内存“数据库”校验账号
    real_pwd = ACCOUNTS.get(username)
    if not real_pwd or real_pwd != password:
        return render_template("level1/index.html", error="用户名不存在或密码错误，请先注册或重试", identity=None, next_url=next_url), 400

    # 角色：如果是 admin，则标记 role=admin
    role = "admin" if username == "admin" else "user"
    identity = {"user_id": 101, "username": username, "role": role}
    manager = get_jwt_manager()
    access = manager.encode_access_token(identity)
    refresh = manager.encode_refresh_token(identity)

    # 登录成功后，统一跳转到“登录后页面”
    resp = make_response(redirect(url_for("level1.after_login_page")))
    resp.set_cookie(
        "l1_access_token",
        access,
        max_age=int(manager.access_expires),
        httponly=True,
        samesite="Lax",
        secure=False,  # 开发环境；生产建议 True + HTTPS
        path="/level1",
    )
    resp.set_cookie(
        "l1_refresh_token",
        refresh,
        max_age=int(manager.refresh_expires),
        httponly=True,
        samesite="Lax",
        secure=False,
        path="/level1",
    )
    return resp


@level1_bp.get("/logout")
def logout():
    """退出登录：删除关卡1的 Cookie 令牌。"""
    resp = make_response(redirect(url_for("level1.index")))
    resp.delete_cookie("l1_access_token", path="/level1")
    resp.delete_cookie("l1_refresh_token", path="/level1")
    return resp


@level1_bp.get("/secure")
def secure_page():
    """兼容旧链接：受保护页面已合并到首页，这里重定向到首页。"""
    return redirect(url_for("level1.index"))


@level1_bp.get("/after")
def after_login_page():
    """登录后访问的页面：显示当前身份；如果是 admin，返回 flag{过关了}。

    访问要求：
    - 需已登录（存在并且有效的 l1_access_token）。
    - 否则返回首页并提示需要登录。
    """
    g.identity = _get_identity_from_cookie()
    print(g.identity)
    if not g.identity:
        # 未登录，直接在首页提示错误；并设置 next 指向当前页面，方便登录后自动返回这里。
        return render_template(
            "level1/index.html",
            error="请先登录后再访问此页面",
            identity=None,
            next_url=url_for("level1.after_login_page"),
        ), 401

    flag = LEVEL1_AFTER_FLAG if g.identity.get("username") == "admin" else None
    return render_template("level1/after.html", identity=g.identity, flag=flag)

@level1_bp.get("/debug-token")
def debug_token():
    """调试端点：查看 cookie 中的原始令牌与未验证解析内容。

    注意：此端点仅用于开发调试，不进行签名与时效校验。生产环境不应开启或应加访问限制。
    """
    token = request.cookies.get("l1_access_token")
    if not token:
        return jsonify({"ok": False, "error": "No l1_access_token cookie"}), 200

    info = {"ok": True, "raw_cookie": token}
    # 未验证的头部
    try:
        info["unverified_header"] = pyjwt.get_unverified_header(token)
    except Exception as e:
        info["unverified_header_error"] = str(e)

    # 不验证签名与时效，尝试解析 payload（仅用于观察结构）
    try:
        info["unverified_payload"] = pyjwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
            },
            algorithms=[get_jwt_manager().algorithm],
        )
    except Exception as e:
        info["unverified_payload_error"] = str(e)

    return jsonify(info), 200