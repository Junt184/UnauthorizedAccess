from __future__ import annotations

import time
from functools import wraps
from typing import Any, Dict, Optional, Tuple

import jwt
from flask import current_app, request, jsonify, g


class JWTError(Exception):
    """JWT 相关错误的通用异常。

    给新手的解释：
    - 当令牌过期或格式不对时，我们会抛出这个错误，方便上层统一处理。
    """
    pass


class JWTManager:
    """简单易用的 JWT 工具类：负责“生成令牌（签发）”与“验证令牌（解码/校验）”。

    给新手的解释：
    - 你可以把 JWT 理解成一张“加密的身份证”，里面写着“你是谁、什么时候签发、什么时候过期”。
    - 服务端用一个秘密钥匙（secret）来“签名”这张身份证，别人不知道这个钥匙就无法伪造。
    - 用户每次访问受保护资源时，都要出示这张身份证（通常放在请求头或 Cookie）。

    使用方式示例：
        from app.utils.jwt import get_jwt_manager, token_required

        @bp.get('/secure')
        @token_required()  # 默认要求 access token
        def secure_view():
            identity = g.identity  # 由装饰器在验证后放入
            return {...}
    """

    def __init__(self, secret: str, algorithm: str = "HS256",
                 access_expires: int = 3600, refresh_expires: int = 86400 * 7,
                 leeway: int = 5):
        self.secret = secret
        self.algorithm = algorithm
        self.access_expires = access_expires
        self.refresh_expires = refresh_expires
        # 允许少量时间漂移，避免极端情况下出现 iat/nbf/exp 的秒级对齐问题导致无法解码
        self.leeway = leeway

    def _encode(self, payload: Dict[str, Any], expire_in: int, token_type: str) -> str:
        """内部方法：根据给定载荷生成指定类型的 JWT。

        参数解释：
        - payload：要写进令牌里的信息（例如用户身份）。
        - expire_in：令牌多少秒后过期。
        - token_type：令牌类型（access 或 refresh）。
        """
        now = int(time.time())
        data = {
            **payload,
            "iat": now,
            "nbf": now,
            "exp": now + expire_in,
            "type": token_type,
        }
        return jwt.encode(data, self.secret, algorithm=self.algorithm)

    def encode_access_token(self, identity: Dict[str, Any], claims: Optional[Dict[str, Any]] = None) -> str:
        """生成“访问令牌”（短期用），常用于访问受保护接口。"""
        payload = {"sub": identity}
        if claims:
            payload.update({"claims": claims})
        return self._encode(payload, self.access_expires, "access")

    def encode_refresh_token(self, identity: Dict[str, Any], claims: Optional[Dict[str, Any]] = None) -> str:
        """生成“刷新令牌”（长期用），用于在 access 过期后换新令牌。"""
        payload = {"sub": identity}
        if claims:
            payload.update({"claims": claims})
        return self._encode(payload, self.refresh_expires, "refresh")

    def decode_token(self, token: str) -> Dict[str, Any]:
        """验证并解码令牌：检查签名与过期时间，返回令牌里写的内容。

        注意：
        - 加入 leeway（默认 5 秒），允许少量时间漂移，避免在极端情况下出现“刚签发立即解码却提示未到生效时间/已过期”的问题。
        """
        try:
            return jwt.decode(token, self.secret, algorithms=[self.algorithm], leeway=self.leeway)
        except jwt.ExpiredSignatureError as e:
            # 过期：需要用户重新登录或使用 refresh_token 换新
            raise JWTError(f"ExpiredSignatureError: {e}") from e
        except jwt.InvalidSignatureError as e:
            # 签名不匹配：密钥或算法不一致
            raise JWTError(f"InvalidSignatureError: {e}") from e
        except jwt.ImmatureSignatureError as e:
            # nbf 未到：令牌尚未生效
            raise JWTError(f"ImmatureSignatureError: {e}") from e
        except jwt.InvalidIssuedAtError as e:
            # iat 非法：签发时间异常
            raise JWTError(f"InvalidIssuedAtError: {e}") from e
        except jwt.InvalidAudienceError as e:
            # aud 校验失败（当前我们不设置aud，一般不会触发）
            raise JWTError(f"InvalidAudienceError: {e}") from e
        except jwt.DecodeError as e:
            # 解析失败：令牌结构或编码有问题
            raise JWTError(f"DecodeError: {e}") from e
        except jwt.InvalidTokenError as e:
            # 兜底：其他 PyJWT 抛出的无效令牌错误
            raise JWTError(f"InvalidTokenError: {e}") from e


def get_jwt_manager() -> JWTManager:
    """从 Flask 配置中读取参数，创建一个 JWT 管理器实例。

    给新手的解释：
    - 配置里存着“密钥、算法、过期时间”等参数，我们把它们取出来用于签发和验证令牌。
    """
    cfg = current_app.config
    return JWTManager(
        secret=cfg.get("JWT_SECRET_KEY"),
        algorithm=cfg.get("JWT_ALGORITHM", "HS256"),
        access_expires=cfg.get("JWT_ACCESS_TOKEN_EXPIRES", 3600),
        refresh_expires=cfg.get("JWT_REFRESH_TOKEN_EXPIRES", 86400 * 7),
        leeway=int(cfg.get("JWT_LEEWAY", 5)),
    )


# 关卡专用的 JWT 管理器已移动到各关卡的 utils 中：
# - app/routes/level1/utils/jwt.py
# - app/routes/level2/utils/jwt.py


def parse_authorization_header() -> Tuple[Optional[str], Optional[str]]:
    """解析请求头里的 Authorization 字段，返回 (认证方案, 令牌)。

    给新手的解释：
    - 访问受保护接口时，常见做法是把令牌放在请求头里：
      Authorization: Bearer <你的令牌>
    - 解析后我们能得到 scheme="Bearer" 和 token="<你的令牌>"。
    """
    auth = request.headers.get("Authorization", "")
    if not auth:
        return None, None
    try:
        scheme, token = auth.split(" ", 1)
        return scheme, token
    except ValueError:
        return None, None


def token_required(token_type: str = "access"):
    """路由装饰器：要求请求里必须带上指定类型的 JWT。

    给新手的解释：
    - 在函数上加 @token_required()，表示这个接口需要“访问令牌”。
    - 如果改成 @token_required("refresh")，表示需要“刷新令牌”。
    - 验证成功后，我们会把身份信息放到 g.identity 里，供你的业务函数使用。
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # 1) 从请求头里解析出 "Bearer <token>"
            scheme, token = parse_authorization_header()
            if scheme != "Bearer" or not token:
                return jsonify({"error": "Authorization header missing or invalid"}), 401

            manager = get_jwt_manager()
            try:
                # 2) 验证并解码令牌
                data = manager.decode_token(token)
            except JWTError as e:
                return jsonify({"error": str(e)}), 401

            # 3) 验证令牌类型是否匹配（access 或 refresh）
            if data.get("type") != token_type:
                return jsonify({"error": "Token type mismatch"}), 401

            # 4) 把身份信息注入到全局上下文，后续业务函数可使用 g.identity
            g.identity = data.get("sub")
            g.claims = data.get("claims")
            return fn(*args, **kwargs)

        return wrapper

    return decorator