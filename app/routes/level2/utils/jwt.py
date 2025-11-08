from __future__ import annotations

from flask import current_app

# 复用全局的 JWTManager 与异常类型，但关卡2的配置独立读取
from ....utils.jwt import JWTManager, JWTError


def get_jwt_manager() -> JWTManager:
    """关卡2专用的 JWT 管理器工厂：读取 LEVEL2_* 配置。

    如果未设置 LEVEL2_*，则回退到全局 JWT_*。
    """
    cfg = current_app.config
    return JWTManager(
        secret=cfg.get("LEVEL2_JWT_SECRET_KEY", cfg.get("JWT_SECRET_KEY")),
        algorithm=cfg.get("LEVEL2_JWT_ALGORITHM", cfg.get("JWT_ALGORITHM", "HS256")),
        access_expires=cfg.get("LEVEL2_JWT_ACCESS_TOKEN_EXPIRES", cfg.get("JWT_ACCESS_TOKEN_EXPIRES", 3600)),
        refresh_expires=cfg.get("LEVEL2_JWT_REFRESH_TOKEN_EXPIRES", cfg.get("JWT_REFRESH_TOKEN_EXPIRES", 86400 * 7)),
        leeway=int(cfg.get("LEVEL2_JWT_LEEWAY", cfg.get("JWT_LEEWAY", 5))),
    )