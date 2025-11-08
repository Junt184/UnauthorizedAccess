import os
from datetime import timedelta


class Config:
    """应用配置类：集中管理所有可调参数。

    给新手的解释：
    - 这儿就像“项目的设置面板”。你可以通过环境变量覆盖默认值，避免把敏感信息写死在代码里。
    - 例如在服务器上设置 JWT_SECRET_KEY=xxxx，即可使用更安全的密钥。
    """
    # Flask 基础密钥（用于会话、CSRF 等，不用于 JWT）
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")

    # JWT 配置
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", os.getenv("JWT_SECRET", "dev-jwt-secret-change-me"))
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", 3600))  # 1 小时
    JWT_REFRESH_TOKEN_EXPIRES = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", 86400 * 7))  # 7 天
    JWT_LEEWAY = int(os.getenv("JWT_LEEWAY", 5))

    # 每个关卡的独立 JWT 配置（默认回退到全局配置）
    # 关卡1
    LEVEL1_JWT_SECRET_KEY = os.getenv("LEVEL1_JWT_SECRET_KEY", "dev-level1-jwt-secret-change-me")
    LEVEL1_JWT_ALGORITHM = os.getenv("LEVEL1_JWT_ALGORITHM", JWT_ALGORITHM)
    LEVEL1_JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv("LEVEL1_JWT_ACCESS_TOKEN_EXPIRES", JWT_ACCESS_TOKEN_EXPIRES))
    LEVEL1_JWT_REFRESH_TOKEN_EXPIRES = int(os.getenv("LEVEL1_JWT_REFRESH_TOKEN_EXPIRES", JWT_REFRESH_TOKEN_EXPIRES))
    LEVEL1_JWT_LEEWAY = int(os.getenv("LEVEL1_JWT_LEEWAY", JWT_LEEWAY))

    # 关卡2
    LEVEL2_JWT_SECRET_KEY = os.getenv("LEVEL2_JWT_SECRET_KEY", "dev-level2-jwt-secret-change-me")
    LEVEL2_JWT_ALGORITHM = os.getenv("LEVEL2_JWT_ALGORITHM", JWT_ALGORITHM)
    LEVEL2_JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv("LEVEL2_JWT_ACCESS_TOKEN_EXPIRES", JWT_ACCESS_TOKEN_EXPIRES))
    LEVEL2_JWT_REFRESH_TOKEN_EXPIRES = int(os.getenv("LEVEL2_JWT_REFRESH_TOKEN_EXPIRES", JWT_REFRESH_TOKEN_EXPIRES))
    LEVEL2_JWT_LEEWAY = int(os.getenv("LEVEL2_JWT_LEEWAY", JWT_LEEWAY))

    # 其他可选配置
    JSON_AS_ASCII = False
    RESTX_MASK_SWAGGER = False

    # 邮件/验证码发送配置（支持 QQ 邮箱）
    # 注意：QQ 邮箱需要在“设置-账户-开启POP3/SMTP服务”，并使用授权码而非登录密码。
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.qq.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 465))  # QQ SMTP SSL 默认 465；TLS 可用 587
    SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "true").lower() in {"1", "true", "yes"}
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")  # 你的 QQ 邮箱地址，例如 123456@qq.com
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")  # QQ 邮箱授权码（非登录密码）
    EMAIL_FROM = os.getenv("EMAIL_FROM", os.getenv("SMTP_USERNAME", ""))
    EMAIL_SUBJECT_PREFIX = os.getenv("EMAIL_SUBJECT_PREFIX", "[UnauthorizedAccess Lab]")