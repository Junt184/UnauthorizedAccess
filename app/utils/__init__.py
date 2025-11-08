"""实用工具包。

导出常用函数，方便在其他模块中直接引用：
    from app.utils import send_verification_code, generate_verification_code
"""

from .email import (
    send_verification_code,
    generate_verification_code,
    send_email_raw,
)

# 可以在此处继续导出其他工具函数，例如 JWT 相关等
try:
    from .jwt import get_jwt_manager, token_required
except Exception:  # 避免循环导入或缺少依赖导致初始化报错
    pass