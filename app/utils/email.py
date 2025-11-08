"""邮件发送工具：支持通过 QQ 邮箱发送验证码。

使用说明：
- 在 QQ 邮箱开启 POP3/SMTP 服务，并获取“授权码”（不是登录密码）。
- 通过环境变量配置：
  - SMTP_HOST=smtp.qq.com
  - SMTP_PORT=465  # 使用 SSL；若使用 TLS，则设 587 并将 SMTP_USE_SSL=false
  - SMTP_USE_SSL=true
  - SMTP_USERNAME=你的QQ邮箱地址，例如 123456@qq.com
  - SMTP_PASSWORD=授权码
  - EMAIL_FROM=发件人地址（通常与 SMTP_USERNAME 相同）
  - EMAIL_SUBJECT_PREFIX=[UnauthorizedAccess Lab]（可选）

示例：
    from app.utils.email import generate_verification_code, send_verification_code

    code = generate_verification_code()
    ok, msg = send_verification_code("target@example.com", code)
    if ok:
        print("发送成功")
    else:
        print("发送失败:", msg)
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Tuple

from flask import current_app

import secrets
import string


def generate_verification_code(length: int = 6, digits_only: bool = True) -> str:
    """生成验证码（默认 6 位，仅数字）。"""
    if digits_only:
        alphabet = string.digits
    else:
        alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _build_message(subject: str, body_text: str, from_addr: str, to_addr: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(body_text)
    return msg


def send_email_raw(to_email: str, subject: str, body_text: str) -> Tuple[bool, str]:
    """发送纯文本邮件。

    返回：
    - (True, "ok") 发送成功
    - (False, err_msg) 发送失败
    """
    cfg = current_app.config
    host = cfg.get("SMTP_HOST")
    port = int(cfg.get("SMTP_PORT"))
    use_ssl = bool(cfg.get("SMTP_USE_SSL"))
    username = cfg.get("SMTP_USERNAME")
    password = cfg.get("SMTP_PASSWORD")
    from_addr = cfg.get("EMAIL_FROM") or username
    subject_prefix = cfg.get("EMAIL_SUBJECT_PREFIX", "")

    if not (host and port and username and password and from_addr):
        return False, "SMTP 配置不完整：请设置 SMTP_HOST/SMTP_PORT/SMTP_USERNAME/SMTP_PASSWORD/EMAIL_FROM"

    full_subject = f"{subject_prefix} {subject}".strip()
    msg = _build_message(full_subject, body_text, from_addr, to_email)

    try:
        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context) as server:
                server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port) as server:
                server.ehlo()
                server.starttls()
                server.login(username, password)
                server.send_message(msg)
        current_app.logger.info(f"[Email] 发送成功: to={to_email}, subject={full_subject}")
        return True, "ok"
    except smtplib.SMTPException as e:
        current_app.logger.warning(f"[Email] 发送失败: to={to_email}, error={e}")
        return False, f"SMTPException: {e}"
    except Exception as e:
        current_app.logger.warning(f"[Email] 未知错误: to={to_email}, error={e}")
        return False, str(e)


def send_verification_code(to_email: str, code: str | None = None, expire_minutes: int = 10) -> Tuple[bool, str]:
    """发送验证码邮件（纯文本）。

    参数：
    - to_email: 收件人
    - code: 验证码（若未提供则自动生成 6 位数字）
    - expire_minutes: 有效期提示（仅在邮件文案展示，不做服务端存储）

    返回：同 send_email_raw

    注意：本函数只负责发送邮件，不负责验证码的存储与校验。你可以在路由层或数据库中
    存储 code 及其过期时间，用于后续校验。
    """
    code = code or generate_verification_code()
    subject = "验证码"
    body_text = (
        f"你的验证码是：{code}\n"
        f"该验证码在 {expire_minutes} 分钟内有效。\n"
        f"如果非你本人操作，请忽略本邮件。"
    )
    return send_email_raw(to_email, subject, body_text)