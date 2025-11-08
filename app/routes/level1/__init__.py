"""关卡1（Level 1）路由包。

说明：
- 该包包含一个 Blueprint（level1_bp），提供 SSR 页面：首页、登录、退出、受保护页面。
- 鉴权机制：使用 JWT 存入浏览器 Cookie（cookie 名称以 l1_ 为前缀，仅作用于 /level1 路径）。
"""

from .web import level1_bp