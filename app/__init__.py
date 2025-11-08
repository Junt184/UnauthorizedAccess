import os
from flask import Flask, jsonify
from .config import Config


def create_app() -> Flask:
    """应用工厂：创建并配置一个 Flask 实例。

    给新手的解释：
    - 这是项目的入口函数，负责把“配置、路由（接口/页面）、错误处理”等都组装到一个应用对象里。
    - 以后如果你要扩展功能（新增页面或接口），只需在这里注册相应的蓝图即可。
    """
    app = Flask(__name__)
    app.config.from_object(Config())

    # 注册蓝图（把不同模块的路由整合到应用里）
    from .routes.auth import auth_bp
    from .routes.secure import secure_bp
    from .routes.web import web_bp
    # 新增：关卡1与关卡2的 SSR 蓝图（各自独立的 Cookie 鉴权）
    from .routes.level1 import level1_bp
    from .routes.level2 import level2_bp
    app.register_blueprint(auth_bp, url_prefix="/api")
    app.register_blueprint(secure_bp, url_prefix="/api")
    app.register_blueprint(web_bp)
    app.register_blueprint(level1_bp)
    app.register_blueprint(level2_bp)

    # 通用错误处理（当接口返回 401/403/404 等时，给出统一格式的 JSON）
    @app.errorhandler(401)
    def unauthorized(_):
        return jsonify({"error": "Unauthorized"}), 401

    @app.errorhandler(403)
    def forbidden(_):
        return jsonify({"error": "Forbidden"}), 403

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"error": "Not Found"}), 404

    @app.get("/api/health")
    def health():
        """健康检查接口：用于确认服务是否正常运行。"""
        return {"status": "ok"}

    return app