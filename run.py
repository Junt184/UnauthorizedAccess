import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    # 启动脚本（开发模式）
    # 给新手的解释：
    # - 运行 `python run.py` 就能启动服务。
    # - 默认使用端口 5000；如果该端口被占用，可设置环境变量 PORT=5050 改成 5050。
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)