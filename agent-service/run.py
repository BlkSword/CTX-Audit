#!/usr/bin/env python3
"""
CTX-Audit Agent Service 快速启动脚本

用法：
    python run.py       # Windows/Linux/Mac
    或直接双击 run.bat  # Windows
"""

import sys
import os
from pathlib import Path

# 添加项目根目录到 Python 路径（必须在最前面）
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

# 设置环境变量
os.environ.setdefault("PYTHONPATH", str(project_root))

def main():
    import uvicorn

    print("=" * 50)
    print("  CTX-Audit Agent Service 启动")
    print("=" * 50)
    print()

    # 检查Python版本
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print(f"Python版本: {python_version}")
    print(f"项目目录: {project_root}")
    print()
    print("正在启动服务...")
    print(f"访问地址: http://localhost:8001")
    print(f"API文档: http://localhost:8001/docs")
    print()
    print("-" * 50)
    print()

    try:
        # 导入配置获取端口
        from app.config import settings

        # 启动服务 - 使用字符串路径以支持 reload
        uvicorn.run(
            "app.main:app",  # 使用字符串路径
            host="0.0.0.0",
            port=settings.AGENT_PORT,
            reload=True,
            log_level=settings.LOG_LEVEL,
        )
    except KeyboardInterrupt:
        print("\n\n✅ 服务已停止")
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
