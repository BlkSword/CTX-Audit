"""
FastAPI 认证中间件

提供基于 JWT 的身份验证和授权中间件
"""
from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from loguru import logger

from app.core.auth import get_auth_service, Permission, UserRole


security = HTTPBearer(auto_error=False)


async def get_current_user_optional(
    request: Request,
) -> Optional[dict]:
    """
    获取当前用户（可选认证）

    如果请求中包含有效的 token，返回用户信息
    否则返回 None（不抛出错误）
    """
    try:
        # 从 header 获取 token
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header[7:]  # 移除 "Bearer " 前缀
        auth_service = get_auth_service()
        user = auth_service.get_current_user(token)

        if user:
            return user.to_dict()
        return None

    except Exception as e:
        logger.warning(f"Token 验证失败: {e}")
        return None


async def require_auth(
    request: Request,
) -> dict:
    """
    要求认证（必须登录）

    如果未认证，抛出 401 错误
    """
    user = await get_current_user_optional(request)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未认证，请提供有效的 token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def require_permission(
    request: Request,
    permission: Permission,
) -> dict:
    """
    要求特定权限

    Args:
        request: FastAPI 请求对象
        permission: 需要的权限

    Returns:
        用户信息

    Raises:
        HTTPException: 如果未认证或没有权限
    """
    # 先检查认证
    user = await require_auth(request)

    # 检查权限
    auth_service = get_auth_service()
    user_obj = auth_service.user_store.get_user(user["id"])

    if not user_obj or not user_obj.has_permission(permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"权限不足，需要权限: {permission.value}",
        )

    return user


async def require_role(
    request: Request,
    role: UserRole,
) -> dict:
    """
    要求特定角色

    Args:
        request: FastAPI 请求对象
        role: 需要的角色

    Returns:
        用户信息

    Raises:
        HTTPException: 如果未认证或角色不匹配
    """
    user = await require_auth(request)

    if user.get("role") != role.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"权限不足，需要角色: {role.value}",
        )

    return user


# FastAPI 依赖项（可以在路由中使用）
async def auth_required(request: Request) -> dict:
    """FastAPI 依赖项：要求认证"""
    return await require_auth(request)


async def audit_create_required(request: Request) -> dict:
    """FastAPI 依赖项：要求创建审计权限"""
    return await require_permission(request, Permission.AUDIT_CREATE)


async def audit_delete_required(request: Request) -> dict:
    """FastAPI 依赖项：要求删除审计权限"""
    return await require_permission(request, Permission.AUDIT_DELETE)


async def admin_required(request: Request) -> dict:
    """FastAPI 依赖项：要求管理员角色"""
    return await require_role(request, UserRole.ADMIN)
