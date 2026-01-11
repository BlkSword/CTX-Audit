"""
认证 API 端点

处理用户注册、登录、token 刷新等
"""
from fastapi import APIRouter, HTTPException, status, Request
from pydantic import BaseModel
from typing import Optional
from loguru import logger

from app.core.auth import get_auth_service, UserRole


router = APIRouter()


# ========== 请求/响应模型 ==========


class RegisterRequest(BaseModel):
    """注册请求"""
    username: str
    email: str
    password: str
    role: Optional[str] = "user"


class LoginRequest(BaseModel):
    """登录请求"""
    username: str
    password: str


class TokenResponse(BaseModel):
    """Token 响应"""
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int


class UserResponse(BaseModel):
    """用户信息响应"""
    id: str
    username: str
    email: str
    role: str
    created_at: float
    is_active: bool


# ========== API 端点 ==========


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(request: RegisterRequest):
    """
    注册新用户

    Args:
        request: 注册请求

    Returns:
        用户信息
    """
    try:
        auth_service = get_auth_service()

        # 解析角色
        try:
            user_role = UserRole(request.role.lower())
        except ValueError:
            user_role = UserRole.USER

        # 注册用户
        user = auth_service.register(
            username=request.username,
            email=request.email,
            password=request.password,
            role=user_role,
        )

        return UserResponse(**user.to_dict())

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"注册失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="注册失败",
        )


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """
    用户登录

    Args:
        request: 登录请求

    Returns:
        Token 信息
    """
    try:
        auth_service = get_auth_service()
        result = auth_service.login(
            username=request.username,
            password=request.password,
        )

        if not result:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="用户名或密码错误",
            )

        return TokenResponse(**result)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"登录失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="登录失败",
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user(request: Request):
    """
    获取当前用户信息

    需要有效的 Bearer token
    """
    from app.core.auth_middleware import get_current_user_optional

    user = await get_current_user_optional(request)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未认证",
        )

    return UserResponse(**user)


@router.post("/verify")
async def verify_token(request: Request):
    """
    验证 token 是否有效

    Args:
        request: FastAPI 请求对象

    Returns:
        验证结果
    """
    from app.core.auth_middleware import get_current_user_optional

    user = await get_current_user_optional(request)

    if user:
        return {"valid": True, "user": user}
    else:
        return {"valid": False}
