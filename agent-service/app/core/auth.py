"""
用户认证和授权模块

提供 JWT 认证、用户管理、权限控制等功能
"""
import time
import jwt
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
from passlib.context import CryptContext
from loguru import logger

# JWT 配置
SECRET_KEY = "your-secret-key-change-in-production"  # 生产环境需要更改
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7


class UserRole(str, Enum):
    """用户角色"""
    ADMIN = "admin"      # 管理员
    USER = "user"        # 普通用户
    VIEWER = "viewer"    # 只读用户


class Permission(str, Enum):
    """权限定义"""
    # 审计相关
    AUDIT_CREATE = "audit:create"
    AUDIT_READ = "audit:read"
    AUDIT_UPDATE = "audit:update"
    AUDIT_DELETE = "audit:delete"
    AUDIT_EXPORT = "audit:export"

    # 项目相关
    PROJECT_READ = "project:read"
    PROJECT_WRITE = "project:write"
    PROJECT_DELETE = "project:delete"

    # 系统相关
    SYSTEM_ADMIN = "system:admin"
    SYSTEM_CONFIG = "system:config"


# 角色权限映射
ROLE_PERMISSIONS: Dict[UserRole, List[Permission]] = {
    UserRole.ADMIN: [
        Permission.AUDIT_CREATE,
        Permission.AUDIT_READ,
        Permission.AUDIT_UPDATE,
        Permission.AUDIT_DELETE,
        Permission.AUDIT_EXPORT,
        Permission.PROJECT_READ,
        Permission.PROJECT_WRITE,
        Permission.PROJECT_DELETE,
        Permission.SYSTEM_ADMIN,
        Permission.SYSTEM_CONFIG,
    ],
    UserRole.USER: [
        Permission.AUDIT_CREATE,
        Permission.AUDIT_READ,
        Permission.AUDIT_UPDATE,
        Permission.AUDIT_EXPORT,
        Permission.PROJECT_READ,
        Permission.PROJECT_WRITE,
    ],
    UserRole.VIEWER: [
        Permission.AUDIT_READ,
        Permission.PROJECT_READ,
    ],
}


@dataclass
class User:
    """用户模型"""
    id: str
    username: str
    email: str
    role: UserRole
    created_at: float
    is_active: bool = True

    def has_permission(self, permission: Permission) -> bool:
        """检查用户是否有指定权限"""
        permissions = ROLE_PERMISSIONS.get(self.role, [])
        return permission in permissions

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role.value,
            "created_at": self.created_at,
            "is_active": self.is_active,
        }


@dataclass
class TokenData:
    """Token 数据"""
    user_id: str
    username: str
    role: UserRole
    exp: float
    iat: float
    type: str  # access | refresh


class PasswordManager:
    """密码管理器"""

    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def hash_password(self, password: str) -> str:
        """哈希密码"""
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """验证密码"""
        return self.pwd_context.verify(plain_password, hashed_password)


class TokenManager:
    """Token 管理器"""

    def __init__(
        self,
        secret_key: str = SECRET_KEY,
        algorithm: str = ALGORITHM,
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm

    def create_access_token(self, data: Dict[str, Any]) -> str:
        """创建访问令牌"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access",
        })
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """创建刷新令牌"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh",
        })
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def decode_token(self, token: str) -> TokenData:
        """解码令牌"""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
            )
            return TokenData(
                user_id=payload["user_id"],
                username=payload["username"],
                role=UserRole(payload["role"]),
                exp=payload["exp"],
                iat=payload["iat"],
                type=payload.get("type", "access"),
            )
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")


class UserStore:
    """用户存储（内存实现，生产环境应使用数据库）"""

    def __init__(self):
        self._users: Dict[str, User] = {}
        self._username_to_id: Dict[str, str] = {}

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        role: UserRole = UserRole.USER,
    ) -> User:
        """创建用户"""
        if username in self._username_to_id:
            raise ValueError(f"Username {username} already exists")

        user_id = f"user_{int(time.time())}"
        user = User(
            id=user_id,
            username=username,
            email=email,
            role=role,
            created_at=time.time(),
        )

        self._users[user_id] = user
        self._username_to_id[username] = user_id

        logger.info(f"User created: {username} ({user_id})")
        return user

    def get_user(self, user_id: str) -> Optional[User]:
        """根据 ID 获取用户"""
        return self._users.get(user_id)

    def get_user_by_username(self, username: str) -> Optional[User]:
        """根据用户名获取用户"""
        user_id = self._username_to_id.get(username)
        return self._users.get(user_id) if user_id else None

    def authenticate_user(
        self,
        username: str,
        password: str,
        password_manager: PasswordManager,
        hashed_passwords: Dict[str, str],
    ) -> Optional[User]:
        """验证用户"""
        user = self.get_user_by_username(username)
        if not user:
            return None

        stored_hash = hashed_passwords.get(username)
        if not stored_hash:
            return None

        if not password_manager.verify_password(password, stored_hash):
            return None

        return user


class AuthService:
    """认证服务"""

    def __init__(self):
        self.user_store = UserStore()
        self.password_manager = PasswordManager()
        self.token_manager = TokenManager()
        self._hashed_passwords: Dict[str, str] = {}

    def register(
        self,
        username: str,
        email: str,
        password: str,
        role: UserRole = UserRole.USER,
    ) -> User:
        """注册用户"""
        user = self.user_store.create_user(username, email, password, role)
        self._hashed_passwords[username] = self.password_manager.hash_password(password)
        return user

    def login(
        self,
        username: str,
        password: str,
    ) -> Optional[Dict[str, str]]:
        """用户登录"""
        user = self.user_store.authenticate_user(
            username,
            password,
            self.password_manager,
            self._hashed_passwords,
        )

        if not user:
            return None

        # 创建 token
        token_data = {
            "user_id": user.id,
            "username": user.username,
            "role": user.role.value,
        }

        access_token = self.token_manager.create_access_token(token_data)
        refresh_token = self.token_manager.create_refresh_token(token_data)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }

    def verify_token(self, token: str) -> Optional[TokenData]:
        """验证 token"""
        try:
            return self.token_manager.decode_token(token)
        except ValueError as e:
            logger.warning(f"Token verification failed: {e}")
            return None

    def get_current_user(self, token: str) -> Optional[User]:
        """获取当前用户"""
        token_data = self.verify_token(token)
        if not token_data:
            return None

        return self.user_store.get_user(token_data.user_id)

    def check_permission(
        self,
        user: User,
        permission: Permission,
    ) -> bool:
        """检查权限"""
        return user.has_permission(permission)


# 全局认证服务实例
_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    """获取全局认证服务实例"""
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()

        # 创建默认管理员用户
        try:
            _auth_service.register(
                username="admin",
                email="admin@ctx-audit.com",
                password="admin123",  # 生产环境需要修改
                role=UserRole.ADMIN,
            )
            logger.info("Default admin user created")
        except Exception as e:
            logger.debug(f"Admin user might already exist: {e}")

    return _auth_service


# 便捷函数
async def get_current_user(token: str) -> Optional[User]:
    """获取当前用户（便捷函数）"""
    auth_service = get_auth_service()
    return auth_service.get_current_user(token)


def require_permission(permission: Permission):
    """
    权限检查装饰器

    用法:
        @require_permission(Permission.AUDIT_CREATE)
        async def create_audit():
            pass
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # 这里需要从请求中获取 token 和用户
            # 实际实现需要与 FastAPI 依赖注入集成
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# FastAPI 依赖项
async def get_current_user_dependency(token: str) -> Optional[User]:
    """FastAPI 依赖项：获取当前用户"""
    return await get_current_user(token)


async def require_permission_dependency(
    permission: Permission,
    current_user: User = None,
) -> bool:
    """FastAPI 依赖项：检查权限"""
    if not current_user:
        return False

    auth_service = get_auth_service()
    return auth_service.check_permission(current_user, permission)
