# FastAPI 框架安全知识模块

## 框架概述

FastAPI 是一个现代、快速的 Python Web 框架，基于 Python 3.6+ 类型提示，使用 Starlette 和 Pydantic 构建。

## 安全特性

### 内置安全功能
- Pydantic 数据验证
- 自动 JSON 序列化
- OpenAPI 文档生成
- CORS 支持

### 需要注意的点
- 默认启用 CORS（开发模式）
- 自动文档可能泄露敏感信息
- 路径参数注入风险

## 常见安全模式

### 1. 路径操作装饰器

```python
# ✅ 标准用法
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    return {"user_id": user_id}

# ❌ 路径遍历风险
@app.get("/files/{filename}")
async def get_file(filename: str):
    # 危险：用户可以访问任意文件
    return File(filename)

# ✅ 安全做法
@app.get("/files/{filename}")
async def get_file(filename: str):
    # 验证文件名
    if not re.match(r'^[\w\-\.]+$', filename):
        raise HTTPException(400, "Invalid filename")

    file_path = Path(SAFE_DIR) / filename
    if not file_path.resolve().is_relative_to(SAFE_DIR):
        raise HTTPException(400, "Access denied")

    return File(file_path)
```

### 2. 请求体验证

```python
# ✅ 使用 Pydantic 模型
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

@app.post("/users")
async def create_user(user: UserCreate):
    # 自动验证
    return create_user(user)

# ❌ 手动验证（容易出错）
@app.post("/users")
async def create_user(request: Request):
    data = await request.json()
    # 缺少验证
```

### 3. 查询参数验证

```python
# ✅ 使用 Query 参数
@app.get("/search")
async def search(
    q: Optional[str] = Query(None, min_length=1, max_length=50),
    limit: int = Query(10, ge=1, le=100),
):
    return {"results": []}

# ❌ 未验证
@app.get("/search")
async def search(q: str = None, limit: int = 10):
    # 无限制，可能导致 DoS
```

### 4. 文件上传

```python
# ❌ 危险 - 无限制
@app.post("/upload")
async def upload(file: UploadFile):
    # 可以上传任意大小的文件
    contents = await file.read()
    return {"size": len(contents)}

# ✅ 安全做法
@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    # 检查文件大小
    MAX_SIZE = 10 * 1024 * 1024  # 10MB
    contents = await file.read(MAX_SIZE + 1)
    if len(contents) > MAX_SIZE:
        raise HTTPException(400, "File too large")

    # 检查文件类型
    ALLOWED_EXTENSIONS = {'.jpg', '.png', '.pdf'}
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, "Invalid file type")

    # 检查文件内容
    file.file.seek(0)
    magic_bytes = file.file.read(8)
    if not is_valid_file_type(magic_bytes, file_ext):
        raise HTTPException(400, "Invalid file content")

    return {"filename": file.filename}
```

## 数据库操作

### SQLAlchemy

```python
# ❌ SQL 注入风险
@app.get("/users/{user_id}")
async def get_user(user_id: str):
    # 直接拼接
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = db.execute(query)

# ✅ 安全 - 参数化查询
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    # ORM 会自动参数化
    result = db.query(User).filter(User.id == user_id).first()
    return result

# ✅ 使用原始 SQL 时的正确做法
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    from sqlalchemy import text
    query = text("SELECT * FROM users WHERE id = :user_id")
    result = db.execute(query, {"user_id": user_id})
```

### Tortoise ORM

```python
# ✅ ORM 自动保护
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    user = await User.get(id=user_id)
    return user
```

## 认证授权

### JWT 认证

```python
# ❌ 硬编码密钥
SECRET_KEY = "my-secret-key"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/protected")
async def protected(token: str = Depends(oauth2_scheme)):
    # ...

# ✅ 安全做法
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY not set")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/protected")
async def protected(
    current_user: User = Depends(get_current_user)
):
    return current_user
```

### 权限检查

```python
# ❌ 缺少权限检查
@app.delete("/users/{user_id}")
async def delete_user(user_id: int):
    await delete_user(user_id)

# ✅ 正确做法
@app.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
):
    # 只能删除自己
    if current_user.id != user_id:
        raise HTTPException(403, "Not allowed")

    # 或者需要管理员权限
    if not current_user.is_admin:
        raise HTTPException(403, "Admin required")

    await delete_user(user_id)
```

## CORS 配置

```python
# ❌ 开发配置 - 允许所有来源
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

# ✅ 生产配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        'https://example.com',
        'https://www.example.com',
    ],
    allow_credentials=True,
    allow_methods=['GET', 'POST'],
    allow_headers=['Content-Type'],
)
```

## 常见漏洞模式

### 1. 自动文档泄露

```python
# ❌ 生产环境启用文档
app = FastAPI(docs=True, redoc=True)

# ✅ 生产环境禁用
is_prod = os.getenv("ENV") == "production"
app = FastAPI(
    docs=not is_prod,
    redoc=not is_prod,
    openapi_url=None if is_prod else "/openapi.json",
)
```

### 2. 依赖注入绕过

```python
# ❌ 不安全的依赖
def get_current_user(token: str = Header(...)):
    # 未验证 token
    return User(id=1, username="admin")

# ✅ 正确实现
async def get_current_user(
    token: str = Depends(oauth2_scheme)
) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(401, "Invalid token")
    except JWTError:
        raise HTTPException(401, "Invalid token")

    user = await get_user(user_id)
    if user is None:
        raise HTTPException(401, "User not found")
    return user
```

### 3. 异步处理风险

```python
# ❌ 不安全的异步操作
@app.post("/process")
async def process(data: dict):
    # 未验证就执行异步任务
    asyncio.create_task(dangerous_operation(data))

# ✅ 先验证再执行
@app.post("/process")
async def process(data: ProcessData):
    # Pydantic 已验证
    asyncio.create_task(dangerous_operation(data))
```

## 安全配置建议

### 1. 环境变量

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "CTX-Audit API"
    debug: bool = False
    secret_key: str
    database_url: str
    cors_origins: List[str] = []

    class Config:
        env_file = ".env"

settings = Settings()
```

### 2. 中间件

```python
# 安全相关中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["example.com", "*.example.com"],
)

app.add_middleware(
    GZipMiddleware,
    minimum_size=1000,
)

# 安全头
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response
```

### 3. 速率限制

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request):
    pass
```

## 审计检查点

- [ ] 路径参数验证（防止路径遍历）
- [ ] 查询参数限制（防止 DoS）
- [ ] Pydantic 模型验证
- [ ] 文件上传限制（大小、类型）
- [ ] SQL 使用参数化查询
- [ ] 认证实现正确
- [ ] 权限检查完善
- [ ] CORS 配置正确
- [ ] 敏感信息不在文档中
- [ ] 环境变量使用
- [ ] 安全响应头
- [ ] 速率限制

## 常见文件结构

```
app/
├── main.py              # 应用入口
├── dependencies.py      # 依赖注入
├── config.py            # 配置
├── models/              # Pydantic 模型
│   └── user.py
├── routers/             # 路由
│   ├── auth.py
│   └── users.py
├── services/            # 业务逻辑
│   └── auth.py
└── security/            # 安全相关
    ├── jwt.py
    └── password.py
```
