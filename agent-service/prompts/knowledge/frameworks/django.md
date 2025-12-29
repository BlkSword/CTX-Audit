# Django 框架安全知识模块

## 框架概述

Django 是一个高级 Python Web 框架，强调快速开发和简洁设计。它提供了内置的安全功能，但需要正确配置和使用。

## 内置安全特性

### 1. 自动转义
- 模板默认转义 HTML
- 防止 XSS 攻击
- `{{ variable }}` 自动转义

### 2. CSRF 保护
- 默认启用
- `{% csrf_token %}` 标签
- `@csrf_exempt` 危险

### 3. SQL 注入保护
- ORM 自动参数化
- `raw()` 需手动处理

### 4. 点击劫持保护
- `XFrameOptionsMiddleware`
- 默认 `DENY`

## 常见安全模式

### 1. 模板渲染

```python
# ✅ 安全 - 自动转义
def profile(request):
    return render(request, 'profile.html', {
        'username': request.user.username
    })

# ❌ 危险 - 禁用转义
def profile(request):
    return render(request, 'profile.html', {
        'username': request.user.username
    }, autoescape=False)

# ❌ 危险 - 标记安全
def profile(request):
    return render(request, 'profile.html', {
        'html': mark_safe(user_input)  # 危险！
    })

# 模板中
{{ username }}          {# ✅ 自动转义 #}
{{ username|safe }}      {# ❌ 禁用转义 #}
{% autoescape off %}     {# ❌ 全局禁用 #}
    {{ username }}
{% endautoescape %}
```

### 2. 查询集使用

```python
# ✅ 安全 - ORM 自动参数化
def get_user(request, user_id):
    user = User.objects.get(id=user_id)
    return user

# ✅ 使用 raw() 的正确方式
def get_user(request, user_id):
    user = User.objects.raw(
        'SELECT * FROM users WHERE id = %s',
        [user_id]
    )
    return user

# ❌ 危险 - 字符串拼接
def get_user(request, user_id):
    # SQL 注入风险
    query = f'SELECT * FROM users WHERE id = {user_id}'
    user = User.objects.raw(query)
    return user
```

### 3. 表单验证

```python
# ✅ 使用 Form 类
class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email']

    def clean_username(self):
        username = self.cleaned_data['username']
        if len(username) < 3:
            raise forms.ValidationError('用户名至少 3 个字符')
        return username

def register(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            user = form.save()
            return redirect('success')
    else:
        form = UserForm()
    return render(request, 'register.html', {'form': form})

# ❌ 手动验证（容易出错）
def register(request):
    username = request.POST.get('username')
    # 缺少验证，直接使用
    User.objects.create(username=username)
```

### 4. 文件上传

```python
# ❌ 危险 - 无限制
def upload(request):
    file = request.FILES['file']
    # 可以上传任意文件

# ✅ 安全做法
def upload(request):
    file = request.FILES['file']

    # 检查文件大小
    if file.size > 10 * 1024 * 1024:  # 10MB
        return HttpResponse('文件过大', status=400)

    # 检查文件扩展名
    ALLOWED_EXTENSIONS = {'.jpg', '.png', '.pdf'}
    ext = Path(file.name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return HttpResponse('不支持的文件类型', status=400)

    # 检查文件内容（MIME 类型）
    import magic
    mime = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0)
    ALLOWED_MIME = {'image/jpeg', 'image/png', 'application/pdf'}
    if mime not in ALLOWED_MIME:
        return HttpResponse('无效的文件内容', status=400)

    # 安全的文件名
    safe_filename = f"{uuid.uuid4()}{ext}"
    path = Path(settings.MEDIA_ROOT) / 'uploads' / safe_filename

    # 确保路径在允许目录内
    if not path.resolve().is_relative_to(Path(settings.MEDIA_ROOT)):
        return HttpResponse('无效的路径', status=400)

    with open(path, 'wb+') as destination:
        for chunk in file.chunks():
            destination.write(chunk)

    return HttpResponse('上传成功')
```

## 认证授权

### 1. 登录视图

```python
# ✅ 使用内置登录
from django.contrib.auth.views import LoginView

class CustomLoginView(LoginView):
    template_name = 'login.html'
    redirect_authenticated_user = True

# ❌ 不安全的实现
def login(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    # 不要自己实现认证！
    user = User.objects.filter(username=username).first()
    if user and user.password == password:  # 危险！
        login(request, user)
```

### 2. 权限检查

```python
# ✅ 使用装饰器
from django.contrib.auth.decorators import login_required, permission_required

@login_required
def profile(request):
    return render(request, 'profile.html')

@permission_required('app.change_user', raise_exception=True)
def edit_user(request, user_id):
    # ...

# ❌ 缺少权限检查
def edit_user(request, user_id):
    user = User.objects.get(id=user_id)
    # 任何人都可以访问！
```

### 3. 类视图权限

```python
# ✅ 使用 Mixin
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin

class ProfileView(LoginRequiredMixin, TemplateView):
    template_name = 'profile.html'

class UserEditView(PermissionRequiredMixin, UpdateView):
    model = User
    permission_required = 'app.change_user'
    raise_exception = True

# ✅ 或使用 UserPassesTestMixin
from django.contrib.auth.mixins import UserPassesTestMixin

class OwnerOnlyView(UserPassesTestMixin, UpdateView):
    model = User

    def test_func(self):
        return self.get_object() == self.request.user
```

## URL 配置

### 1. 动态 URL

```python
# ✅ 类型转换
from django.urls import path
from . import views

urlpatterns = [
    path('users/<int:user_id>/', views.user_detail),
    path('posts/<slug:post_slug>/', views.post_detail),
]

# ❌ 无验证
def user_detail(request, user_id):
    # user_id 可能是任意值
    user = User.objects.get(id=user_id)
```

### 2. 路径遍历防护

```python
# ❌ 危险
def serve_file(request, filename):
    file_path = Path(settings.MEDIA_ROOT) / filename
    return FileResponse(open(file_path, 'rb'))

# ✅ 安全做法
def serve_file(request, filename):
    # 验证文件名
    if not re.match(r'^[\w\-\.]+$', filename):
        raise Http404('Invalid filename')

    file_path = Path(settings.MEDIA_ROOT) / filename

    # 确保路径在允许目录内
    try:
        file_path.resolve().relative_to(Path(settings.MEDIA_ROOT).resolve())
    except ValueError:
        raise Http404('Access denied')

    if not file_path.exists():
        raise Http404('File not found')

    return FileResponse(open(file_path, 'rb'))
```

## 设置配置

### 安全设置

```python
# settings.py

# ✅ 生产环境必须
DEBUG = False

# ✅ 密钥管理
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError('DJANGO_SECRET_KEY must be set')

# ✅ 允许的主机
ALLOWED_HOSTS = ['example.com', 'www.example.com']

# ✅ HTTPS
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# ✅ HSTS
SECURE_HSTS_SECONDS = 31536000  # 1 年
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# ✅ Cookie 安全
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

# ✅ 其他安全设置
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'

# ✅ CORS（如果需要）
CORS_ALLOWED_ORIGINS = [
    'https://example.com',
    'https://www.example.com',
]
CORS_ALLOW_CREDENTIALS = True
```

### 开发 vs 生产

```python
import os

# 环境检测
ENV = os.getenv('DJANGO_ENV', 'development')

if ENV == 'production':
    DEBUG = False
    # 生产配置
else:
    DEBUG = True
    # 开发配置
```

## 中间件

```python
# settings.py

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

## 常见漏洞

### 1. CSRF 禁用

```python
# ❌ 危险 - 全局禁用
MIDDLEWARE = [
    # ...
    # 'django.middleware.csrf.CsrfViewMiddleware',  # 删除
]

# ❌ 危险 - 视图禁用
@csrf_exempt  # 危险！
def transfer_money(request):
    pass

# ✅ 仅对 API 端点禁用（使用其他认证）
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

@csrf_exempt
@require_http_methods(["POST"])
def api_endpoint(request):
    # 使用 JWT 或 API Key 认证
    pass
```

### 2. 主机头注入

```python
# ❌ 危险配置
ALLOWED_HOSTS = ['*']

# ✅ 正确配置
ALLOWED_HOSTS = ['example.com', 'www.example.com']
```

### 3. 静态文件服务

```python
# ❌ 开发服务器用于生产
# python manage.py runserver

# ✅ 使用专业服务器
# gunicorn, uwsgi, etc.

# 静态文件
STATIC_ROOT = '/var/www/static/'
STATIC_URL = '/static/'
```

## 审计检查点

- [ ] DEBUG = False（生产环境）
- [ ] SECRET_KEY 来自环境变量
- [ ] ALLOWED_HOSTS 正确配置
- [ ] HTTPS/SSL 配置
- [ ] HSTS 启用
- [ ] Cookie 安全设置
- [ ] CSRF 保护启用
- [ ] 模板自动转义
- [ ] ORM 使用（非原始 SQL）
- [ ] 文件上传验证
- [ ] 认证/授权正确
- [ ] 静态文件由专业服务器处理
- [ ] 敏感配置不提交到代码库

## 常见项目结构

```
project/
├── manage.py
├── project/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── apps/
│   ├── users/
│   │   ├── models.py
│   │   ├── views.py
│   │   ├── forms.py
│   │   └── urls.py
│   └── posts/
├── templates/
├── static/
└── media/
```
