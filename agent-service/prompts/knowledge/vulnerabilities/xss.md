# XSS 跨站脚本漏洞知识模块

## 漏洞描述

跨站脚本（Cross-Site Scripting，XSS）是一种代码注入攻击，攻击者可以在受害者的浏览器中执行恶意脚本。XSS 分为三种主要类型：存储型、反射型和 DOM 型。

## 危害等级

- **存储型**: High 到 Critical（持久化，影响所有用户）
- **反射型**: Medium（需要社会工程学诱导）
- **DOM 型**: Medium（取决于上下文）

## 三种类型

### 1. 存储型 XSS
- 恶意代码存储在服务器数据库中
- 所有访问该页面的用户都会执行
- 最危险类型
- 常见：评论、用户资料、消息

### 2. 反射型 XSS
- 恶意代码通过 URL 参数反射
- 需要受害者点击恶意链接
- 一次性攻击
- 常见：搜索结果、错误页面

### 3. DOM 型 XSS
- 漏洞在客户端 JavaScript 代码中
- 不经过服务器
- 取决于浏览器环境
- 常见：前端路由、哈希处理

## 常见注入点

### HTML 内容
```html
<div>${userInput}</div>
<div>{userInput}</div>
```

### HTML 属性
```html
<img src="{userInput}">
<a href="{userInput}">link</a>
```

### JavaScript 代码
```javascript
const data = "${userInput}";
element.innerHTML = userInput;
eval(userInput);
setTimeout(userInput, 1000);
```

### CSS 样式
```html
<div style="{userInput}"></div>
<style>{userInput}</style>
```

## 检测 Payload

### 基础测试
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### 上下文测试
```html
<!-- HTML 内容 -->
<script>alert(1)</script>

<!-- HTML 属性 -->
" onmouseover=alert(1) x="
' onmouseover=alert(1) x='

<!-- JavaScript -->
';alert(1);'
";alert(1);"
\';alert(1);//

<!-- URL -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### 绕过过滤
```html
<!-- 大小写 -->
<ScRiPt>aLeRt(1)</ScRiPt>

<!-- 编码 -->
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
%3Cscript%3Ealert(1)%3C/script%3E

<!-- 混淆 -->
<img src=x onerror=a=\x61ler\x74(1)>

<!-- 事件混淆 -->
<img src=x onerror="a='aler';b='t';eval(a+b+'(1)')">
```

## 代码模式识别

### 易受攻击的模板渲染

**Jinja2 (Flask/Django)**:
```python
# ❌ 不安全
render_template('page.html', content=user_input)

# ✅ 安全 - 自动转义
{{ user_input }}

# ❌ 手动标记安全
{{ user_input|safe }}

# ✅ 正确做法 - 根据上下文选择过滤器
{{ user_input|e }}  # HTML 转义
{{ user_input|escape }}
```

**React**:
```jsx
// ❌ 危险 - 不转义
<div dangerouslySetInnerHTML={{__html: userInput}} />

// ✅ 安全 - 自动转义
<div>{userInput}</div>
```

**Vue.js**:
```vue
<!-- ❌ 不安全 -->
<div v-html="userInput"></div>

<!-- ✅ 安全 - 自动转义 -->
<div>{{ userInput }}</div>
```

### 直接 DOM 操作
```javascript
// ❌ 危险
element.innerHTML = userInput;
document.write(userInput);
eval(userInput);

// ✅ 安全
element.textContent = userInput;
element.innerText = userInput;
```

## 框架特定

### Flask / Jinja2
- 默认启用自动转义
- `|safe` 过滤器会禁用转义
- 检查是否过度使用 `|safe`

### Django
- 模板默认转义
- `safe` 过滤器、`autoescape off` 需审查
- `mark_safe()` 函数需谨慎使用

### FastAPI / Jinja2
- 与 Flask 类似
- 检查模板配置

### React
- JSX 默认转义
- `dangerouslySetInnerHTML` 需审查
- 用户输入作为 prop 时自动转义

### Vue.js
- `{{ }}` 默认转义
- `v-html` 指令需审查
- 动态属性绑定时注意

## 验证步骤

### 1. 识别输入点
- 表单输入
- URL 参数
- Cookie
- Headers
- 数据库存储内容

### 2. 识别输出点
- HTML 内容
- HTML 属性
- JavaScript 代码
- CSS 样式
- URL 参数

### 3. 测试反射
- 在每个输入点插入基础 payload
- 观察输出位置是否转义

### 4. 测试存储
- 提交恶意 payload
- 检查是否持久化
- 访问页面验证执行

### 5. 测试 DOM
- 分析 JavaScript 代码
- 寻找 `innerHTML`、`eval` 等
- 测试 URL 哈希/参数

## 修复建议

### 输出编码
```javascript
// HTML 上下文
encodeHTML(userInput)

// JavaScript 上下文
JSON.stringify(userInput)

// URL 上下文
encodeURIComponent(userInput)

// CSS 上下文
encodeCSS(userInput)
```

### 内容安全策略 (CSP)
```http
Content-Security-Policy: default-src 'self'; script-src 'self'
```

### HttpOnly Cookie
```http
Set-Cookie: session=xxx; HttpOnly; Secure
```

### 框架配置
```python
# Flask
app.jinja_env.autoescape = True

# Django
TEMPLATE_CONFIG = {
    'autoescape': True,
}
```

## 测试检查清单

- [ ] 存储型 XSS: 提交 payload，验证持久化
- [ ] 反射型 XSS: URL 参数注入
- [ ] DOM 型 XSS: 分析客户端代码
- [ ] 所有输入点已测试
- [ ] 所有输出点已验证
- [ ] 常见绕过已测试
- [ ] 富文本编辑器已检查

## 报告格式

```markdown
## XSS 漏洞

**类型**: 存储型 XSS
**位置**: `/profile` - 用户名显示
**严重性**: Critical

**Payload**:
```html
<script>alert(document.cookie)</script>
```

**漏洞代码**:
```html
<div>{{ user.name|safe }}</div>
```

**修复建议**:
移除 `|safe` 过滤器，让模板自动转义：
```html
<div>{{ user.name }}</div>
```
```
