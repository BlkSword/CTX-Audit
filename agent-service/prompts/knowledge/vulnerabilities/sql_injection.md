# SQL 注入漏洞知识模块

## 漏洞描述

SQL 注入（SQL Injection）是一种常见的代码注入技术，用于攻击数据驱动的应用程序。攻击者可以通过在应用程序的输入字段中插入恶意 SQL 代码，从而操纵后端数据库执行非预期的 SQL 查询。

## 危害等级

- **严重性**: High 到 Critical
- **影响**: 数据泄露、数据篡改、权限绕过、拒绝服务

## 常见注入点

### 1. 用户输入
- 登录表单（用户名/密码）
- 搜索框
- 注册表单
- 个人资料编辑

### 2. HTTP 参数
- GET 参数
- POST 数据
- Cookie 值
- HTTP Headers

### 3. 数据库操作
- SELECT 查询
- INSERT 语句
- UPDATE 语句
- DELETE 语句

## 检测方法

### 1. 基础测试
```sql
' OR '1'='1
" OR "1"="1
' OR 1=1--
admin'--
' UNION SELECT NULL--
```

### 2. 时间盲注
```sql
' AND SLEEP(5)--
' WAITFOR DELAY '00:00:05'--
```

### 3. 布尔盲注
```sql
' AND 1=1--
' AND 1=2--
```

### 4. 错误注入
```sql
' AND 1=CONVERT(int, (SELECT @@version))--
```

## 代码模式识别

### Python (易受攻击的模式)
```python
# ❌ 直接拼接 SQL
query = f"SELECT * FROM users WHERE username='{username}'"
cursor.execute(query)

# ❌ 字符串格式化
query = "SELECT * FROM users WHERE id=%s" % user_id
cursor.execute(query)

# ✅ 正确做法 - 使用参数化查询
query = "SELECT * FROM users WHERE username=%s"
cursor.execute(query, (username,))
```

### JavaScript (易受攻击的模式)
```javascript
// ❌ 直接拼接
const query = `SELECT * FROM users WHERE id = ${userId}`;

// ❌ 模板字符串
const query = `SELECT * FROM users WHERE name = '${userName}'`;

// ✅ 正确做法 - 使用参数化
const query = 'SELECT * FROM users WHERE id = $1';
await client.query(query, [userId]);
```

### Java (易受攻击的模式)
```java
// ❌ 字符串拼接
String query = "SELECT * FROM users WHERE id = " + userId;

// ✅ 正确做法 - PreparedStatement
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setInt(1, userId);
```

## 框架特定注意事项

### Django
- Django ORM 默认提供 SQL 注入保护
- 但 `raw()` 查询需要手动参数化
- `extra()` 方法已弃用，应避免使用

### Flask SQLAlchemy
- 使用参数化查询
- 避免使用 `text()` 时直接拼接

### FastAPI
- SQLAlchemy ORM 有保护
- 但原始 SQL 查询需要参数化

### Spring Boot
- JPA/Hibernate 有保护
- 但原生 SQL 查询需要参数化

## 验证步骤

1. **识别数据库操作点**
   - 搜索数据库查询语句
   - 检查 ORM 使用情况

2. **检查参数化**
   - 查看是否使用占位符
   - 检查变量是否直接拼接

3. **手动测试**
   - 注入单引号查看错误
   - 使用基础 payload 测试

4. **确认可利用性**
   - 构造完整注入语句
   - 验证数据泄露可能性

## 修复建议

### 短期修复
1. 使用参数化查询
2. 输入验证和过滤
3. 最小权限数据库账户

### 长期修复
1. 使用 ORM 框架
2. 实施输入验证框架
3. WAF 部署
4. 代码审计流程

## 测试 Payload

### 基础 Payload
```
admin'--
' OR '1'='1
" OR "1"="1
' UNION SELECT NULL--
```

### 高级 Payload
```
' UNION SELECT username, password FROM users--
' OR (SELECT COUNT(*) FROM users) > 0--
'; DROP TABLE users;--
```

## 报告格式

```markdown
## SQL 注入漏洞

**位置**: `app/routes/auth.py:45`
**严重性**: Critical
**payload**: `' OR '1'='1`

**漏洞代码**:
```python
query = f"SELECT * FROM users WHERE username='{username}'"
```

**修复建议**:
使用参数化查询:
```python
query = "SELECT * FROM users WHERE username=%s"
cursor.execute(query, (username,))
```
```
