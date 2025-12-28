# 多阶段构建
# 构建阶段：前端
FROM node:20-alpine AS frontend-builder

WORKDIR /app

# 复制前端源码
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# 构建阶段：后端
FROM rust:1.75-alpine AS backend-builder

# 安装依赖
RUN apk add --no-cache musl-dev sqlite-dev

WORKDIR /app

# 复制 Cargo 配置
COPY core /app/core
COPY web-backend /app/web-backend

# 构建 core 库（先构建它，因为 web-backend 依赖它）
WORKDIR /app/core
RUN cargo build --release

# 构建 web-backend
WORKDIR /app/web-backend
RUN cargo build --release

# 运行阶段：最终镜像
FROM alpine:latest

# 安装运行时依赖
RUN apk add --no-cache sqlite ca-certificates

WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=backend-builder /app/web-backend/target/release/deepaudit-web /app/deepaudit-web

# 从前端构建阶段复制静态文件
COPY --from=frontend-builder /app/dist /app/dist

# 暴露端口
EXPOSE 8000

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8000/health || exit 1

# 运行应用
CMD ["/app/deepaudit-web"]
