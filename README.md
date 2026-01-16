# AI-IDPS (网络入侵检测系统)

本仓库为网络入侵检测系统的开发骨架，包含云端服务与探针端的基础框架。

## 目录结构

- `cloud/` 云端服务（FastAPI + React）
- `probe/` 探针端（Probe Manager 与公共库）
- `rules/` 规则集目录
- `third_party/` 第三方依赖（预留 Suricata 子模块）
- `specs/` 需求与实现计划

## 快速开始（开发环境）

1. 进入云端目录启动服务：
   - `docker compose -f cloud/docker-compose.yml up --build`
2. 访问健康检查：
   - `http://localhost/health`

## 说明

当前完成第一阶段基础框架搭建，后续阶段会逐步补齐探针通信、规则管理、日志上报等功能。
