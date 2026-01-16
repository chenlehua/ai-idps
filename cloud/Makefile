# Docker Compose 管理命令
# 使用方法：
#   make build              - 构建所有服务
#   make build SERVICE=backend  - 构建指定服务
#   make up                 - 启动所有服务
#   make down               - 停止所有服务
#   make restart            - 重启所有服务
#   make logs               - 查看所有服务日志
#   make logs SERVICE=backend   - 查看指定服务日志
#   make list               - 查看所有服务状态

COMPOSE_FILE := docker-compose.yml
DOCKER_COMPOSE := docker compose -f $(COMPOSE_FILE)

# 可选的服务参数
SERVICE ?=

.PHONY: build rebuild restart up down logs list

# 构建服务
build:
ifdef SERVICE
	$(DOCKER_COMPOSE) build $(SERVICE)
else
	$(DOCKER_COMPOSE) build
endif

# 重新构建服务（无缓存）
rebuild:
ifdef SERVICE
	$(DOCKER_COMPOSE) build --no-cache $(SERVICE)
else
	$(DOCKER_COMPOSE) build --no-cache
endif

# 启动服务
up:
ifdef SERVICE
	$(DOCKER_COMPOSE) up -d $(SERVICE)
else
	$(DOCKER_COMPOSE) up -d
endif

# 停止服务
down:
ifdef SERVICE
	$(DOCKER_COMPOSE) stop $(SERVICE)
	$(DOCKER_COMPOSE) rm -f $(SERVICE)
else
	$(DOCKER_COMPOSE) down
endif

# 重启服务
restart:
ifdef SERVICE
	$(DOCKER_COMPOSE) restart $(SERVICE)
else
	$(DOCKER_COMPOSE) restart
endif

# 查看日志
logs:
ifdef SERVICE
	$(DOCKER_COMPOSE) logs -f $(SERVICE)
else
	$(DOCKER_COMPOSE) logs -f
endif

# 查看所有服务状态
list:
	$(DOCKER_COMPOSE) ps -a
