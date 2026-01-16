# AI-IDPS 项目管理命令
#
# ============ 云端服务 (Docker Compose) ============
#   make build              - 构建所有云端服务
#   make build SERVICE=backend  - 构建指定服务
#   make up                 - 启动所有云端服务
#   make down               - 停止所有云端服务
#   make restart            - 重启所有云端服务
#   make logs               - 查看所有服务日志
#   make logs SERVICE=backend   - 查看指定服务日志
#   make list               - 查看所有服务状态
#
# ============ Probe Manager (C++) ============
#   make probe-build        - 构建 Probe Manager
#   make probe-rebuild      - 完全重新构建
#   make probe-run          - 运行 Probe Manager
#   make probe-stop         - 停止 Probe Manager
#   make probe-clean        - 清理构建产物
#
# ============ 测试 ============
#   make test-api           - 运行云端 API 测试
#   make test-probe         - 运行探针黑盒测试 
#   make test-all           - 运行所有测试

# ============ 配置 ============
COMPOSE_FILE := cloud/docker-compose.yml
DOCKER_COMPOSE := docker compose -f $(COMPOSE_FILE)

# Probe Manager 配置
PROBE_BUILD_DIR := probe/build
PROBE_BIN := $(PROBE_BUILD_DIR)/manager/probe-manager
PROBE_CONFIG ?= /etc/probe-manager/config.json
PROBE_PORT ?= 9001
CLOUD_URL ?= http://localhost

# 可选的服务参数
SERVICE ?=

.PHONY: build rebuild restart up down logs list \
        probe-build probe-rebuild probe-run probe-stop probe-clean probe-install \
        test-api test-probe test-stress test-all help

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

# ============================================================
# Probe Manager 命令
# ============================================================

# 构建 Probe Manager
probe-build:
	@echo "Building Probe Manager..."
	@mkdir -p $(PROBE_BUILD_DIR)
	@cd $(PROBE_BUILD_DIR) && cmake .. && make -j$$(nproc)
	@echo "Build complete: $(PROBE_BIN)"

# 完全重新构建 (清理后构建)
probe-rebuild: probe-clean probe-build

# 运行 Probe Manager
probe-run:
	@if [ ! -f $(PROBE_BIN) ]; then \
		echo "Probe Manager not built. Run 'make probe-build' first."; \
		exit 1; \
	fi
	@echo "Starting Probe Manager on port $(PROBE_PORT)..."
	@LISTEN_PORT=$(PROBE_PORT) CLOUD_URL=$(CLOUD_URL) $(PROBE_BIN)

# 后台运行 Probe Manager
probe-start:
	@if [ ! -f $(PROBE_BIN) ]; then \
		echo "Probe Manager not built. Run 'make probe-build' first."; \
		exit 1; \
	fi
	@echo "Starting Probe Manager in background..."
	@LISTEN_PORT=$(PROBE_PORT) CLOUD_URL=$(CLOUD_URL) nohup $(PROBE_BIN) > /tmp/probe-manager.log 2>&1 & \
		echo $$! > /tmp/probe-manager.pid
	@sleep 1
	@if kill -0 $$(cat /tmp/probe-manager.pid) 2>/dev/null; then \
		echo "Probe Manager started (PID: $$(cat /tmp/probe-manager.pid))"; \
		echo "Port: $(PROBE_PORT)"; \
		echo "Log file: /tmp/probe-manager.log"; \
	else \
		echo "Failed to start Probe Manager. Check logs:"; \
		cat /tmp/probe-manager.log; \
		exit 1; \
	fi

# 停止 Probe Manager
probe-stop:
	@if [ -f /tmp/probe-manager.pid ]; then \
		PID=$$(cat /tmp/probe-manager.pid); \
		if kill -0 $$PID 2>/dev/null; then \
			echo "Stopping Probe Manager (PID: $$PID)..."; \
			kill $$PID; \
			rm -f /tmp/probe-manager.pid; \
			echo "Stopped."; \
		else \
			echo "Probe Manager not running."; \
			rm -f /tmp/probe-manager.pid; \
		fi \
	else \
		echo "Probe Manager PID file not found."; \
		echo "Trying to find and kill probe-manager process..."; \
		pkill -f probe-manager || echo "No probe-manager process found."; \
	fi

# 查看 Probe Manager 状态
probe-status:
	@if [ -f /tmp/probe-manager.pid ]; then \
		PID=$$(cat /tmp/probe-manager.pid); \
		if kill -0 $$PID 2>/dev/null; then \
			echo "Probe Manager is running (PID: $$PID)"; \
			echo "Port: $(PROBE_PORT)"; \
		else \
			echo "Probe Manager is not running (stale PID file)"; \
		fi \
	else \
		echo "Probe Manager is not running"; \
	fi

# 查看 Probe Manager 日志
probe-logs:
	@if [ -f /tmp/probe-manager.log ]; then \
		tail -f /tmp/probe-manager.log; \
	else \
		echo "Log file not found: /tmp/probe-manager.log"; \
	fi

# 清理构建产物
probe-clean:
	@echo "Cleaning Probe Manager build..."
	@rm -rf $(PROBE_BUILD_DIR)
	@echo "Clean complete."

# 安装 Probe Manager 到系统
probe-install: probe-build
	@echo "Installing Probe Manager..."
	@sudo cp $(PROBE_BIN) /usr/local/bin/
	@sudo mkdir -p /etc/probe-manager
	@echo "Installed to /usr/local/bin/probe-manager"

# ============================================================
# 测试命令
# ============================================================

# 运行云端 API 测试
test-api:
	@echo "Running Cloud API tests..."
	@chmod +x fixtures/test_api.sh
	@./fixtures/test_api.sh $(CLOUD_URL)

# 运行探针黑盒测试 (快速模式)
test-probe:
	@echo "Running Probe blackbox tests..."
	@cd fixtures/probe_blackbox_tests && python3 run_tests.py --quick \
		--manager-host 127.0.0.1 --manager-port $(PROBE_PORT) \
		--cloud-url $(CLOUD_URL)

# 运行探针压力测试
test-stress:
	@echo "Running Probe stress tests..."
	@cd fixtures/probe_blackbox_tests && python3 run_tests.py --stress \
		--manager-host 127.0.0.1 --manager-port $(PROBE_PORT) \
		--cloud-url $(CLOUD_URL)

# 运行所有探针测试 (包括压力测试)
test-probe-full:
	@echo "Running all Probe blackbox tests..."
	@cd fixtures/probe_blackbox_tests && python3 run_tests.py \
		--manager-host 127.0.0.1 --manager-port $(PROBE_PORT) \
		--cloud-url $(CLOUD_URL)

# 运行所有测试
test-all: test-api test-probe

# ============================================================
# 帮助
# ============================================================

help:
	@echo "AI-IDPS 项目管理命令"
	@echo ""
	@echo "云端服务 (Docker Compose):"
	@echo "  make build              构建所有云端服务"
	@echo "  make up                 启动所有云端服务"
	@echo "  make down               停止所有云端服务"
	@echo "  make restart            重启所有云端服务"
	@echo "  make logs               查看服务日志"
	@echo "  make list               查看服务状态"
	@echo ""
	@echo "Probe Manager (C++):"
	@echo "  make probe-build        构建 Probe Manager"
	@echo "  make probe-rebuild      完全重新构建"
	@echo "  make probe-run          前台运行 (调试用)"
	@echo "  make probe-start        后台启动服务"
	@echo "  make probe-stop         停止服务"
	@echo "  make probe-status       查看运行状态"
	@echo "  make probe-logs         查看运行日志"
	@echo "  make probe-clean        清理构建产物"
	@echo "  make probe-install      安装到系统"
	@echo ""
	@echo "测试:"
	@echo "  make test-api           运行云端 API 测试"
	@echo "  make test-probe         运行探针黑盒测试 (快速)"
	@echo "  make test-probe-full    运行探针完整测试"
	@echo "  make test-stress        运行压力测试"
	@echo "  make test-all           运行所有测试"
	@echo ""
	@echo "配置变量:"
	@echo "  PROBE_PORT=$(PROBE_PORT)        Probe Manager 端口"
	@echo "  CLOUD_URL=$(CLOUD_URL)   云端 API 地址"
	@echo ""
	@echo "示例:"
	@echo "  make up                         启动云端服务"
	@echo "  make probe-build && make probe-start  构建并启动 Probe Manager"
	@echo "  make test-all                   运行所有测试"
	@echo "  PROBE_PORT=9001 make probe-run  指定端口运行"
