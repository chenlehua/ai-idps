# AI-IDPS 项目管理命令
#
# ============ 统一服务管理命令 ============
#   make build [SERVICE=xxx]    - 构建服务 (cloud服务/probe-manager/nids-probe)
#   make rebuild [SERVICE=xxx]  - 完全重新构建服务
#   make up [SERVICE=xxx]       - 启动服务
#   make down [SERVICE=xxx]     - 停止服务
#   make restart [SERVICE=xxx]  - 重启服务
#   make logs [SERVICE=xxx]     - 查看服务日志
#   make list                   - 查看所有服务状态
#
# ============ SERVICE 可选值 ============
#   不指定SERVICE   - 操作所有云端服务
#   backend         - 云端后端服务
#   frontend        - 云端前端服务
#   nginx           - Nginx代理
#   redis/mysql/clickhouse - 数据库服务
#   probe-manager   - Probe Manager (C++本地服务)
#   nids-probe      - NIDS Probe (C++本地服务)
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
PROBE_PORT ?= 9010
CLOUD_URL ?= http://localhost
PROBE_PID_FILE := /tmp/probe-manager.pid
PROBE_LOG_FILE := /tmp/probe-manager.log
PROBE_SERVICE_FILE := /etc/systemd/system/probe-manager.service
PROBE_SERVICE_TEMPLATE := scripts/probe-manager.service

# NIDS Probe 配置
NIDS_BIN := $(PROBE_BUILD_DIR)/nids/nids-probe
NIDS_INTERFACE ?= eth0
NIDS_PID_FILE := /tmp/nids-probe.pid
NIDS_LOG_FILE := /tmp/nids-probe.log
SURICATA_CONFIG ?= /etc/suricata/suricata.yaml

# 可选的服务参数
SERVICE ?=

.PHONY: build rebuild restart up down logs list status \
        probe-clean probe-install probe-uninstall \
        nids-run nids-install nids-uninstall \
        test-api test-probe test-stress test-all help \
        install-service uninstall-service

# ============================================================
# 统一构建命令
# ============================================================

# 构建服务
build:
ifeq ($(SERVICE),probe-manager)
	@echo "Building Probe Manager..."
	@mkdir -p $(PROBE_BUILD_DIR)
	@cd $(PROBE_BUILD_DIR) && CXX=g++ cmake .. && make -j$$(nproc) probe-manager
	@echo "Build complete: $(PROBE_BIN)"
else ifeq ($(SERVICE),nids-probe)
	@echo "Building NIDS Probe..."
	@mkdir -p $(PROBE_BUILD_DIR)
	@cd $(PROBE_BUILD_DIR) && CXX=g++ cmake .. && make -j$$(nproc) nids-probe
	@echo "Build complete: $(NIDS_BIN)"
else ifeq ($(SERVICE),probes)
	@echo "Building all probes (Manager + NIDS)..."
	@mkdir -p $(PROBE_BUILD_DIR)
	@cd $(PROBE_BUILD_DIR) && CXX=g++ cmake .. && make -j$$(nproc)
	@echo "Build complete: $(PROBE_BIN) $(NIDS_BIN)"
else ifdef SERVICE
	$(DOCKER_COMPOSE) build $(SERVICE)
else
	$(DOCKER_COMPOSE) build
endif

# 重新构建服务（无缓存/完全重建）
rebuild:
ifeq ($(SERVICE),probe-manager)
	@echo "Cleaning Probe Manager build..."
	@rm -rf $(PROBE_BUILD_DIR)
	@echo "Building Probe Manager..."
	@mkdir -p $(PROBE_BUILD_DIR)
	@cd $(PROBE_BUILD_DIR) && CXX=g++ cmake .. && make -j$$(nproc) probe-manager
	@echo "Rebuild complete: $(PROBE_BIN)"
else ifeq ($(SERVICE),nids-probe)
	@echo "Cleaning NIDS Probe build..."
	@rm -rf $(PROBE_BUILD_DIR)
	@echo "Building NIDS Probe..."
	@mkdir -p $(PROBE_BUILD_DIR)
	@cd $(PROBE_BUILD_DIR) && CXX=g++ cmake .. && make -j$$(nproc) nids-probe
	@echo "Rebuild complete: $(NIDS_BIN)"
else ifeq ($(SERVICE),probes)
	@echo "Cleaning all probes build..."
	@rm -rf $(PROBE_BUILD_DIR)
	@echo "Building all probes..."
	@mkdir -p $(PROBE_BUILD_DIR)
	@cd $(PROBE_BUILD_DIR) && CXX=g++ cmake .. && make -j$$(nproc)
	@echo "Rebuild complete"
else ifdef SERVICE
	$(DOCKER_COMPOSE) build --no-cache $(SERVICE)
else
	$(DOCKER_COMPOSE) build --no-cache
endif

# ============================================================
# 统一启动/停止命令
# ============================================================

# 启动服务
up:
ifeq ($(SERVICE),probe-manager)
	@if [ ! -f $(PROBE_BIN) ]; then \
		echo "Probe Manager not built. Run 'make build SERVICE=probe-manager' first."; \
		exit 1; \
	fi
	@# 检查是否以systemd服务运行
	@if systemctl is-active --quiet probe-manager 2>/dev/null; then \
		echo "Probe Manager is running as systemd service"; \
		exit 0; \
	fi
	@# 检查是否已经在运行
	@if [ -f $(PROBE_PID_FILE) ] && kill -0 $$(cat $(PROBE_PID_FILE)) 2>/dev/null; then \
		echo "Probe Manager is already running (PID: $$(cat $(PROBE_PID_FILE)))"; \
		exit 0; \
	fi
	@echo "Starting Probe Manager in background..."
	@LISTEN_PORT=$(PROBE_PORT) CLOUD_URL=$(CLOUD_URL) nohup $(PROBE_BIN) > $(PROBE_LOG_FILE) 2>&1 & \
		echo $$! > $(PROBE_PID_FILE)
	@sleep 1
	@if kill -0 $$(cat $(PROBE_PID_FILE)) 2>/dev/null; then \
		echo "Probe Manager started (PID: $$(cat $(PROBE_PID_FILE)))"; \
		echo "Port: $(PROBE_PORT)"; \
		echo "Log file: $(PROBE_LOG_FILE)"; \
	else \
		echo "Failed to start Probe Manager. Check logs:"; \
		cat $(PROBE_LOG_FILE); \
		rm -f $(PROBE_PID_FILE); \
		exit 1; \
	fi
else ifdef SERVICE
	$(DOCKER_COMPOSE) up -d $(SERVICE)
else
	$(DOCKER_COMPOSE) up -d
endif

# 停止服务
down:
ifeq ($(SERVICE),probe-manager)
	@# 首先尝试停止systemd服务
	@if systemctl is-active --quiet probe-manager 2>/dev/null; then \
		echo "Stopping Probe Manager systemd service..."; \
		sudo systemctl stop probe-manager; \
		echo "Stopped."; \
	elif [ -f $(PROBE_PID_FILE) ]; then \
		PID=$$(cat $(PROBE_PID_FILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			echo "Stopping Probe Manager (PID: $$PID)..."; \
			kill $$PID; \
			rm -f $(PROBE_PID_FILE); \
			echo "Stopped."; \
		else \
			echo "Probe Manager not running (stale PID file)."; \
			rm -f $(PROBE_PID_FILE); \
		fi \
	else \
		echo "Probe Manager PID file not found."; \
		echo "Trying to find and kill probe-manager process..."; \
		pkill -f probe-manager || echo "No probe-manager process found."; \
	fi
else ifdef SERVICE
	$(DOCKER_COMPOSE) stop $(SERVICE)
	$(DOCKER_COMPOSE) rm -f $(SERVICE)
else
	$(DOCKER_COMPOSE) down
endif

# 重启服务
restart:
ifeq ($(SERVICE),probe-manager)
	@$(MAKE) down SERVICE=probe-manager
	@sleep 1
	@$(MAKE) up SERVICE=probe-manager
else ifdef SERVICE
	$(DOCKER_COMPOSE) restart $(SERVICE)
else
	$(DOCKER_COMPOSE) restart
endif

# ============================================================
# 日志和状态查看
# ============================================================

# 查看日志
logs:
ifeq ($(SERVICE),probe-manager)
	@if [ -f $(PROBE_LOG_FILE) ]; then \
		tail -f $(PROBE_LOG_FILE); \
	else \
		if systemctl is-active --quiet probe-manager 2>/dev/null; then \
			journalctl -u probe-manager -f; \
		else \
			echo "Log file not found: $(PROBE_LOG_FILE)"; \
			echo "Probe Manager may not be running."; \
		fi \
	fi
else ifdef SERVICE
	$(DOCKER_COMPOSE) logs -f $(SERVICE)
else
	$(DOCKER_COMPOSE) logs -f
endif

# 查看所有服务状态（重构版本：支持服务未启动、启动失败情况）
list:
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║                    AI-IDPS 服务状态                          ║"
	@echo "╠══════════════════════════════════════════════════════════════╣"
	@echo "║ 云端服务 (Docker Compose)                                    ║"
	@echo "╠══════════════════════════════════════════════════════════════╣"
	@if ! docker info >/dev/null 2>&1; then \
		echo "║  ⚠  Docker 未运行或不可用                                    ║"; \
	else \
		docker compose -f $(COMPOSE_FILE) ps -a --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null | \
		while IFS= read -r line; do \
			printf '║  %-60s ║\n' "$$line"; \
		done; \
		if ! docker compose -f $(COMPOSE_FILE) ps -a 2>/dev/null | grep -v "^NAME" | grep -q .; then \
			echo "║  (无运行中的容器 - 使用 make up 启动服务)                    ║"; \
		fi; \
	fi
	@echo "╠══════════════════════════════════════════════════════════════╣"
	@echo "║ Probe Manager (本地服务)                                     ║"
	@echo "╠══════════════════════════════════════════════════════════════╣"
	@if [ ! -f $(PROBE_BIN) ]; then \
		echo "║  ○ 状态: 未构建                                              ║"; \
		echo "║    提示: make build SERVICE=probe-manager                    ║"; \
	else \
		echo "║  ✓ 二进制: 已构建                                            ║"; \
		if systemctl is-active --quiet probe-manager 2>/dev/null; then \
			echo "║  ● 状态: 运行中 (systemd服务)                                ║"; \
			echo "║    端口: $(PROBE_PORT)                                       ║"; \
		elif [ -f $(PROBE_PID_FILE) ]; then \
			PID=$$(cat $(PROBE_PID_FILE)); \
			if kill -0 $$PID 2>/dev/null; then \
				echo "║  ● 状态: 运行中 (PID: $$PID)                                 ║"; \
				echo "║    端口: $(PROBE_PORT)                                       ║"; \
			else \
				echo "║  ✗ 状态: 已停止 (进程不存在, PID文件残留)                   ║"; \
				echo "║    提示: make up SERVICE=probe-manager                      ║"; \
			fi; \
		else \
			RUNNING_PID=$$(pgrep -f "probe-manager" 2>/dev/null | head -1); \
			if [ -n "$$RUNNING_PID" ]; then \
				echo "║  ● 状态: 运行中 (PID: $$RUNNING_PID, 无PID文件)              ║"; \
			else \
				echo "║  ○ 状态: 已停止                                              ║"; \
				echo "║    提示: make up SERVICE=probe-manager                      ║"; \
			fi; \
		fi; \
	fi
	@if [ -f $(PROBE_SERVICE_FILE) ]; then \
		echo "║  ✓ Systemd服务: 已安装                                       ║"; \
		ENABLED=$$(systemctl is-enabled probe-manager 2>/dev/null || echo "unknown"); \
		echo "║    开机启动: $$ENABLED                                       ║"; \
	else \
		echo "║  ○ Systemd服务: 未安装                                        ║"; \
		echo "║    提示: make install-service                                ║"; \
	fi
	@echo "╚══════════════════════════════════════════════════════════════╝"

# 状态命令 (list 的别名)
status: list

# ============================================================
# Probe Manager 额外命令
# ============================================================

# 清理构建产物
probe-clean:
	@echo "Cleaning Probe Manager build..."
	@rm -rf $(PROBE_BUILD_DIR)
	@echo "Clean complete."

# 前台运行 Probe Manager (调试用)
probe-run:
	@if [ ! -f $(PROBE_BIN) ]; then \
		echo "Probe Manager not built. Run 'make build SERVICE=probe-manager' first."; \
		exit 1; \
	fi
	@echo "Starting Probe Manager on port $(PROBE_PORT) (foreground mode)..."
	@LISTEN_PORT=$(PROBE_PORT) CLOUD_URL=$(CLOUD_URL) $(PROBE_BIN)

# 安装 Probe Manager 到系统
probe-install:
	@echo "Installing Probe Manager..."
	@if [ ! -f $(PROBE_BIN) ]; then \
		echo "Probe Manager not built. Run 'make build SERVICE=probe-manager' first."; \
		exit 1; \
	fi
	@sudo cp $(PROBE_BIN) /usr/local/bin/
	@sudo mkdir -p /etc/probe-manager
	@if [ ! -f /etc/probe-manager/config.json ]; then \
		sudo cp probe/manager/config.example.json /etc/probe-manager/config.json 2>/dev/null || true; \
	fi
	@echo "Installed to /usr/local/bin/probe-manager"

# 卸载 Probe Manager
probe-uninstall:
	@echo "Uninstalling Probe Manager..."
	@sudo rm -f /usr/local/bin/probe-manager
	@echo "Uninstalled."

# ============================================================
# NIDS Probe 额外命令
# ============================================================

# 前台运行 NIDS Probe (调试用)
nids-run:
	@if [ ! -f $(NIDS_BIN) ]; then \
		echo "NIDS Probe not built. Run 'make build SERVICE=nids-probe' first."; \
		exit 1; \
	fi
	@echo "Starting NIDS Probe on interface $(NIDS_INTERFACE) (foreground mode)..."
	@$(NIDS_BIN) --manager 127.0.0.1:$(PROBE_PORT) --interface $(NIDS_INTERFACE) \
		--config $(SURICATA_CONFIG)

# 安装 NIDS Probe 到系统
nids-install:
	@echo "Installing NIDS Probe..."
	@if [ ! -f $(NIDS_BIN) ]; then \
		echo "NIDS Probe not built. Run 'make build SERVICE=nids-probe' first."; \
		exit 1; \
	fi
	@sudo cp $(NIDS_BIN) /usr/local/bin/
	@echo "Installed to /usr/local/bin/nids-probe"

# 卸载 NIDS Probe
nids-uninstall:
	@echo "Uninstalling NIDS Probe..."
	@sudo rm -f /usr/local/bin/nids-probe
	@echo "Uninstalled."

# 后台启动 NIDS Probe
nids-up:
	@if [ ! -f $(NIDS_BIN) ]; then \
		echo "NIDS Probe not built. Run 'make build SERVICE=nids-probe' first."; \
		exit 1; \
	fi
	@if [ -f $(NIDS_PID_FILE) ] && kill -0 $$(cat $(NIDS_PID_FILE)) 2>/dev/null; then \
		echo "NIDS Probe is already running (PID: $$(cat $(NIDS_PID_FILE)))"; \
		exit 0; \
	fi
	@echo "Starting NIDS Probe in background..."
	@nohup $(NIDS_BIN) --manager 127.0.0.1:$(PROBE_PORT) --interface $(NIDS_INTERFACE) \
		--config $(SURICATA_CONFIG) > $(NIDS_LOG_FILE) 2>&1 & \
		echo $$! > $(NIDS_PID_FILE)
	@sleep 1
	@if kill -0 $$(cat $(NIDS_PID_FILE)) 2>/dev/null; then \
		echo "NIDS Probe started (PID: $$(cat $(NIDS_PID_FILE)))"; \
		echo "Interface: $(NIDS_INTERFACE)"; \
		echo "Log file: $(NIDS_LOG_FILE)"; \
	else \
		echo "Failed to start NIDS Probe. Check logs:"; \
		cat $(NIDS_LOG_FILE); \
		rm -f $(NIDS_PID_FILE); \
		exit 1; \
	fi

# 停止 NIDS Probe
nids-down:
	@if [ -f $(NIDS_PID_FILE) ]; then \
		PID=$$(cat $(NIDS_PID_FILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			echo "Stopping NIDS Probe (PID: $$PID)..."; \
			kill $$PID; \
			rm -f $(NIDS_PID_FILE); \
			echo "Stopped."; \
		else \
			echo "NIDS Probe not running (stale PID file)."; \
			rm -f $(NIDS_PID_FILE); \
		fi \
	else \
		echo "NIDS Probe PID file not found."; \
		pkill -f nids-probe || echo "No nids-probe process found."; \
	fi

# 查看 NIDS Probe 日志
nids-logs:
	@if [ -f $(NIDS_LOG_FILE) ]; then \
		tail -f $(NIDS_LOG_FILE); \
	else \
		echo "Log file not found: $(NIDS_LOG_FILE)"; \
	fi

# ============================================================
# Systemd 服务管理
# ============================================================

# 安装 systemd 服务
install-service: probe-install
	@echo "Creating systemd service file..."
	@sudo cp $(PROBE_SERVICE_TEMPLATE) $(PROBE_SERVICE_FILE)
	@sudo sed -i 's|Environment=LISTEN_PORT=.*|Environment=LISTEN_PORT=$(PROBE_PORT)|' $(PROBE_SERVICE_FILE)
	@sudo sed -i 's|Environment=CLOUD_URL=.*|Environment=CLOUD_URL=$(CLOUD_URL)|' $(PROBE_SERVICE_FILE)
	@sudo systemctl daemon-reload
	@echo "Systemd service installed: probe-manager"
	@echo ""
	@echo "Usage:"
	@echo "  sudo systemctl start probe-manager    - 启动服务"
	@echo "  sudo systemctl stop probe-manager     - 停止服务"
	@echo "  sudo systemctl enable probe-manager   - 开机自启"
	@echo "  sudo systemctl status probe-manager   - 查看状态"
	@echo "  journalctl -u probe-manager -f        - 查看日志"

# 卸载 systemd 服务
uninstall-service:
	@echo "Removing systemd service..."
	@if systemctl is-active --quiet probe-manager 2>/dev/null; then \
		sudo systemctl stop probe-manager; \
	fi
	@sudo systemctl disable probe-manager 2>/dev/null || true
	@sudo rm -f $(PROBE_SERVICE_FILE)
	@sudo systemctl daemon-reload
	@echo "Systemd service removed."

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
	@echo "统一服务管理:"
	@echo "  make build [SERVICE=xxx]     构建服务"
	@echo "  make rebuild [SERVICE=xxx]   完全重新构建"
	@echo "  make up [SERVICE=xxx]        启动服务"
	@echo "  make down [SERVICE=xxx]      停止服务"
	@echo "  make restart [SERVICE=xxx]   重启服务"
	@echo "  make logs [SERVICE=xxx]      查看服务日志"
	@echo "  make list                    查看所有服务状态"
	@echo ""
	@echo "SERVICE 可选值:"
	@echo "  (不指定)      所有云端Docker服务"
	@echo "  backend       云端后端服务"
	@echo "  frontend      云端前端服务"
	@echo "  nginx         Nginx代理"
	@echo "  redis         Redis服务"
	@echo "  mysql         MySQL服务"
	@echo "  clickhouse    ClickHouse服务"
	@echo "  probe-manager Probe Manager (C++本地服务)"
	@echo "  nids-probe    NIDS Probe (C++本地服务)"
	@echo "  probes        所有探针 (Manager + NIDS)"
	@echo ""
	@echo "Probe Manager 专用命令:"
	@echo "  make probe-run              前台运行 (调试用)"
	@echo "  make probe-clean            清理构建产物"
	@echo "  make probe-install          安装到系统"
	@echo "  make probe-uninstall        从系统卸载"
	@echo ""
	@echo "NIDS Probe 专用命令:"
	@echo "  make nids-run               前台运行 (调试用)"
	@echo "  make nids-up                后台启动"
	@echo "  make nids-down              停止"
	@echo "  make nids-logs              查看日志"
	@echo "  make nids-install           安装到系统"
	@echo "  make nids-uninstall         从系统卸载"
	@echo ""
	@echo "Systemd 服务管理:"
	@echo "  make install-service        安装为 systemd 服务"
	@echo "  make uninstall-service      卸载 systemd 服务"
	@echo ""
	@echo "测试:"
	@echo "  make test-api               运行云端 API 测试"
	@echo "  make test-probe             运行探针黑盒测试 (快速)"
	@echo "  make test-probe-full        运行探针完整测试"
	@echo "  make test-stress            运行压力测试"
	@echo "  make test-all               运行所有测试"
	@echo ""
	@echo "配置变量:"
	@echo "  PROBE_PORT=$(PROBE_PORT)        Probe Manager 端口"
	@echo "  CLOUD_URL=$(CLOUD_URL)   云端 API 地址"
	@echo ""
	@echo "示例:"
	@echo "  make up                              启动所有云端服务"
	@echo "  make build SERVICE=probe-manager    构建 Probe Manager"
	@echo "  make up SERVICE=probe-manager       启动 Probe Manager"
	@echo "  make list                           查看所有服务状态"
	@echo "  make install-service                安装为 systemd 服务"
	@echo "  PROBE_PORT=9002 make up SERVICE=probe-manager  指定端口启动"
