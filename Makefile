# AI-IDPS 项目管理命令
#
# ============ 统一服务管理命令 ============
#   make build [SERVICE=xxx]    - 构建服务
#   make rebuild [SERVICE=xxx]  - 完全重新构建服务
#   make up [SERVICE=xxx]       - 启动服务
#   make down [SERVICE=xxx]     - 停止服务
#   make restart [SERVICE=xxx]  - 重启服务
#   make logs [SERVICE=xxx]     - 查看服务日志
#   make clean [SERVICE=xxx]    - 清理构建产物
#   make install [SERVICE=xxx]  - 安装到系统
#   make uninstall [SERVICE=xxx]- 从系统卸载
#   make run [SERVICE=xxx]      - 前台运行(调试用)
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
#   probes          - 所有探针 (Manager + NIDS)
#   suricata        - Suricata 检测引擎
#
# ============ 测试 ============
#   make test-api           - 运行云端 API 测试
#   make test-probe         - 运行探针黑盒测试
#   make test-all           - 运行所有测试

# ============ 配置 ============
COMPOSE_FILE := cloud/docker-compose.yml
DOCKER_COMPOSE := docker compose -f $(COMPOSE_FILE)

# 探针构建配置
PROBE_BUILD_DIR := probe/build
PROBE_BIN := $(PROBE_BUILD_DIR)/manager/probe-manager
NIDS_BIN := $(PROBE_BUILD_DIR)/nids/nids-probe

# Suricata 配置
SURICATA_SRC_DIR := third_party/suricata
SURICATA_BUILD_DIR := $(SURICATA_SRC_DIR)/build
SURICATA_BIN := /usr/local/bin/suricata
SURICATA_CONFIG ?= /etc/suricata/suricata.yaml

# 运行配置
PROBE_PORT ?= 9010
CLOUD_URL ?= http://localhost
NIDS_INTERFACE ?= eth0

# PID/日志文件
PROBE_PID_FILE := /tmp/probe-manager.pid
PROBE_LOG_FILE := /tmp/probe-manager.log
NIDS_PID_FILE := /tmp/nids-probe.pid
NIDS_LOG_FILE := /tmp/nids-probe.log

# Systemd 服务
PROBE_SERVICE_FILE := /etc/systemd/system/probe-manager.service
NIDS_SERVICE_FILE := /etc/systemd/system/nids-probe.service
PROBE_SERVICE_TEMPLATE := scripts/probe-manager.service
NIDS_SERVICE_TEMPLATE := scripts/nids-probe.service

# 可选的服务参数
SERVICE ?=

.PHONY: build rebuild up down restart logs clean install uninstall run \
        list status test-api test-probe test-nids test-stress test-all help

# ============================================================
# 构建命令
# ============================================================

build:
ifeq ($(SERVICE),probe-manager)
	@echo "=== Building Probe Manager ==="
	@mkdir -p $(PROBE_BUILD_DIR)
	@cd $(PROBE_BUILD_DIR) && CXX=g++ cmake .. && make -j$$(nproc) probe-manager
	@echo "Build complete: $(PROBE_BIN)"
else ifeq ($(SERVICE),nids-probe)
	@echo "=== Building NIDS Probe ==="
	@mkdir -p $(PROBE_BUILD_DIR)
	@cd $(PROBE_BUILD_DIR) && CXX=g++ cmake .. && make -j$$(nproc) nids-probe
	@echo "Build complete: $(NIDS_BIN)"
else ifeq ($(SERVICE),probes)
	@echo "=== Building All Probes (Manager + NIDS) ==="
	@mkdir -p $(PROBE_BUILD_DIR)
	@cd $(PROBE_BUILD_DIR) && CXX=g++ cmake .. && make -j$$(nproc)
	@echo "Build complete: $(PROBE_BIN) $(NIDS_BIN)"
else ifeq ($(SERVICE),suricata)
	@echo "=== Building Suricata ==="
	@if [ ! -d "$(SURICATA_SRC_DIR)" ] || [ ! -f "$(SURICATA_SRC_DIR)/configure.ac" ]; then \
		echo "Error: Suricata source not found in $(SURICATA_SRC_DIR)"; \
		echo "Please run: git submodule update --init --recursive"; \
		exit 1; \
	fi
	@cd $(SURICATA_SRC_DIR) && \
		if [ ! -f configure ]; then \
			echo "Running autogen.sh..."; \
			./autogen.sh; \
		fi && \
		if [ ! -f Makefile ]; then \
			echo "Running configure..."; \
			./configure --prefix=/usr/local --sysconfdir=/etc --localstatedir=/var \
				--enable-nfqueue --enable-nflog --disable-gccmarch-native; \
		fi && \
		echo "Compiling Suricata..." && \
		make -j$$(nproc)
	@echo "Build complete. Run 'make install SERVICE=suricata' to install."
else ifdef SERVICE
	$(DOCKER_COMPOSE) build $(SERVICE)
else
	$(DOCKER_COMPOSE) build
endif

rebuild:
ifeq ($(SERVICE),probe-manager)
	@echo "=== Rebuilding Probe Manager ==="
	@rm -rf $(PROBE_BUILD_DIR)
	@$(MAKE) build SERVICE=probe-manager
else ifeq ($(SERVICE),nids-probe)
	@echo "=== Rebuilding NIDS Probe ==="
	@rm -rf $(PROBE_BUILD_DIR)
	@$(MAKE) build SERVICE=nids-probe
else ifeq ($(SERVICE),probes)
	@echo "=== Rebuilding All Probes ==="
	@rm -rf $(PROBE_BUILD_DIR)
	@$(MAKE) build SERVICE=probes
else ifeq ($(SERVICE),suricata)
	@echo "=== Rebuilding Suricata ==="
	@if [ -d "$(SURICATA_SRC_DIR)" ]; then \
		cd $(SURICATA_SRC_DIR) && make clean 2>/dev/null || true; \
		rm -f Makefile configure; \
	fi
	@$(MAKE) build SERVICE=suricata
else ifdef SERVICE
	$(DOCKER_COMPOSE) build --no-cache $(SERVICE)
else
	$(DOCKER_COMPOSE) build --no-cache
endif

# ============================================================
# 启动/停止命令
# ============================================================

up:
ifeq ($(SERVICE),probe-manager)
	@if [ ! -f $(PROBE_BIN) ]; then \
		echo "Probe Manager not built. Run 'make build SERVICE=probe-manager' first."; \
		exit 1; \
	fi
	@if systemctl is-active --quiet probe-manager 2>/dev/null; then \
		echo "Probe Manager is running as systemd service"; \
		exit 0; \
	fi
	@if [ -f $(PROBE_PID_FILE) ] && kill -0 $$(cat $(PROBE_PID_FILE)) 2>/dev/null; then \
		echo "Probe Manager is already running (PID: $$(cat $(PROBE_PID_FILE)))"; \
		exit 0; \
	fi
	@echo "Starting Probe Manager..."
	@LISTEN_PORT=$(PROBE_PORT) CLOUD_URL=$(CLOUD_URL) nohup $(PROBE_BIN) > $(PROBE_LOG_FILE) 2>&1 & \
		echo $$! > $(PROBE_PID_FILE)
	@sleep 1
	@if kill -0 $$(cat $(PROBE_PID_FILE)) 2>/dev/null; then \
		echo "Probe Manager started (PID: $$(cat $(PROBE_PID_FILE)), Port: $(PROBE_PORT))"; \
	else \
		echo "Failed to start. Check logs: $(PROBE_LOG_FILE)"; \
		rm -f $(PROBE_PID_FILE); \
		exit 1; \
	fi
else ifeq ($(SERVICE),nids-probe)
	@if [ ! -f $(NIDS_BIN) ]; then \
		echo "NIDS Probe not built. Run 'make build SERVICE=nids-probe' first."; \
		exit 1; \
	fi
	@if systemctl is-active --quiet nids-probe 2>/dev/null; then \
		echo "NIDS Probe is running as systemd service"; \
		exit 0; \
	fi
	@if [ -f $(NIDS_PID_FILE) ] && kill -0 $$(cat $(NIDS_PID_FILE)) 2>/dev/null; then \
		echo "NIDS Probe is already running (PID: $$(cat $(NIDS_PID_FILE)))"; \
		exit 0; \
	fi
	@echo "Starting NIDS Probe..."
	@nohup $(NIDS_BIN) --manager 127.0.0.1:$(PROBE_PORT) --interface $(NIDS_INTERFACE) \
		--config $(SURICATA_CONFIG) > $(NIDS_LOG_FILE) 2>&1 & echo $$! > $(NIDS_PID_FILE)
	@sleep 1
	@if kill -0 $$(cat $(NIDS_PID_FILE)) 2>/dev/null; then \
		echo "NIDS Probe started (PID: $$(cat $(NIDS_PID_FILE)), Interface: $(NIDS_INTERFACE))"; \
	else \
		echo "Failed to start. Check logs: $(NIDS_LOG_FILE)"; \
		rm -f $(NIDS_PID_FILE); \
		exit 1; \
	fi
else ifeq ($(SERVICE),probes)
	@$(MAKE) up SERVICE=probe-manager
	@sleep 1
	@$(MAKE) up SERVICE=nids-probe
else ifdef SERVICE
	$(DOCKER_COMPOSE) up -d $(SERVICE)
else
	$(DOCKER_COMPOSE) up -d
endif

down:
ifeq ($(SERVICE),probe-manager)
	@if systemctl is-active --quiet probe-manager 2>/dev/null; then \
		echo "Stopping Probe Manager systemd service..."; \
		sudo systemctl stop probe-manager; \
	elif [ -f $(PROBE_PID_FILE) ]; then \
		PID=$$(cat $(PROBE_PID_FILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			echo "Stopping Probe Manager (PID: $$PID)..."; \
			kill $$PID; \
		fi; \
		rm -f $(PROBE_PID_FILE); \
	else \
		pkill -f "probe-manager" 2>/dev/null || true; \
	fi
	@echo "Probe Manager stopped."
else ifeq ($(SERVICE),nids-probe)
	@if systemctl is-active --quiet nids-probe 2>/dev/null; then \
		echo "Stopping NIDS Probe systemd service..."; \
		sudo systemctl stop nids-probe; \
	elif [ -f $(NIDS_PID_FILE) ]; then \
		PID=$$(cat $(NIDS_PID_FILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			echo "Stopping NIDS Probe (PID: $$PID)..."; \
			kill $$PID; \
		fi; \
		rm -f $(NIDS_PID_FILE); \
	else \
		pkill -f "nids-probe" 2>/dev/null || true; \
	fi
	@echo "NIDS Probe stopped."
else ifeq ($(SERVICE),probes)
	@$(MAKE) down SERVICE=nids-probe
	@$(MAKE) down SERVICE=probe-manager
else ifdef SERVICE
	$(DOCKER_COMPOSE) stop $(SERVICE)
	$(DOCKER_COMPOSE) rm -f $(SERVICE)
else
	$(DOCKER_COMPOSE) down
endif

restart:
ifeq ($(SERVICE),probe-manager)
	@$(MAKE) down SERVICE=probe-manager
	@sleep 1
	@$(MAKE) up SERVICE=probe-manager
else ifeq ($(SERVICE),nids-probe)
	@$(MAKE) down SERVICE=nids-probe
	@sleep 1
	@$(MAKE) up SERVICE=nids-probe
else ifeq ($(SERVICE),probes)
	@$(MAKE) down SERVICE=probes
	@sleep 1
	@$(MAKE) up SERVICE=probes
else ifdef SERVICE
	$(DOCKER_COMPOSE) restart $(SERVICE)
else
	$(DOCKER_COMPOSE) restart
endif

# ============================================================
# 日志查看
# ============================================================

logs:
ifeq ($(SERVICE),probe-manager)
	@if [ -f $(PROBE_LOG_FILE) ]; then \
		tail -f $(PROBE_LOG_FILE); \
	elif systemctl is-active --quiet probe-manager 2>/dev/null; then \
		journalctl -u probe-manager -f; \
	else \
		echo "Probe Manager is not running."; \
	fi
else ifeq ($(SERVICE),nids-probe)
	@if [ -f $(NIDS_LOG_FILE) ]; then \
		tail -f $(NIDS_LOG_FILE); \
	elif systemctl is-active --quiet nids-probe 2>/dev/null; then \
		journalctl -u nids-probe -f; \
	else \
		echo "NIDS Probe is not running."; \
	fi
else ifdef SERVICE
	$(DOCKER_COMPOSE) logs -f $(SERVICE)
else
	$(DOCKER_COMPOSE) logs -f
endif

# ============================================================
# 清理命令
# ============================================================

clean:
ifeq ($(SERVICE),probe-manager)
	@echo "Cleaning Probe Manager build..."
	@rm -rf $(PROBE_BUILD_DIR)/manager
	@echo "Done."
else ifeq ($(SERVICE),nids-probe)
	@echo "Cleaning NIDS Probe build..."
	@rm -rf $(PROBE_BUILD_DIR)/nids
	@echo "Done."
else ifeq ($(SERVICE),probes)
	@echo "Cleaning all probes build..."
	@rm -rf $(PROBE_BUILD_DIR)
	@echo "Done."
else ifeq ($(SERVICE),suricata)
	@echo "Cleaning Suricata build..."
	@if [ -d "$(SURICATA_SRC_DIR)" ] && [ -f "$(SURICATA_SRC_DIR)/Makefile" ]; then \
		cd $(SURICATA_SRC_DIR) && make clean; \
	fi
	@echo "Done."
else ifdef SERVICE
	@echo "No clean action for Docker service: $(SERVICE)"
else
	@echo "Cleaning all probe builds..."
	@rm -rf $(PROBE_BUILD_DIR)
	@echo "Done."
endif

# ============================================================
# 安装/卸载命令
# ============================================================

install:
ifeq ($(SERVICE),probe-manager)
	@echo "=== Installing Probe Manager ==="
	@if [ ! -f $(PROBE_BIN) ]; then \
		echo "Probe Manager not built. Run 'make build SERVICE=probe-manager' first."; \
		exit 1; \
	fi
	@sudo cp $(PROBE_BIN) /usr/local/bin/
	@sudo mkdir -p /etc/probe-manager
	@if [ ! -f /etc/probe-manager/config.json ] && [ -f probe/manager/config.example.json ]; then \
		sudo cp probe/manager/config.example.json /etc/probe-manager/config.json; \
	fi
	@if [ -f $(PROBE_SERVICE_TEMPLATE) ]; then \
		sudo cp $(PROBE_SERVICE_TEMPLATE) $(PROBE_SERVICE_FILE); \
		sudo sed -i 's|Environment=LISTEN_PORT=.*|Environment=LISTEN_PORT=$(PROBE_PORT)|' $(PROBE_SERVICE_FILE); \
		sudo sed -i 's|Environment=CLOUD_URL=.*|Environment=CLOUD_URL=$(CLOUD_URL)|' $(PROBE_SERVICE_FILE); \
		sudo systemctl daemon-reload; \
		echo "Systemd service installed."; \
	fi
	@echo "Installed to /usr/local/bin/probe-manager"
else ifeq ($(SERVICE),nids-probe)
	@echo "=== Installing NIDS Probe ==="
	@if [ ! -f $(NIDS_BIN) ]; then \
		echo "NIDS Probe not built. Run 'make build SERVICE=nids-probe' first."; \
		exit 1; \
	fi
	@sudo cp $(NIDS_BIN) /usr/local/bin/
	@if [ -f $(NIDS_SERVICE_TEMPLATE) ]; then \
		sudo cp $(NIDS_SERVICE_TEMPLATE) $(NIDS_SERVICE_FILE); \
		sudo systemctl daemon-reload; \
		echo "Systemd service installed."; \
	fi
	@echo "Installed to /usr/local/bin/nids-probe"
else ifeq ($(SERVICE),probes)
	@$(MAKE) install SERVICE=probe-manager
	@$(MAKE) install SERVICE=nids-probe
else ifeq ($(SERVICE),suricata)
	@echo "=== Installing Suricata ==="
	@if [ ! -f "$(SURICATA_SRC_DIR)/src/suricata" ]; then \
		echo "Suricata not built. Run 'make build SERVICE=suricata' first."; \
		exit 1; \
	fi
	@cd $(SURICATA_SRC_DIR) && sudo make install
	@sudo ldconfig
	@echo "Installing Suricata config files..."
	@cd $(SURICATA_SRC_DIR) && sudo make install-conf
	@echo "Suricata installed to /usr/local/bin/suricata"
else
	@echo "Usage: make install SERVICE=<probe-manager|nids-probe|probes|suricata>"
endif

uninstall:
ifeq ($(SERVICE),probe-manager)
	@echo "=== Uninstalling Probe Manager ==="
	@$(MAKE) down SERVICE=probe-manager 2>/dev/null || true
	@if [ -f $(PROBE_SERVICE_FILE) ]; then \
		sudo systemctl disable probe-manager 2>/dev/null || true; \
		sudo rm -f $(PROBE_SERVICE_FILE); \
		sudo systemctl daemon-reload; \
	fi
	@sudo rm -f /usr/local/bin/probe-manager
	@echo "Uninstalled."
else ifeq ($(SERVICE),nids-probe)
	@echo "=== Uninstalling NIDS Probe ==="
	@$(MAKE) down SERVICE=nids-probe 2>/dev/null || true
	@if [ -f $(NIDS_SERVICE_FILE) ]; then \
		sudo systemctl disable nids-probe 2>/dev/null || true; \
		sudo rm -f $(NIDS_SERVICE_FILE); \
		sudo systemctl daemon-reload; \
	fi
	@sudo rm -f /usr/local/bin/nids-probe
	@echo "Uninstalled."
else ifeq ($(SERVICE),probes)
	@$(MAKE) uninstall SERVICE=nids-probe
	@$(MAKE) uninstall SERVICE=probe-manager
else ifeq ($(SERVICE),suricata)
	@echo "=== Uninstalling Suricata ==="
	@if [ -d "$(SURICATA_SRC_DIR)" ] && [ -f "$(SURICATA_SRC_DIR)/Makefile" ]; then \
		cd $(SURICATA_SRC_DIR) && sudo make uninstall; \
	else \
		sudo rm -f /usr/local/bin/suricata; \
	fi
	@echo "Uninstalled."
else
	@echo "Usage: make uninstall SERVICE=<probe-manager|nids-probe|probes|suricata>"
endif

# ============================================================
# 前台运行(调试)
# ============================================================

run:
ifeq ($(SERVICE),probe-manager)
	@if [ ! -f $(PROBE_BIN) ]; then \
		echo "Probe Manager not built. Run 'make build SERVICE=probe-manager' first."; \
		exit 1; \
	fi
	@echo "Starting Probe Manager in foreground (Port: $(PROBE_PORT))..."
	@LISTEN_PORT=$(PROBE_PORT) CLOUD_URL=$(CLOUD_URL) $(PROBE_BIN)
else ifeq ($(SERVICE),nids-probe)
	@if [ ! -f $(NIDS_BIN) ]; then \
		echo "NIDS Probe not built. Run 'make build SERVICE=nids-probe' first."; \
		exit 1; \
	fi
	@echo "Starting NIDS Probe in foreground (Interface: $(NIDS_INTERFACE))..."
	@$(NIDS_BIN) --manager 127.0.0.1:$(PROBE_PORT) --interface $(NIDS_INTERFACE) \
		--config $(SURICATA_CONFIG)
else
	@echo "Usage: make run SERVICE=<probe-manager|nids-probe>"
endif

# ============================================================
# 状态查看
# ============================================================

list:
	@echo "╔══════════════════════════════════════════════════════════════════╗"
	@echo "║                      AI-IDPS 服务状态                            ║"
	@echo "╠══════════════════════════════════════════════════════════════════╣"
	@echo "║ [云端服务] Docker Compose                                        ║"
	@echo "╠══════════════════════════════════════════════════════════════════╣"
	@if ! command -v docker >/dev/null 2>&1; then \
		echo "║  ⚠  Docker 未安装                                                ║"; \
	elif ! docker info >/dev/null 2>&1; then \
		echo "║  ⚠  Docker 未运行                                                ║"; \
	else \
		docker compose -f $(COMPOSE_FILE) ps -a --format 'table {{.Name}}\t{{.Status}}' 2>/dev/null | \
		tail -n +2 | while IFS= read -r line; do \
			printf '║  %-66s ║\n' "$$line"; \
		done; \
		if ! docker compose -f $(COMPOSE_FILE) ps -a 2>/dev/null | grep -v "^NAME" | grep -q .; then \
			echo "║  (无容器 - 使用 make up 启动)                                    ║"; \
		fi; \
	fi
	@echo "╠══════════════════════════════════════════════════════════════════╣"
	@echo "║ [探针服务] Probe Manager                                         ║"
	@echo "╠══════════════════════════════════════════════════════════════════╣"
	@if [ ! -f $(PROBE_BIN) ]; then \
		echo "║  ○ 构建: 未构建  (make build SERVICE=probe-manager)               ║"; \
	else \
		echo "║  ✓ 构建: 已完成                                                   ║"; \
		if systemctl is-active --quiet probe-manager 2>/dev/null; then \
			echo "║  ● 状态: 运行中 (systemd)                                         ║"; \
		elif [ -f $(PROBE_PID_FILE) ] && kill -0 $$(cat $(PROBE_PID_FILE)) 2>/dev/null; then \
			printf '║  ● 状态: 运行中 (PID: %-44s ║\n' "$$(cat $(PROBE_PID_FILE)))"; \
		elif ps aux | grep -E "^\S+\s+\S+.*probe-manager" | grep -v defunct | grep -v grep >/dev/null 2>&1; then \
			echo "║  ● 状态: 运行中 (无PID文件)                                       ║"; \
		else \
			echo "║  ○ 状态: 已停止  (make up SERVICE=probe-manager)                  ║"; \
		fi; \
	fi
	@echo "╠══════════════════════════════════════════════════════════════════╣"
	@echo "║ [探针服务] NIDS Probe                                            ║"
	@echo "╠══════════════════════════════════════════════════════════════════╣"
	@if [ ! -f $(NIDS_BIN) ]; then \
		echo "║  ○ 构建: 未构建  (make build SERVICE=nids-probe)                  ║"; \
	else \
		echo "║  ✓ 构建: 已完成                                                   ║"; \
		if systemctl is-active --quiet nids-probe 2>/dev/null; then \
			echo "║  ● 状态: 运行中 (systemd)                                         ║"; \
		elif [ -f $(NIDS_PID_FILE) ] && kill -0 $$(cat $(NIDS_PID_FILE)) 2>/dev/null; then \
			printf '║  ● 状态: 运行中 (PID: %-44s ║\n' "$$(cat $(NIDS_PID_FILE)))"; \
		elif ps aux | grep -E "^\S+\s+\S+.*nids-probe" | grep -v defunct | grep -v grep >/dev/null 2>&1; then \
			echo "║  ● 状态: 运行中 (无PID文件)                                       ║"; \
		else \
			echo "║  ○ 状态: 已停止  (make up SERVICE=nids-probe)                     ║"; \
		fi; \
	fi
	@echo "╠══════════════════════════════════════════════════════════════════╣"
	@echo "║ [依赖] Suricata                                                  ║"
	@echo "╠══════════════════════════════════════════════════════════════════╣"
	@if command -v suricata >/dev/null 2>&1; then \
		VERSION=$$(suricata -V 2>&1 | head -1 | cut -d' ' -f5); \
		printf '║  ✓ 已安装: %-56s ║\n' "$$VERSION"; \
	else \
		echo "║  ○ 未安装  (make build/install SERVICE=suricata)                ║"; \
	fi
	@echo "╚══════════════════════════════════════════════════════════════════╝"

status: list

# ============================================================
# 测试命令
# ============================================================

test-api:
	@echo "=== Running Cloud API Tests ==="
	@chmod +x fixtures/test_api.sh
	@./fixtures/test_api.sh $(CLOUD_URL)

test-probe:
	@echo "=== Running Probe Blackbox Tests ==="
	@cd fixtures/probe_blackbox_tests && python3 run_tests.py --quick \
		--manager-host 127.0.0.1 --manager-port $(PROBE_PORT) \
		--cloud-url $(CLOUD_URL)

test-nids:
	@echo "=== Running NIDS Probe Blackbox Tests ==="
	@chmod +x fixtures/nids_tests/*.sh fixtures/nids_tests/*.py
	@cd fixtures/nids_tests && ./run_all_tests.sh 127.0.0.1 $(PROBE_PORT)

test-nids-quick:
	@echo "=== Running NIDS Quick Tests ==="
	@chmod +x fixtures/nids_tests/*.py
	@cd fixtures/nids_tests && python3 run_nids_tests.py --quick --manager-port $(PROBE_PORT)

test-nids-manager:
	@echo "=== Running NIDS Manager Communication Tests ==="
	@chmod +x fixtures/nids_tests/*.py
	@cd fixtures/nids_tests && python3 test_manager_comm.py --port $(PROBE_PORT)

test-stress:
	@echo "=== Running Probe Stress Tests ==="
	@cd fixtures/probe_blackbox_tests && python3 run_tests.py --stress \
		--manager-host 127.0.0.1 --manager-port $(PROBE_PORT) \
		--cloud-url $(CLOUD_URL)

test-all: test-api test-probe test-nids-quick

# ============================================================
# 规则下载
# ============================================================

download-rules:
	@echo "=== Downloading ET Open Rules ==="
	@chmod +x scripts/download-et-rules.sh
	@./scripts/download-et-rules.sh

# ============================================================
# 帮助
# ============================================================

help:
	@echo "AI-IDPS 项目管理命令"
	@echo ""
	@echo "统一服务管理:"
	@echo "  make build [SERVICE=xxx]      构建服务"
	@echo "  make rebuild [SERVICE=xxx]    完全重新构建"
	@echo "  make up [SERVICE=xxx]         启动服务(后台)"
	@echo "  make down [SERVICE=xxx]       停止服务"
	@echo "  make restart [SERVICE=xxx]    重启服务"
	@echo "  make logs [SERVICE=xxx]       查看服务日志"
	@echo "  make run [SERVICE=xxx]        前台运行(调试)"
	@echo "  make clean [SERVICE=xxx]      清理构建产物"
	@echo "  make install [SERVICE=xxx]    安装到系统"
	@echo "  make uninstall [SERVICE=xxx]  从系统卸载"
	@echo "  make list                     查看所有服务状态"
	@echo ""
	@echo "SERVICE 可选值:"
	@echo "  (不指定)       操作所有云端Docker服务"
	@echo "  backend        云端后端服务"
	@echo "  frontend       云端前端服务"
	@echo "  nginx          Nginx代理"
	@echo "  redis          Redis服务"
	@echo "  mysql          MySQL服务"
	@echo "  clickhouse     ClickHouse服务"
	@echo "  probe-manager  Probe Manager"
	@echo "  nids-probe     NIDS Probe"
	@echo "  probes         所有探针 (Manager + NIDS)"
	@echo "  suricata       Suricata 检测引擎"
	@echo ""
	@echo "测试:"
	@echo "  make test-api          运行云端 API 测试"
	@echo "  make test-probe        运行探针黑盒测试"
	@echo "  make test-nids         运行 NIDS 探针完整测试"
	@echo "  make test-nids-quick   运行 NIDS 探针快速测试"
	@echo "  make test-nids-manager 运行 NIDS-Manager 通信测试"
	@echo "  make test-stress       运行压力测试"
	@echo "  make test-all          运行所有测试"
	@echo ""
	@echo "其他:"
	@echo "  make download-rules  下载 ET Open 规则"
	@echo "  make help            显示此帮助"
	@echo ""
	@echo "配置变量:"
	@echo "  PROBE_PORT=$(PROBE_PORT)           Probe Manager 端口"
	@echo "  CLOUD_URL=$(CLOUD_URL)   云端 API 地址"
	@echo "  NIDS_INTERFACE=$(NIDS_INTERFACE)        NIDS 监控网卡"
	@echo ""
	@echo "示例:"
	@echo "  make build SERVICE=probes           构建所有探针"
	@echo "  make up SERVICE=probe-manager       启动 Probe Manager"
	@echo "  make logs SERVICE=nids-probe        查看 NIDS Probe 日志"
	@echo "  make install SERVICE=probes         安装所有探针到系统"
	@echo "  PROBE_PORT=9002 make up SERVICE=probe-manager  指定端口启动"
