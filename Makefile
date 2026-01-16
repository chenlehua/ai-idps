# AI-IDPS 项目管理命令
#
# ============ 命令说明 ============
#   make build [SERVICE=xxx]    - 构建服务
#   make rebuild [SERVICE=xxx]  - 完全重新构建服务
#   make up [SERVICE=xxx]       - 启动服务
#   make down [SERVICE=xxx]     - 停止服务
#   make restart [SERVICE=xxx]  - 重启服务
#   make logs [SERVICE=xxx]     - 查看服务日志
#   make clean [SERVICE=xxx]    - 清理构建产物
#   make install [SERVICE=xxx]  - 安装到系统
#   make uninstall [SERVICE=xxx]- 从系统卸载
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

.PHONY: build rebuild up down restart logs clean install uninstall download-rules list status help

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
ifeq ($(SERVICE),suricata)
	@if systemctl is-active --quiet suricata 2>/dev/null; then \
		echo "Suricata is already running"; \
	else \
		echo "Starting Suricata..."; \
		sudo systemctl start suricata; \
		sleep 2; \
		if systemctl is-active --quiet suricata 2>/dev/null; then \
			echo "Suricata started successfully"; \
		else \
			echo "Failed to start Suricata. Check: journalctl -u suricata"; \
			exit 1; \
		fi; \
	fi
else ifeq ($(SERVICE),probe-manager)
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
ifeq ($(SERVICE),suricata)
	@echo "Stopping Suricata..."
	@sudo systemctl stop suricata 2>/dev/null || true
	@echo "Suricata stopped."
else ifeq ($(SERVICE),probe-manager)
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
ifeq ($(SERVICE),suricata)
	@echo "Restarting Suricata..."
	@sudo systemctl restart suricata
	@sleep 2
	@if systemctl is-active --quiet suricata 2>/dev/null; then \
		echo "Suricata restarted successfully"; \
	else \
		echo "Failed to restart Suricata. Check: journalctl -u suricata"; \
		exit 1; \
	fi
else ifeq ($(SERVICE),probe-manager)
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
ifeq ($(SERVICE),suricata)
	@if systemctl is-active --quiet suricata 2>/dev/null; then \
		sudo journalctl -u suricata -f; \
	elif [ -f /var/log/suricata/suricata.log ]; then \
		sudo tail -f /var/log/suricata/suricata.log; \
	else \
		echo "Suricata is not running and no log file found."; \
	fi
else ifeq ($(SERVICE),probe-manager)
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
# 规则下载
# ============================================================

RULES_DIR := /var/lib/suricata/rules

download-rules:
	@echo "=== Downloading Suricata Rules ==="
	@sudo mkdir -p $(RULES_DIR)
	@echo "Downloading ET Open rules..."
	@sudo curl -L -o /tmp/emerging.rules.tar.gz \
		"https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"
	@echo "Extracting rules..."
	@sudo tar xzf /tmp/emerging.rules.tar.gz -C $(RULES_DIR) --strip-components=1
	@sudo rm -f /tmp/emerging.rules.tar.gz
	@echo "Rules downloaded to $(RULES_DIR)"
	@echo "Rule files:"
	@ls $(RULES_DIR)/*.rules 2>/dev/null | wc -l | xargs -I {} echo "  {} rule files found"

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
		if systemctl is-active --quiet suricata 2>/dev/null; then \
			echo "║  ● 状态: 运行中 (systemd)                                         ║"; \
		else \
			echo "║  ○ 状态: 已停止  (make up SERVICE=suricata)                        ║"; \
		fi; \
	else \
		echo "║  ○ 未安装  (make build/install SERVICE=suricata)                ║"; \
	fi
	@echo "╚══════════════════════════════════════════════════════════════════╝"

status: list

# ============================================================
# 帮助
# ============================================================

help:
	@echo "AI-IDPS 项目管理命令"
	@echo ""
	@echo "服务管理:"
	@echo "  make build [SERVICE=xxx]      构建服务"
	@echo "  make rebuild [SERVICE=xxx]    完全重新构建"
	@echo "  make up [SERVICE=xxx]         启动服务(后台)"
	@echo "  make down [SERVICE=xxx]       停止服务"
	@echo "  make restart [SERVICE=xxx]    重启服务"
	@echo "  make logs [SERVICE=xxx]       查看服务日志"
	@echo "  make clean [SERVICE=xxx]      清理构建产物"
	@echo "  make install [SERVICE=xxx]    安装到系统"
	@echo "  make uninstall [SERVICE=xxx]  从系统卸载"
	@echo "  make download-rules           下载 Suricata 规则"
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
	@echo "配置变量:"
	@echo "  PROBE_PORT=$(PROBE_PORT)           Probe Manager 端口"
	@echo "  CLOUD_URL=$(CLOUD_URL)   云端 API 地址"
	@echo "  NIDS_INTERFACE=$(NIDS_INTERFACE)        NIDS 监控网卡"
	@echo ""
	@echo "示例:"
	@echo "  make build                          构建所有云端服务"
	@echo "  make build SERVICE=probes           构建所有探针"
	@echo "  make up                             启动所有云端服务"
	@echo "  make up SERVICE=probe-manager       启动 Probe Manager"
	@echo "  make logs SERVICE=backend           查看后端日志"
	@echo "  make list                           查看所有服务状态"
	@echo "  make install SERVICE=suricata       安装 Suricata"
