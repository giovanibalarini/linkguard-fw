.PHONY: all build build-frontend build-backend deb deb-from-binary install clean test lint

BINARY_NAME   := linkguard-fw
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DIR     := dist
WEB_DIR       := web
INSTALL_DIR   := /usr/local/bin
SERVICE_DIR   := /etc/systemd/system
DATA_DIR      := /var/lib/linkguard-fw
CONFIG_DIR    := /etc/linkguard-fw

GO_BUILD_FLAGS := -ldflags="-X main.version=$(VERSION) -s -w"

# ─── Build ───────────────────────────────────────────────────────────────────

## all: build frontend and backend
all: build

## build: build the full binary (frontend + backend)
build: build-frontend build-backend

## build-frontend: compile the React frontend into web/dist
build-frontend:
	@echo ">>> Building frontend..."
	cd $(WEB_DIR) && npm install && npm run build

## build-backend: compile the Go binary (embeds web/dist)
build-backend:
	@echo ">>> Building backend binary..."
	@mkdir -p $(BUILD_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/linkguard-fw/

## build-dev: build without optimisations for development
build-dev:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/linkguard-fw/

# ─── Package ─────────────────────────────────────────────────────────────────

# DEB_RECOMMENDS é a FONTE ÚNICA das relações de dependência do pacote. Ela é
# usada tanto por `make deb` (build local) quanto pelo release do GitHub —
# .github/workflows/release.yml chama `make deb-from-binary`, ele NÃO monta
# mais um control próprio.
#
# Isso não é preciosismo: enquanto o workflow tinha a sua própria cópia, o
# .deb oficial (o que chega ao firewall por release e por auto-update) ainda
# declarava `Depends: nftables, iproute2, iptables, iputils-ping` — ou seja,
# o artefato entregue continuava com exatamente o defeito que esta mudança
# existe para eliminar, e sem dns-root-data. TestControlFieldsAreSingleSourced
# (internal/sysprep) trava a reincidência.
#
# NÃO existe campo Depends. A base (nftables, iproute2, iptables,
# iputils-ping) está em Recommends junto com os pacotes opcionais, de
# propósito.
#
# Com a base em Depends, `dpkg -i` numa máquina pelada para no meio: o pacote
# fica em `iU` ("dependency problems prevent configuration of linkguard-fw"),
# o serviço nunca sobe e não sobra painel nenhum para explicar o que houve. E
# o postinst também não pode resolver isso sozinho — o dpkg segura o
# /var/lib/dpkg/lock-frontend durante toda a execução, então qualquer apt-get
# chamado de dentro de um script do pacote morre com "Could not get lock".
#
# Em Recommends: `apt install ./linkguard-fw_*.deb` continua instalando tudo
# (o apt instala Recommends por padrão), e `dpkg -i` puro instala E configura
# — o serviço sobe e o próprio LinkGuard garante a base no primeiro boot
# (internal/bootstrapdeps), que é a premissa do produto: instalar o LinkGuard
# é entregar a máquina a ele.
DEB_RECOMMENDS := nftables, iproute2, iptables, iputils-ping, kea-dhcp4-server, unbound, dns-root-data, smartmontools, chrony

# Parâmetros do deb-from-binary. Sobrescritos pelo workflow de release, que
# cross-compila os dois arcos antes de empacotar.
DEB_ARCH      ?= $(shell dpkg --print-architecture)
DEB_BINARY    ?= $(BUILD_DIR)/$(BINARY_NAME)

## deb: build a .deb package for the current architecture (requires dpkg-deb)
deb: build
	@$(MAKE) --no-print-directory deb-from-binary VERSION=$(VERSION)

## deb-from-binary: package an already-built binary (no build step).
## Chamado por `make deb` e pelo workflow de release — é o único lugar do
## repositório que escreve um DEBIAN/control.
deb-from-binary:
	$(eval DEB_VERSION := $(shell echo "$(VERSION)" | sed 's/^v//'))
	$(eval PKG         := $(BINARY_NAME)_$(DEB_VERSION)_$(DEB_ARCH))
	$(eval PKG_DIR     := $(BUILD_DIR)/deb/$(PKG))
	@echo ">>> Building $(PKG).deb..."
	@rm -rf $(PKG_DIR)
	@mkdir -p $(PKG_DIR)/DEBIAN
	@mkdir -p $(PKG_DIR)/usr/local/bin
	@mkdir -p $(PKG_DIR)/lib/systemd/system
	@install -m 0755 $(DEB_BINARY)                          $(PKG_DIR)/usr/local/bin/$(BINARY_NAME)
	@install -m 0644 deploy/linkguard-fw.service            $(PKG_DIR)/lib/systemd/system/linkguard-fw.service
	@install -m 0644 deploy/linkguard-notify-down.service    $(PKG_DIR)/lib/systemd/system/linkguard-notify-down.service
	@printf 'Package: $(BINARY_NAME)\nVersion: $(DEB_VERSION)\nArchitecture: $(DEB_ARCH)\nMaintainer: giovanibalarini <giovanibalarini@users.noreply.github.com>\nSection: net\nPriority: optional\nRecommends: $(DEB_RECOMMENDS)\nHomepage: https://github.com/giovanibalarini/linkguard-fw\nDescription: Linux Firewall Management Tool\n A web-based firewall management tool for Linux.\n' \
		> $(PKG_DIR)/DEBIAN/control
	@cp deploy/deb/postinst $(PKG_DIR)/DEBIAN/postinst && chmod 0755 $(PKG_DIR)/DEBIAN/postinst
	@cp deploy/deb/prerm    $(PKG_DIR)/DEBIAN/prerm    && chmod 0755 $(PKG_DIR)/DEBIAN/prerm
	@dpkg-deb --build --root-owner-group $(PKG_DIR) $(BUILD_DIR)/$(PKG).deb
	@echo ">>> Package ready: $(BUILD_DIR)/$(PKG).deb"

# ─── Test ────────────────────────────────────────────────────────────────────

## test: run all Go tests
test:
	go test ./...

## test-verbose: run all Go tests with verbose output
test-verbose:
	go test -v ./...

## test-coverage: run tests with coverage report
test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# ─── Install ─────────────────────────────────────────────────────────────────

## install: install the binary and systemd service (requires root)
install: build
	@echo ">>> Installing LinkGuard FW..."
	install -m 0755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	install -d -m 0750 $(DATA_DIR)
	install -d -m 0750 $(CONFIG_DIR)
	install -m 0644 deploy/linkguard-fw.service $(SERVICE_DIR)/linkguard-fw.service
	@if [ ! -f $(CONFIG_DIR)/config.json ]; then \
		$(INSTALL_DIR)/$(BINARY_NAME) --config $(CONFIG_DIR)/config.json --init-config 2>/dev/null || true; \
		echo ">>> Default config created at $(CONFIG_DIR)/config.json"; \
	fi
	systemctl daemon-reload
	@echo ">>> Installation complete."
	@echo ">>> Run: systemctl enable --now linkguard-fw"

## uninstall: remove the binary and service (requires root)
uninstall:
	systemctl stop linkguard-fw 2>/dev/null || true
	systemctl disable linkguard-fw 2>/dev/null || true
	rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	rm -f $(SERVICE_DIR)/linkguard-fw.service
	systemctl daemon-reload
	@echo ">>> Uninstalled. Data preserved at $(DATA_DIR) and $(CONFIG_DIR)."

# ─── Development ─────────────────────────────────────────────────────────────

## run: run the server in dry-run mode (development)
run: build-backend
	$(BUILD_DIR)/$(BINARY_NAME) --dry-run --debug --addr 127.0.0.1 --port 9997

## run-frontend: start the Vite dev server (hot reload)
run-frontend:
	cd $(WEB_DIR) && npm run dev

## lint: run Go linter
lint:
	go vet ./...

# ─── Clean ───────────────────────────────────────────────────────────────────

## clean: remove build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

## clean-all: remove build artifacts and node_modules
clean-all: clean
	rm -rf $(WEB_DIR)/node_modules $(WEB_DIR)/dist

# ─── Help ────────────────────────────────────────────────────────────────────

## help: print this help
help:
	@echo "LinkGuard FW - Linux Firewall Management Tool"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@awk '/^##/{help=$$0; sub(/^## /,"",help); next} /^[a-z]/{if(help){printf "  %-20s %s\n", $$1, help; help=""}}' $(MAKEFILE_LIST)
