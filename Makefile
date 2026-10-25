# oauth — build/test/run entry points. `make help` lists targets.

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

CARGO_BUILD_JOBS ?= 4
export CARGO_BUILD_JOBS

# Integration tests create a database per test on this server (admin connection);
# empty → a throwaway testcontainers Postgres 17 instead (CI).
TEST_DATABASE_URL ?= postgres://postgres@localhost:5432/postgres
export TEST_DATABASE_URL

IMAGE ?= ghcr.io/xmiksay/oauth:dev
NPM := npm --prefix web

# Ensure the Node major from .nvmrc: use the current `node` if it already
# matches (CI via setup-node), else switch with nvm; fail loudly otherwise.
NVM = want=$$(cat .nvmrc); have=$$(node --version 2>/dev/null | sed 's/^v\([0-9]*\).*/\1/'); \
	if [ "$$have" != "$$want" ]; then \
		export NVM_DIR="$${NVM_DIR:-$$HOME/.nvm}"; \
		[ -s "$$NVM_DIR/nvm.sh" ] || { echo "Node $$want required (found $${have:-none}) and nvm not found" >&2; exit 1; }; \
		. "$$NVM_DIR/nvm.sh" && nvm use >/dev/null || { echo "Node $$want not installed in nvm (run: nvm install)" >&2; exit 1; }; \
	fi;
# Load .env (if present) into the recipe's environment with shell semantics.
DOTENV = set -a; [ -f .env ] && . ./.env; set +a;

.PHONY: help build run dev-db web-dev lint lint-rust lint-web fmt test test-unit \
	test-integration test-db-clean web-test web-build docker bootstrap telegram-webhook clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-17s\033[0m %s\n", $$1, $$2}'

build: web-build ## Build the SPA and the release binary
	cargo build --release --locked

run: ## Run `oauth serve` locally (loads .env; needs `make dev-db`)
	$(DOTENV) cargo run -- serve

dev-db: ## Start the dev Postgres 17 and Mailpit (docker compose)
	docker compose up -d --wait postgres mailpit

web-dev: ## Run the Vite dev server (proxies API to the backend)
	$(NVM) $(NPM) run dev

lint: lint-rust lint-web ## rustfmt check, clippy -D warnings, eslint, vue-tsc

lint-rust: ## rustfmt check, clippy -D warnings
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings

lint-web: ## eslint, vue-tsc
	$(NVM) $(NPM) run lint
	$(NVM) $(NPM) run typecheck

fmt: ## Format Rust sources
	cargo fmt --all

test: test-unit test-integration web-test ## Run every test suite

test-unit: ## Rust unit tests (lib + bin)
	cargo test --workspace --lib --bins

test-integration: ## Rust integration tests (local Postgres at TEST_DATABASE_URL; empty → testcontainers)
	cargo test --workspace --test '*'

web-test: ## Frontend unit tests (vitest)
	$(NVM) $(NPM) run test

web-build: ## Build the SPA into web/dist
	$(NVM) $(NPM) run build

docker: ## Build the container image ($(IMAGE))
	docker build -t $(IMAGE) .

bootstrap: ## Create system tenant + Global Admin (idempotent): make bootstrap ADMIN_EMAIL=you@example.com [RESET=1]
	@[ -n "$(ADMIN_EMAIL)" ] || { echo "usage: make bootstrap ADMIN_EMAIL=you@example.com [RESET=1]" >&2; exit 1; }
	$(DOTENV) cargo run -- bootstrap --admin-email "$(ADMIN_EMAIL)" $(if $(RESET),--reset-password)

telegram-webhook: ## Register {PUBLIC_URL}/telegram/webhook with the Telegram bot (loads .env; needs TELEGRAM_*)
	$(DOTENV) cargo run -- telegram set-webhook

test-db-clean: ## Drop oauth_it_* databases and roles left on TEST_DATABASE_URL by killed test runs
	@[ -n "$$TEST_DATABASE_URL" ] || { echo "TEST_DATABASE_URL is empty" >&2; exit 1; }
	psql "$$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -qAt \
	  -c "SELECT format('DROP DATABASE %I WITH (FORCE)', datname) FROM pg_database WHERE datname LIKE 'oauth\\_it\\_%'" \
	  -c "SELECT format('DROP ROLE %I', rolname) FROM pg_roles WHERE rolname LIKE 'oauth\\_it\\_%'" \
	  | psql "$$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -q

clean: ## Remove build artifacts
	cargo clean
	rm -rf web/dist
