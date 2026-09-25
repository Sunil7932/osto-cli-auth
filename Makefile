BINARY  ?= bin/authcli
VERSION ?= 0.1.0
COMPOSE ?= docker compose

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show the available targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## ---------------------------------------------------------------------------
## Docker (the intended way to run this project)
## ---------------------------------------------------------------------------

.PHONY: up
up: ## Start the PostgreSQL container and wait until it is healthy
	$(COMPOSE) up -d --wait db

.PHONY: cli
cli: up ## Open the interactive login shell in a container
	$(COMPOSE) run --rm app

.PHONY: migrate
migrate: up ## Apply database migrations in a container
	$(COMPOSE) run --rm app migrate

.PHONY: migrate-status
migrate-status: up ## Show which migrations have been applied
	$(COMPOSE) run --rm app migrate-status

.PHONY: logs
logs: ## Follow the database logs
	$(COMPOSE) logs -f db

.PHONY: psql
psql: ## Open a psql session against the running database
	$(COMPOSE) exec db psql -U $${DB_USER:-authcli} -d $${DB_NAME:-authcli}

.PHONY: down
down: ## Stop the containers, keeping the data volume
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop the containers and delete the data volume
	$(COMPOSE) down -v
	rm -rf bin

## ---------------------------------------------------------------------------
## Local development
## ---------------------------------------------------------------------------

.PHONY: build
build: ## Compile the binary into bin/
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/authcli

.PHONY: run
run: build ## Run the shell against a database on localhost
	./$(BINARY)

.PHONY: test
test: ## Run the unit tests
	go test ./...

.PHONY: test-integration
test-integration: ## Run the tests including the ones that need Postgres
	@test -n "$$TEST_DATABASE_URL" || { echo "set TEST_DATABASE_URL first"; exit 1; }
	go test -count=1 ./...

.PHONY: cover
cover: ## Run the unit tests and print coverage per package
	go test -cover ./...

.PHONY: fmt
fmt: ## Format the code
	gofmt -l -w .

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	go mod tidy

.PHONY: check
check: fmt vet test ## Format, vet and test
