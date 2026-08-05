VERSION      ?= $(shell git describe --tags --dirty --always)
COMMIT_HASH  ?= $(shell git rev-parse --short HEAD)

.PHONY: install
install:
	@echo "Installing Talmi version $(VERSION) CLI"
	@go install \
        -ldflags="-w -s \
          -X github.com/darmiel/talmi/internal/buildinfo.Version=$(VERSION) \
          -X github.com/darmiel/talmi/internal/buildinfo.CommitHash=$(COMMIT_HASH)" \
        .
	@echo "✅ Installed Talmi version $(VERSION) CLI"

.PHONY: migrate
migrate:
	migrate -path internal/store/postgres/migrations \
		-database "postgres://talmi:talmi@localhost:5432/talmi_test?sslmode=disable" \
		up

.PHONY: schema
schema:
	@echo "Generating schema"
	@for t in config issuers realms rules; do go run . config schema $$t -o docs/schema/$$t.schema.json; done
	@echo "Generated schema"