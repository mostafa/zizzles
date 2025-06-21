.PHONY: update-schema
update-schema:
	@mkdir -p schema
	@echo "Downloading github-action.json from schemastore"
	@wget --show-progress -q https://raw.githubusercontent.com/SchemaStore/schemastore/refs/heads/master/src/schemas/json/github-action.json -O schema/github-action.json
	@echo "Generating Go code from github-action.json"
	@go install github.com/atombender/go-jsonschema@latest
	@go-jsonschema -p github.com/mostafa/zizzles/schema -o schema/github-action.go schema/github-action.json
	@go mod tidy
	@echo "Done"

.PHONY: build-release
build-release-doc:
	@go build -o zizzles -tags doc -trimpath -ldflags "-s -w" main.go

.PHONY: build-release
build-release:
	@go build -o zizzles -trimpath -ldflags "-s -w" main.go

.PHONY: build-debug
build-debug:
	@go build -o zizzles -tags doc main.go

.PHONY: test
test:
	@go test ./...

.PHONY: run
run:
	@make build-debug
	@./zizzles $(ARGS)

# Helper target to show usage
.PHONY: run-help
run-help:
	@echo "Usage: make run ARGS='command [options] [files...]'"
	@echo "Examples:"
	@echo "  make run ARGS='run example.yml'"
	@echo "  make run ARGS='run --severity high example.yml'"
	@echo "  make run ARGS='doc expression-injection'"
	@echo "  make run ARGS='--help'"

.PHONY: doc
doc:
	@make build-debug
	@./zizzles doc
