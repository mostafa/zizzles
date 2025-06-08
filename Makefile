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
