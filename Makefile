.PHONY: test check build

test:
	@mkdir -p .coverage
	go test -mod=vendor -race -timeout=2m -covermode=atomic -coverprofile=.coverage/coverage.out ./...
	@go tool cover -func=.coverage/coverage.out | tee .coverage/functions.txt
	@awk '$$1 == "total:" { found = 1; if ($$3 != "100.0%") { print "Required statement coverage: 100%"; exit 1 } } END { if (!found) exit 1 }' .coverage/functions.txt
	@awk 'NR > 1 && $$(NF-1) > 0 && $$NF == 0 { print "Uncovered code block: " $$0; bad = 1 } END { exit bad }' .coverage/coverage.out

check:
	go vet -mod=vendor ./...
	@test -z "$$(gofmt -l assets.go assets_test.go cmd internal)" || { printf '%s\n' 'Run gofmt before committing'; exit 1; }

build:
	CGO_ENABLED=0 go build -mod=vendor -trimpath -o bin/banwords ./cmd/banwords
