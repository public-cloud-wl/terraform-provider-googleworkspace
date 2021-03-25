TEST?=$$(go list ./...)

default: testacc

fmt:
	@echo "==> Fixing source code with gofmt..."
	gofmt -w -s ./internal/provider

# Currently required by tf-deploy compile
fmtcheck:
	@echo "==> Checking source code against gofmt..."
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

generate:
	go generate  ./...

lint:
	@echo "==> Checking source code against linters..."
	@golangci-lint run ./internal/provider

test: fmtcheck generate
	go test $(TESTARGS) -timeout=30s $(TEST)

# Run acceptance tests
.PHONY: testacc
testacc: fmtcheck
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m