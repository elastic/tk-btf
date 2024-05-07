GO_LICENSE_DETECTOR := go run go.elastic.co/go-licence-detector@v0.6.0
GO_LICENSER := go run github.com/elastic/go-licenser@v0.4.1

.PHONY: tidy lint test notice write-license-headers

all: tidy lint test notice write-license-headers

tidy:
	go mod tidy

lint:
	golangci-lint run -v --timeout=600s

test:
	go test -cover -v -race github.com/elastic/tk-btf

notice:
	@echo "Generate NOTICE"
	go mod tidy
	go mod download
	go list -m -json all | $(GO_LICENSE_DETECTOR) \
		-includeIndirect \
		-rules tools/notice/rules.json \
		-overrides tools/notice/overrides.json \
		-noticeTemplate tools/notice/NOTICE.txt.tmpl \
		-noticeOut NOTICE.txt \
		-depsOut ""

write-license-headers:
	@echo "Write license headers"
	$(GO_LICENSER) \
		-ext ".go" \
		-license ASL2 \
		-licensor "Elasticsearch B.V." \
		.
