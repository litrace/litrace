.PHONY: default generate build clean check vet test test-privileged lint

default: generate build

generate:
	go generate ./...

build:
	go build -o litrace .

clean:
	rm -f litrace internal/bpf/tracer_bpf*.go internal/bpf/tracer_bpf*.o
	$(MAKE) -C tests/fixtures clean

check: default
	$(MAKE) -C tests/fixtures all
	go test ./...

test: default
	$(MAKE) -C tests/fixtures all
	go test -v ./tests

lint: generate
	go vet ./...
	@go_files="$$(find . -type f -name '*.go' \
		-not -path './.git/*' \
		-not -path './vendor/*')"; \
	if [ -n "$$go_files" ]; then \
		gofmt -w $$go_files; \
	fi
	@tmp="$$(mktemp)"; \
	indent -linux -st internal/bpf/tracer.c > "$$tmp" && mv "$$tmp" internal/bpf/tracer.c || { rm -f "$$tmp"; exit 1; }
