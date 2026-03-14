.PHONY: default generate build clean check vet test lint

default: generate build

generate:
	go generate ./...

build:
	go build -o litrace .

clean:
	rm -f litrace internal/bpf/tracer_bpf*.go internal/bpf/tracer_bpf*.o

check: vet test

vet:
	go vet ./...

test:
	go test ./...

lint:
	gofmt -w $$(git ls-files '*.go')
	@tmp="$$(mktemp)"; \
	indent -linux -st internal/bpf/tracer.c > "$$tmp" && mv "$$tmp" internal/bpf/tracer.c || { rm -f "$$tmp"; exit 1; }
