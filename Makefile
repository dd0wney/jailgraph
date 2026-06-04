.PHONY: build test integration vet lint cross clean

build:
	go build ./...

# Cross-platform unit tests (run anywhere, including macOS).
test:
	go test ./... -count=1 -short

# Full-pipeline test against a real local graphdb. Requires JAILGRAPH_GRAPHDB_URL.
integration:
	go test ./... -count=1 -run Integration

vet:
	go vet ./...

lint:
	golangci-lint run ./...

# Verify the Linux-only seccomp backend builds for both supported arches.
cross:
	GOOS=linux GOARCH=amd64 go build ./...
	GOOS=linux GOARCH=arm64 go build ./...

clean:
	go clean ./...
