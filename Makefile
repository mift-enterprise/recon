.PHONY: build run test install clean

BINARY=recon
BUILD_DIR=build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/recon

run: build
	./$(BUILD_DIR)/$(BINARY) scan $(TARGET) -v $(VULN) -d $(DEPTH)

install-tools:
	bash scripts/install-tools.sh

test:
	go test ./...

clean:
	rm -rf $(BUILD_DIR) output/

dev:
	go run ./cmd/recon scan $(TARGET) -v $(VULN) -d $(DEPTH)