# Makefile for Cisco RE Tools Container
# Using Buildah, Podman, and Skopeo

.PHONY: help build push run stop shell logs clean test inspect save load

# Variables
IMAGE_NAME := localhost/cisco-re-tools
IMAGE_TAG := latest
FULL_IMAGE := $(IMAGE_NAME):$(IMAGE_TAG)
CONTAINER_NAME := cisco-re-workspace
REGISTRY ?= registry.example.com

# Directories
BINARIES_DIR := ../binaries
ANALYSIS_DIR := ../analysis
IDA_PRO_DIR := /opt/software/IDA_Pro_9.2.250908
SCRIPTS_DIR := ./scripts
OUTPUT_DIR := ./output
GHIDRA_PROJECTS_DIR := ./ghidra-projects

# Default target
help:
	@echo "Cisco RE Tools Container Management"
	@echo ""
	@echo "Build & Push:"
	@echo "  make build          - Build container image with Buildah"
	@echo "  make push           - Push image to registry with Skopeo"
	@echo "  make save           - Export image to tarball"
	@echo "  make load           - Import image from tarball"
	@echo ""
	@echo "Run & Manage:"
	@echo "  make run            - Start workspace with podman-compose"
	@echo "  make stop           - Stop workspace"
	@echo "  make shell          - Open interactive shell"
	@echo "  make logs           - Show container logs"
	@echo ""
	@echo "Maintenance:"
	@echo "  make test           - Test container functionality"
	@echo "  make inspect        - Inspect image details"
	@echo "  make clean          - Remove containers, images, and volumes"
	@echo ""
	@echo "Analysis Commands:"
	@echo "  make recon          - Run reconnaissance on all binaries"
	@echo "  make ghidra         - Start Ghidra GUI"
	@echo "  make ida            - Start IDA Pro (if mounted)"

# Build container image with Buildah
build:
	@echo "[*] Building container image: $(FULL_IMAGE)"
	@mkdir -p $(OUTPUT_DIR) $(GHIDRA_PROJECTS_DIR) $(SCRIPTS_DIR)
	buildah bud \
		--format docker \
		--layers \
		--tag $(FULL_IMAGE) \
		--file Containerfile \
		.
	@echo "[✓] Build complete: $(FULL_IMAGE)"

# Push image to registry with Skopeo
push:
	@echo "[*] Pushing $(FULL_IMAGE) to $(REGISTRY)"
	skopeo copy \
		--dest-tls-verify=false \
		containers-storage:$(FULL_IMAGE) \
		docker://$(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	@echo "[✓] Push complete"

# Save image to tarball
save:
	@echo "[*] Saving $(FULL_IMAGE) to tarball"
	podman save -o cisco-re-tools.tar $(FULL_IMAGE)
	@echo "[✓] Saved to cisco-re-tools.tar"

# Load image from tarball
load:
	@echo "[*] Loading image from cisco-re-tools.tar"
	podman load -i cisco-re-tools.tar
	@echo "[✓] Image loaded"

# Start workspace with podman-compose
run:
	@echo "[*] Starting RE workspace"
	@mkdir -p $(OUTPUT_DIR) $(GHIDRA_PROJECTS_DIR) $(SCRIPTS_DIR)
	@if [ ! -d "$(IDA_PRO_DIR)" ]; then \
		echo "[!] WARNING: IDA Pro not found at $(IDA_PRO_DIR)"; \
		echo "[!] IDA Pro will not be available in container"; \
	fi
	podman-compose -f compose.yaml up -d
	@echo "[✓] Workspace running"
	@echo "    Access with: make shell"

# Stop workspace
stop:
	@echo "[*] Stopping RE workspace"
	podman-compose -f compose.yaml down
	@echo "[✓] Workspace stopped"

# Open interactive shell
shell:
	@echo "[*] Opening shell in $(CONTAINER_NAME)"
	podman exec -it $(CONTAINER_NAME) /bin/bash

# Show container logs
logs:
	@echo "[*] Showing logs from $(CONTAINER_NAME)"
	podman logs -f $(CONTAINER_NAME)

# Test container functionality
test:
	@echo "[*] Testing container functionality"
	@echo "Testing Ghidra..."
	podman exec $(CONTAINER_NAME) /tools/ghidra/support/analyzeHeadless -help > /dev/null 2>&1 && echo "[✓] Ghidra OK" || echo "[✗] Ghidra FAIL"
	@echo "Testing radare2..."
	podman exec $(CONTAINER_NAME) radare2 -v > /dev/null 2>&1 && echo "[✓] radare2 OK" || echo "[✗] radare2 FAIL"
	@echo "Testing angr..."
	podman exec $(CONTAINER_NAME) python3 -c "import angr; print('angr', angr.__version__)" && echo "[✓] angr OK" || echo "[✗] angr FAIL"
	@echo "Testing file access..."
	podman exec $(CONTAINER_NAME) ls /workspace/binaries > /dev/null 2>&1 && echo "[✓] Binaries mounted OK" || echo "[✗] Binaries NOT mounted"
	@if [ -d "$(IDA_PRO_DIR)" ]; then \
		echo "Testing IDA Pro..."; \
		podman exec $(CONTAINER_NAME) test -x /opt/ida/idat64 && echo "[✓] IDA Pro OK" || echo "[✗] IDA Pro FAIL"; \
	fi

# Inspect image details
inspect:
	@echo "[*] Inspecting $(FULL_IMAGE)"
	podman inspect $(FULL_IMAGE) | jq '.[0] | {Created, Size, Architecture, Os, Labels}'

# Clean up containers, images, and volumes
clean:
	@echo "[*] Cleaning up"
	podman-compose -f compose.yaml down -v || true
	podman rm -f $(CONTAINER_NAME) 2>/dev/null || true
	podman rmi $(FULL_IMAGE) 2>/dev/null || true
	podman volume rm cisco-re-tools_re-output 2>/dev/null || true
	podman volume rm cisco-re-tools_ghidra-projects 2>/dev/null || true
	@echo "[✓] Cleanup complete"

# Completely purge everything (including output)
purge: clean
	@echo "[*] Purging all data (including output)"
	rm -rf $(OUTPUT_DIR)/* $(GHIDRA_PROJECTS_DIR)/*
	@echo "[✓] Purge complete"

# Run reconnaissance on all binaries
recon:
	@echo "[*] Running reconnaissance on all binaries"
	podman exec $(CONTAINER_NAME) bash -c 'for binary in $$(find /workspace/binaries -type f -executable); do \
		echo "Processing: $$binary"; \
		file $$binary > /workspace/output/$$(basename $$binary)_file.txt; \
		strings -n 8 $$binary | grep -E "(CSTP|DTLS|X-CSTP|X-DTLS|auth|token)" > /workspace/output/$$(basename $$binary)_keywords.txt 2>/dev/null || true; \
	done'
	@echo "[✓] Reconnaissance complete. Results in $(OUTPUT_DIR)/"

# Start Ghidra GUI (requires X11 forwarding)
ghidra:
	@echo "[*] Starting Ghidra GUI (requires X11)"
	@echo "    Make sure DISPLAY is set correctly"
	podman exec -it -e DISPLAY=$(DISPLAY) $(CONTAINER_NAME) /tools/ghidra/ghidraRun

# Start IDA Pro (if mounted)
ida:
	@if [ -d "$(IDA_PRO_DIR)" ]; then \
		echo "[*] Starting IDA Pro"; \
		podman exec -it -e DISPLAY=$(DISPLAY) $(CONTAINER_NAME) /opt/ida/ida64; \
	else \
		echo "[!] IDA Pro not mounted at $(IDA_PRO_DIR)"; \
		exit 1; \
	fi

# Quick build and run (for development)
dev: build run
	@echo "[✓] Development environment ready"
	@echo "    Access with: make shell"

# Rebuild from scratch
rebuild: clean build
	@echo "[✓] Rebuild complete"

# Show system info
info:
	@echo "System Information:"
	@echo "  Buildah version: $$(buildah --version)"
	@echo "  Podman version:  $$(podman --version)"
	@echo "  Skopeo version:  $$(skopeo --version)"
	@echo ""
	@echo "Image Information:"
	@if podman inspect $(FULL_IMAGE) > /dev/null 2>&1; then \
		echo "  Image exists: $(FULL_IMAGE)"; \
		echo "  Image size:   $$(podman inspect $(FULL_IMAGE) | jq -r '.[0].Size')"; \
		echo "  Created:      $$(podman inspect $(FULL_IMAGE) | jq -r '.[0].Created')"; \
	else \
		echo "  Image not built yet"; \
	fi
	@echo ""
	@echo "Container Status:"
	@if podman inspect $(CONTAINER_NAME) > /dev/null 2>&1; then \
		echo "  Container running: $(CONTAINER_NAME)"; \
		echo "  Status: $$(podman inspect $(CONTAINER_NAME) | jq -r '.[0].State.Status')"; \
	else \
		echo "  Container not running"; \
	fi
