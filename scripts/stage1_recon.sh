#!/bin/bash
# Stage 1: Parallel Reconnaissance
# Based on batch-analysis.md workflow
# Analyzes all binaries in parallel using GNU Parallel

set -e

# Configuration
BINARY_DIR="${1:-/opt/projects/repositories/ocproto-research/binaries/5.1.12.146/extracted/linux64/cisco-secure-client-linux64-5.1.12.146}"
OUTPUT_DIR="${2:-/opt/projects/repositories/ocproto-research/analysis/5.1/predeploy/stage1_output}"
WORKERS="${3:-8}"
LOG_FILE="$OUTPUT_DIR/stage1_recon.log"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Functions
log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[⚠]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[✗]${NC} $1" | tee -a "$LOG_FILE"
}

analyze_binary() {
    local binary="$1"
    local output_dir="$2"
    local base=$(basename "$binary")

    echo "[*] Analyzing: $base"
    mkdir -p "$output_dir/$base"

    # File type identification
    file "$binary" > "$output_dir/$base/file_type.txt" 2>&1 || true

    # String extraction (min 8 chars)
    strings -a -n 8 "$binary" > "$output_dir/$base/strings.txt" 2>&1 || true

    # Protocol keywords
    grep -iE "otp|totp|auth|token|secret|verify|cstp|dtls|x-cstp|x-dtls|tls|ssl|hmac" \
        "$output_dir/$base/strings.txt" \
        > "$output_dir/$base/keywords.txt" 2>&1 || true

    # Symbol extraction (dynamic)
    nm -D "$binary" 2>/dev/null > "$output_dir/$base/nm_dynamic.txt" || true

    # Symbol extraction (all, demangled)
    nm -C "$binary" 2>/dev/null > "$output_dir/$base/nm_all.txt" || true

    # Dependencies
    ldd "$binary" 2>/dev/null > "$output_dir/$base/ldd.txt" || true

    # ELF sections
    readelf -S "$binary" 2>/dev/null > "$output_dir/$base/sections.txt" || true

    # ELF headers
    readelf -h "$binary" 2>/dev/null > "$output_dir/$base/headers.txt" || true

    # ELF program headers
    readelf -l "$binary" 2>/dev/null > "$output_dir/$base/program_headers.txt" || true

    # Function count estimation
    local func_count=$(grep -c " T " "$output_dir/$base/nm_all.txt" 2>/dev/null || echo "0")
    echo "Estimated function count: $func_count" > "$output_dir/$base/stats.txt"

    # Size
    local size=$(stat -c%s "$binary" 2>/dev/null || echo "0")
    echo "Binary size: $size bytes" >> "$output_dir/$base/stats.txt"

    # String count
    local str_count=$(wc -l < "$output_dir/$base/strings.txt" 2>/dev/null || echo "0")
    echo "String count: $str_count" >> "$output_dir/$base/stats.txt"

    # Keyword matches
    local kw_count=$(wc -l < "$output_dir/$base/keywords.txt" 2>/dev/null || echo "0")
    echo "Keyword matches: $kw_count" >> "$output_dir/$base/stats.txt"

    echo "[✓] Complete: $base (funcs: $func_count, strings: $str_count, keywords: $kw_count)"
}

export -f analyze_binary

# Main execution
main() {
    # Create output directory first
    mkdir -p "$OUTPUT_DIR"

    log "Stage 1: Parallel Reconnaissance"
    log "Binary directory: $BINARY_DIR"
    log "Output directory: $OUTPUT_DIR"
    log "Parallel workers: $WORKERS"

    # Check if binary directory exists
    if [ ! -d "$BINARY_DIR" ]; then
        error "Binary directory not found: $BINARY_DIR"
        exit 1
    fi

    # Find all ELF binaries
    log "Discovering binaries..."
    local binary_list=$(find "$BINARY_DIR" -type f \( -name "*.so" -o -name "*.so.*" -o -executable \) 2>/dev/null)
    local binary_count=$(echo "$binary_list" | wc -l)

    if [ -z "$binary_list" ]; then
        error "No binaries found in $BINARY_DIR"
        exit 1
    fi

    success "Found $binary_count binaries"

    # Check for GNU Parallel
    if command -v parallel &> /dev/null; then
        log "Using GNU Parallel with $WORKERS workers"
        echo "$binary_list" | parallel -j "$WORKERS" --bar analyze_binary {} "$OUTPUT_DIR"
    else
        warning "GNU Parallel not found, using sequential processing"
        while IFS= read -r binary; do
            analyze_binary "$binary" "$OUTPUT_DIR"
        done <<< "$binary_list"
    fi

    # Generate summary report
    log "Generating summary report..."
    {
        echo "# Stage 1 Reconnaissance Summary"
        echo ""
        echo "**Date**: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "**Binary Directory**: $BINARY_DIR"
        echo "**Binaries Analyzed**: $binary_count"
        echo "**Workers**: $WORKERS"
        echo ""
        echo "## Binary Statistics"
        echo ""
        echo "| Binary | Size | Functions | Strings | Keywords |"
        echo "|--------|------|-----------|---------|----------|"

        for dir in "$OUTPUT_DIR"/*/; do
            if [ -d "$dir" ]; then
                local name=$(basename "$dir")
                local size=$(grep "Binary size:" "$dir/stats.txt" 2>/dev/null | awk '{print $3}' || echo "0")
                local funcs=$(grep "function count:" "$dir/stats.txt" 2>/dev/null | awk '{print $4}' || echo "0")
                local strings=$(grep "String count:" "$dir/stats.txt" 2>/dev/null | awk '{print $3}' || echo "0")
                local keywords=$(grep "Keyword matches:" "$dir/stats.txt" 2>/dev/null | awk '{print $3}' || echo "0")
                echo "| $name | $size | $funcs | $strings | $keywords |"
            fi
        done

        echo ""
        echo "## High-Priority Binaries"
        echo ""
        echo "Binaries with most protocol keywords:"
        echo ""

        for dir in "$OUTPUT_DIR"/*/; do
            if [ -d "$dir" ]; then
                local name=$(basename "$dir")
                local kw_count=$(wc -l < "$dir/keywords.txt" 2>/dev/null || echo "0")
                if [ "$kw_count" -gt 0 ]; then
                    echo "- **$name**: $kw_count keyword matches"
                fi
            fi
        done | sort -rn -t: -k2 | head -10

    } > "$OUTPUT_DIR/SUMMARY.md"

    success "Stage 1 reconnaissance complete!"
    log "Output directory: $OUTPUT_DIR"
    log "Summary report: $OUTPUT_DIR/SUMMARY.md"
    log "Log file: $LOG_FILE"
}

# Run main
main "$@"
