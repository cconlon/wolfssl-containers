#!/bin/bash
# This script verifies checksums on wolfSSL and JNI/JCE/JSSE library files
# match the expected values defined in checksum files to prevent against
# image modification.
set -e

CHECKSUM_DIR="/opt/wolfssl-fips/checksums"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

verify_checksum_file() {
    local checksum_file="$1"
    local description="$2"
    local checksum_path="$CHECKSUM_DIR/$checksum_file"
    local all_valid=true

    echo "Verifying $description..."

    if [ ! -f "$checksum_path" ]; then
        echo -e "  ${RED}${NC} Checksum file not found: $checksum_path"
        return 1
    fi

    while IFS= read -r line; do
        # Skip empty lines
        [ -z "$line" ] && continue

        # Parse checksum and file path
        expected_checksum=$(echo "$line" | awk '{print $1}')
        file_path=$(echo "$line" | awk '{print $2}')

        if [ -z "$expected_checksum" ] || [ -z "$file_path" ]; then
            echo -e "  ${RED}${NC} Invalid checksum format: $line"
            all_valid=false
            continue
        fi

        if [ ! -f "$file_path" ]; then
            echo -e "  ${RED}${NC} File not found: $file_path"
            all_valid=false
            continue
        fi

        # Compute actual checksum
        actual_checksum=$(sha256sum "$file_path" | awk '{print $1}')

        if [ "$expected_checksum" = "$actual_checksum" ]; then
            echo -e "  ${GREEN}${NC} $(basename "$file_path")"
        else
            echo -e "  ${RED}${NC} $(basename "$file_path") - INTEGRITY FAILURE"
            echo -e "    Expected: $expected_checksum"
            echo -e "    Actual:   $actual_checksum"
            all_valid=false
        fi

    done < "$checksum_path"

    if [ "$all_valid" = true ]; then
        return 0
    else
        return 1
    fi
}

# Main verification
all_components_valid=true

# Check all library files (native libraries and JAR files)
if ! verify_checksum_file "libraries.sha256" "all wolfSSL library files (libwolfssl.so, libwolfcryptjni.so, libwolfssljni.so, wolfcrypt-jni.jar, wolfssl-jsse.jar)"; then
    all_components_valid=false
fi

echo ""

# Final result
if [ "$all_components_valid" = true ]; then
    echo -e "${GREEN}ALL FIPS COMPONENTS INTEGRITY VERIFIED${NC}"
    exit 0
else
    echo -e "${RED}FIPS INTEGRITY VERIFICATION FAILED${NC}"
    exit 1
fi

