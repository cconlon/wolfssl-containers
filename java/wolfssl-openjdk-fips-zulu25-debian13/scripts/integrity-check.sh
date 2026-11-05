#!/bin/bash
# This script verifies that the checksums of the wolfSSL native libraries,
# the JNI libraries, the provider JARs and the FIPS security configuration
# files (java.security, cacerts, krb5.conf) match the values recorded at image
# build time, to detect image modification.
#
# The script and checksum file are root-owned and read-only, and the image
# runs as a non-root user, so the application cannot change the files or
# their recorded checksums.
set -e

CHECKSUM_DIR="/opt/wolfssl-fips/checksums"

# Files that must be listed in libraries.sha256. A checksum file that is
# missing any of these fails verification. Keep in sync with the file list in
# update-integrity-checksums.sh.
REQUIRED_FILES=(
    "/usr/lib/jni/libwolfcryptjni.so"
    "/usr/lib/jni/libwolfssljni.so"
    "/usr/share/java/wolfcrypt-jni.jar"
    "/usr/share/java/wolfssl-jsse.jar"
    "/usr/share/java/filtered-providers.jar"
    "/usr/lib/jvm/zulu25/conf/security/java.security"
    "/usr/lib/jvm/zulu25/lib/security/cacerts"
    "/etc/krb5.conf"
)

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

    echo "Verifying $description:"

    if [ ! -f "$checksum_path" ]; then
        echo -e "  ${RED}[FAIL]${NC} Checksum file not found: $checksum_path"
        return 1
    fi

    # Every required file must be listed, and at least one libwolfssl.so
    for required in "${REQUIRED_FILES[@]}"; do
        if ! awk '{print $2}' "$checksum_path" | grep -qxF "$required"; then
            echo -e "  ${RED}[FAIL]${NC} Not listed in checksum file: $required"
            all_valid=false
        fi
    done
    if ! awk '{print $2}' "$checksum_path" | grep -q '^/usr/local/lib/libwolfssl\.so'; then
        echo -e "  ${RED}[FAIL]${NC} Not listed in checksum file: /usr/local/lib/libwolfssl.so*"
        all_valid=false
    fi

    while IFS= read -r line; do
        # Skip empty lines
        [ -z "$line" ] && continue

        # Parse checksum and file path
        expected_checksum=$(echo "$line" | awk '{print $1}')
        file_path=$(echo "$line" | awk '{print $2}')

        if [ -z "$expected_checksum" ] || [ -z "$file_path" ]; then
            echo -e "  ${RED}[FAIL]${NC} Invalid checksum format: $line"
            all_valid=false
            continue
        fi

        if [ ! -f "$file_path" ]; then
            echo -e "  ${RED}[FAIL]${NC} File not found: $file_path"
            all_valid=false
            continue
        fi

        # Compute actual checksum
        actual_checksum=$(sha256sum "$file_path" | awk '{print $1}')

        if [ "$expected_checksum" = "$actual_checksum" ]; then
            echo -e "  ${GREEN}[OK]${NC} $(basename "$file_path")"
        else
            echo -e "  ${RED}[FAIL]${NC} $(basename "$file_path") - INTEGRITY FAILURE"
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
if ! verify_checksum_file "libraries.sha256" "sensitive libraries and files"; then
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

