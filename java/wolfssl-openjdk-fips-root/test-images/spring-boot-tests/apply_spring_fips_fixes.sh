#!/bin/bash
# ==============================================================================
# Spring Boot FIPS Compatibility Fixes for wolfJSSE
# ==============================================================================
# Simplified version based on working non-FIPS approach, with FIPS-specific additions.
#
# FIPS Requirements:
# 1. WKS keystore format (not JKS/PKCS12)
# 2. FIPS-compliant passwords (min 14 chars for HMAC PBKDF2)
# 3. CA-signed certificates (self-signed fail native wolfSSL validation)
# ==============================================================================

# Don't use set -e due to subshell/pipeline interactions

SPRING_BOOT_DIR="${1:-/app/spring-boot}"
BOOT_MAIN="${SPRING_BOOT_DIR}/spring-boot-project/spring-boot/src/main/java/org/springframework/boot"
BOOT_TEST="${SPRING_BOOT_DIR}/spring-boot-project/spring-boot/src/test/java/org/springframework/boot"
AUTOCONFIG_TEST="${SPRING_BOOT_DIR}/spring-boot-project/spring-boot-autoconfigure/src/test/java/org/springframework/boot/autoconfigure"

echo "=== Applying Spring Boot FIPS Fixes ==="

# FIPS-compliant password (minimum 14 characters for HMAC PBKDF2)
FIPS_PASSWORD="wolfSSLFIPSPwd2024"

# ==============================================================================
# SECTION 1: Replace short passwords with FIPS-compliant ones
# ==============================================================================
echo ""
echo "=== SECTION 1: Password replacements for FIPS compliance ==="

# Replace common short passwords in SSL-related test files
find "${SPRING_BOOT_DIR}/spring-boot-project" -name "*.java" -type f 2>/dev/null | while IFS= read -r file; do
    # Check basename for SSL-related names OR file contents for SSL patterns
    if echo "$(basename "$file")" | grep -qE 'Ssl|ssl|Pem|Jks|KeyStore|TrustStore|WebServer|Servlet|Reactive|Redis|Mongo|Mail|Cassandra|Couchbase|RSocket|Elasticsearch|Rabbit|Kafka' 2>/dev/null || \
       grep -qE 'getSsl|setSsl|SslBundle|ssl\.bundle|\.wks|\.jks|\.p12|keystore\.password|key\.password' "$file" 2>/dev/null; then
        modified=false
        for pwd in "secret" "password" "changeit" "changeme" "testpass" "storepass" "keypass"; do
            # Replace "password" format (Java strings)
            if grep -q "\"${pwd}\"" "$file" 2>/dev/null; then
                sed -i "s/\"${pwd}\"/\"${FIPS_PASSWORD}\"/g" "$file"
                modified=true
            fi
            # Replace :password" format (property strings like keystore.password:secret")
            if grep -q ":${pwd}\"" "$file" 2>/dev/null; then
                sed -i "s/:${pwd}\"/:${FIPS_PASSWORD}\"/g" "$file"
                modified=true
            fi
            # Replace =password" format (property strings like keystore.password=secret")
            if grep -q "=${pwd}\"" "$file" 2>/dev/null; then
                sed -i "s/=${pwd}\"/=${FIPS_PASSWORD}\"/g" "$file"
                modified=true
            fi
        done
        [ "$modified" = true ] && echo "  Updated passwords in $(basename "$file")"
    fi
done

# ==============================================================================
# SECTION 2: Fix null password handling in PemSslStoreBundle
# ==============================================================================
echo ""
echo "=== SECTION 2: Null password fixes ==="

PEM_BUNDLE="${BOOT_MAIN}/ssl/pem/PemSslStoreBundle.java"
if [ -f "$PEM_BUNDLE" ] && ! grep -q "FIPS_DEFAULT_PASSWORD" "$PEM_BUNDLE"; then
    sed -i '/^public class PemSslStoreBundle/a\
\
	// Default password for wolfJSSE WKS keystore (requires non-null, min 14 chars for FIPS HMAC)\
	private static final char[] FIPS_DEFAULT_PASSWORD = "wolfSSLFIPSPwd2024".toCharArray();' "$PEM_BUNDLE"
    # Fix setKeyEntry: replace null fallback with FIPS default password
    sed -i 's/(keyPassword != null) ? keyPassword\.toCharArray() : null/(keyPassword != null) ? keyPassword.toCharArray() : FIPS_DEFAULT_PASSWORD/g' "$PEM_BUNDLE"
    # Fix store.load(null) -> store.load(null, FIPS_DEFAULT_PASSWORD) for WKS compatibility
    sed -i 's/store\.load(null);/store.load(null, FIPS_DEFAULT_PASSWORD);/' "$PEM_BUNDLE"
    # Fix getKeyStorePassword() to return FIPS password instead of null.
    # When PemSslStoreBundle stores a key with FIPS_DEFAULT_PASSWORD, Tomcat's
    # SslConnectorCustomizer calls getKeyStorePassword() to retrieve the key.
    # If it returns null, KeyStore.getKey(alias, null) throws UnrecoverableKeyException.
    sed -i '/getKeyStorePassword/,/return null;/{s/return null;/return "wolfSSLFIPSPwd2024";/}' "$PEM_BUNDLE"
    echo "  Fixed PemSslStoreBundle.java null password handling"
fi

# Fix store.load(null, null) patterns
find "${SPRING_BOOT_DIR}/spring-boot-project" -name "*.java" -type f 2>/dev/null | while IFS= read -r file; do
    if grep -q 'store\.load(null, null)' "$file" 2>/dev/null; then
        sed -i 's/store\.load(null, null)/store.load(null, "'"${FIPS_PASSWORD}"'".toCharArray())/g' "$file"
        echo "  Fixed store.load(null,null) in $(basename "$file")"
    fi
done

# ==============================================================================
# SECTION 3: Change keystore type from JKS/PKCS12 to WKS
# ==============================================================================
echo ""
echo "=== SECTION 3: Keystore type changes (JKS/PKCS12 -> WKS) ==="

find "${SPRING_BOOT_DIR}/spring-boot-project" -name "*.java" -type f 2>/dev/null | while IFS= read -r file; do
    modified=false
    if grep -q 'KeyStore\.getInstance("JKS")' "$file" 2>/dev/null; then
        sed -i 's/KeyStore\.getInstance("JKS")/KeyStore.getInstance("WKS")/g' "$file"
        modified=true
    fi
    if grep -q 'KeyStore\.getInstance("PKCS12")' "$file" 2>/dev/null; then
        sed -i 's/KeyStore\.getInstance("PKCS12")/KeyStore.getInstance("WKS")/g' "$file"
        modified=true
    fi
    if grep -q 'KeyStore\.getInstance("pkcs12")' "$file" 2>/dev/null; then
        sed -i 's/KeyStore\.getInstance("pkcs12")/KeyStore.getInstance("WKS")/g' "$file"
        modified=true
    fi
    if grep -q 'KeyStore\.getInstance("jks")' "$file" 2>/dev/null; then
        sed -i 's/KeyStore\.getInstance("jks")/KeyStore.getInstance("WKS")/g' "$file"
        modified=true
    fi
    [ "$modified" = true ] && echo "  Changed keystore type in $(basename "$file")"
done

# Fix JksSslStoreBundle to default to WKS type
JKS_BUNDLE="${BOOT_MAIN}/ssl/jks/JksSslStoreBundle.java"
if [ -f "$JKS_BUNDLE" ]; then
    # Replace KeyStore.getDefaultType() with "WKS" for FIPS compliance
    if grep -q 'KeyStore\.getDefaultType()' "$JKS_BUNDLE"; then
        sed -i 's/KeyStore\.getDefaultType()/"WKS"/g' "$JKS_BUNDLE"
        echo "  Changed KeyStore.getDefaultType() to WKS in JksSslStoreBundle.java"
    fi
    # Also change any type == null checks that default to JKS
    if grep -q '"JKS"' "$JKS_BUNDLE"; then
        sed -i 's/"JKS"/"WKS"/g' "$JKS_BUNDLE"
        echo "  Changed JKS string literals to WKS in JksSslStoreBundle.java"
    fi
fi

# Fix JksSslStoreDetails default type
JKS_DETAILS="${BOOT_MAIN}/ssl/jks/JksSslStoreDetails.java"
if [ -f "$JKS_DETAILS" ]; then
    if grep -q 'KeyStore\.getDefaultType()' "$JKS_DETAILS"; then
        sed -i 's/KeyStore\.getDefaultType()/"WKS"/g' "$JKS_DETAILS"
        echo "  Changed KeyStore.getDefaultType() to WKS in JksSslStoreDetails.java"
    fi
fi

# ==============================================================================
# SECTION 3.5: Replace keystore TYPE string values in test files
# ==============================================================================
echo ""
echo "=== SECTION 3.5: Keystore type string replacements ==="

# Replace setKeyStoreType("JKS") and similar patterns in test files
find "${SPRING_BOOT_DIR}/spring-boot-project" -name "*.java" -type f 2>/dev/null | while IFS= read -r file; do
    modified=false
    # setKeyStoreType("JKS") -> setKeyStoreType("WKS")
    if grep -q 'setKeyStoreType("JKS")' "$file" 2>/dev/null; then
        sed -i 's/setKeyStoreType("JKS")/setKeyStoreType("WKS")/g' "$file"
        modified=true
    fi
    if grep -q 'setKeyStoreType("PKCS12")' "$file" 2>/dev/null; then
        sed -i 's/setKeyStoreType("PKCS12")/setKeyStoreType("WKS")/g' "$file"
        modified=true
    fi
    if grep -q 'setTrustStoreType("JKS")' "$file" 2>/dev/null; then
        sed -i 's/setTrustStoreType("JKS")/setTrustStoreType("WKS")/g' "$file"
        modified=true
    fi
    if grep -q 'setTrustStoreType("PKCS12")' "$file" 2>/dev/null; then
        sed -i 's/setTrustStoreType("PKCS12")/setTrustStoreType("WKS")/g' "$file"
        modified=true
    fi
    # Also fix .type("JKS") and .type("PKCS12") builder patterns
    if grep -q '\.type("JKS")' "$file" 2>/dev/null; then
        sed -i 's/\.type("JKS")/.type("WKS")/g' "$file"
        modified=true
    fi
    if grep -q '\.type("PKCS12")' "$file" 2>/dev/null; then
        sed -i 's/\.type("PKCS12")/.type("WKS")/g' "$file"
        modified=true
    fi
    # Also fix setType("JKS/PKCS12") setter patterns
    if grep -q 'setType("JKS")' "$file" 2>/dev/null; then
        sed -i 's/setType("JKS")/setType("WKS")/g' "$file"
        modified=true
    fi
    if grep -q 'setType("PKCS12")' "$file" 2>/dev/null; then
        sed -i 's/setType("PKCS12")/setType("WKS")/g' "$file"
        modified=true
    fi
    # Also fix Spring property strings like key-store-type=jks or trust-store-type=pkcs12
    for old_type in jks pkcs12 PKCS12 JKS; do
        if grep -q "store-type=${old_type}\"" "$file" 2>/dev/null; then
            sed -i "s/store-type=${old_type}\"/store-type=WKS\"/g" "$file"
            modified=true
        fi
    done
    # Fix Spring config property .type=PKCS12 and .type=JKS patterns
    for old_type in PKCS12 JKS pkcs12 jks; do
        if grep -q "\.type=${old_type}\"" "$file" 2>/dev/null; then
            sed -i "s/\.type=${old_type}\"/\.type=WKS\"/g" "$file"
            modified=true
        fi
    done
    [ "$modified" = true ] && echo "  Changed keystore type properties in $(basename "$file")"
done

# ==============================================================================
# SECTION 4: Replace .jks/.p12 file references with .wks
# ==============================================================================
echo ""
echo "=== SECTION 4: File extension changes (.jks/.p12 -> .wks) ==="

find "${SPRING_BOOT_DIR}/spring-boot-project" -name "*.java" -type f 2>/dev/null | while IFS= read -r file; do
    modified=false
    if grep -q '\.jks"' "$file" 2>/dev/null; then
        sed -i 's/\.jks"/.wks"/g' "$file"
        modified=true
    fi
    if grep -q '\.p12"' "$file" 2>/dev/null; then
        sed -i 's/\.p12"/.wks"/g' "$file"
        modified=true
    fi
    [ "$modified" = true ] && echo "  Changed file extensions in $(basename "$file")"
done

# ==============================================================================
# SECTION 4.5: Fix getStoreType method in test files
# ==============================================================================
echo ""
echo "=== SECTION 4.5: Fix getStoreType methods ==="

# After section 4 changes .p12 to .wks, the getStoreType method still returns "pkcs12"
# We need to change it to return "WKS" for .wks files
SERVLET_TESTS="${BOOT_TEST}/web/servlet/server/AbstractServletWebServerFactoryTests.java"
if [ -f "$SERVLET_TESTS" ]; then
    # Fix the getStoreType method that returns wrong type for .wks files
    if grep -q 'endsWith(".wks") ? "pkcs12"' "$SERVLET_TESTS" 2>/dev/null; then
        sed -i 's/endsWith(".wks") ? "pkcs12"/endsWith(".wks") ? "WKS"/g' "$SERVLET_TESTS"
        echo "  Fixed getStoreType in AbstractServletWebServerFactoryTests.java"
    fi
fi

# ==============================================================================
# SECTION 5: Disable incompatible test classes
# ==============================================================================
echo ""
echo "=== SECTION 5: Disabling incompatible test classes ==="

disable_test_class() {
    local file="$1"
    local reason="$2"
    [ ! -f "$file" ] && return 0

    local class_line=$(grep -n -E '^(public )?(abstract )?class ' "$file" | head -1 | cut -d: -f1)
    [ -z "$class_line" ] && return 0

    # Skip if already disabled
    local check_start=$((class_line - 3))
    [ $check_start -lt 1 ] && check_start=1
    sed -n "${check_start},${class_line}p" "$file" | grep -q "@Disabled" && return 0

    # Add import and annotation
    grep -q "import org.junit.jupiter.api.Disabled;" "$file" || \
        sed -i '/^package /a\import org.junit.jupiter.api.Disabled;' "$file"
    class_line=$(grep -n -E '^(public )?(abstract )?class ' "$file" | head -1 | cut -d: -f1)
    sed -i "${class_line}i\\@Disabled(\"${reason}\")" "$file"
    echo "  Disabled: $(basename "$file")"
}

disable_test_method() {
    local file="$1"
    local method="$2"
    local reason="$3"
    [ ! -f "$file" ] && return 0

    # Find method - handle both parameterized and regular tests
    local method_line=$(grep -n "void ${method}(" "$file" | head -1 | cut -d: -f1)
    [ -z "$method_line" ] && return 0

    # Check if already disabled
    local check_start=$((method_line - 5))
    [ $check_start -lt 1 ] && check_start=1
    sed -n "${check_start},${method_line}p" "$file" | grep -q "@Disabled" && return 0

    # Add import if needed
    grep -q "import org.junit.jupiter.api.Disabled;" "$file" || \
        sed -i '/^package /a\import org.junit.jupiter.api.Disabled;' "$file"

    # Find @Test annotation before method and add @Disabled after it
    method_line=$(grep -n "void ${method}(" "$file" | head -1 | cut -d: -f1)
    local search_start=$((method_line - 10))
    [ $search_start -lt 1 ] && search_start=1
    for i in $(seq $method_line -1 $search_start); do
        if sed -n "${i}p" "$file" | grep -qE '^\s*@(Test|ParameterizedTest)'; then
            sed -i "${i}a\\	@Disabled(\"${reason}\")" "$file"
            echo "  Disabled: $method"
            break
        fi
    done
}

# PemPrivateKeyParserTests: Most methods are parser/format tests and can run in FIPS.
# Patch/disable only the unsupported pieces:
# - DSA row in shouldParseTraditionalPkcs8
# - EC curve toString() assertions (provider formatting differs)
# - EdDSA parsing (not available in FIPS)
# - Encrypted PKCS#8 success path (PBES2 encrypted key parsing unsupported in FIPS)
PEM_PRIV_KEY_TESTS="${BOOT_TEST}/ssl/pem/PemPrivateKeyParserTests.java"
if [ -f "$PEM_PRIV_KEY_TESTS" ]; then
    # Remove the DSA success row; RSA row remains.
    sed -i '/"dsa\.key,.*DSA"/d' "$PEM_PRIV_KEY_TESTS"

    # wolfJCE parses rsa-pss PKCS#8 private key but reports algorithm "RSA"
    # (provider naming difference vs Spring's expected "RSASSA-PSS").
    sed -i '/rsa-pss\.key.*RSASSA-PSS/s/RSASSA-PSS/RSA/' "$PEM_PRIV_KEY_TESTS"

    # Relax provider-specific ECParameterSpec.toString() formatting assertions
    sed -i 's/assertThat(ecPrivateKey.getParams().toString()).contains(curveName).contains(oid);/assertThat(ecPrivateKey.getParams()).isNotNull();/' "$PEM_PRIV_KEY_TESTS"

    echo "  Patched PemPrivateKeyParserTests.java (DSA row removed, EC assertion relaxed)"
fi
disable_test_method "${BOOT_TEST}/ssl/pem/PemPrivateKeyParserTests.java" \
    "shouldParseEdDsaPkcs8" "wolfJCE FIPS: EdDSA not available"
disable_test_method "${BOOT_TEST}/ssl/pem/PemPrivateKeyParserTests.java" \
    "shouldParseXdhPkcs8" "wolfJCE FIPS: XDH not available"
disable_test_method "${BOOT_TEST}/ssl/pem/PemPrivateKeyParserTests.java" \
    "shouldParseEncryptedPkcs8" "wolfJCE FIPS: PBES2 encrypted PKCS#8 parsing unsupported"

# PemContentTests: switch the DSA-specific parser sanity check to RSA so the
# test still validates PKCS#8 private key loading in FIPS mode.
PEM_CONTENT_TESTS="${BOOT_TEST}/ssl/pem/PemContentTests.java"
if [ -f "$PEM_CONTENT_TESTS" ]; then
    sed -i '/void getPrivateKeyReturnsPrivateKey/,/^\t}/ s#/pkcs8/dsa\.key#/pkcs8/rsa.key#' "$PEM_CONTENT_TESTS"
    sed -i '/void getPrivateKeyReturnsPrivateKey/,/^\t}/ s/isEqualTo(\"DSA\")/isEqualTo(\"RSA\")/' "$PEM_CONTENT_TESTS"
    echo "  Patched PemContentTests.java (DSA fixture -> RSA for FIPS)"
fi

# CertificateMatcherTests: parameter source includes DSA/EdDSA algorithms that may
# be unavailable in FIPS. Patch the source to skip unsupported algorithms instead
# of disabling the whole class (RSA/EC cases still validate matching behavior).
CERT_MATCH_SRC="${AUTOCONFIG_TEST}/ssl/CertificateMatchingTestSource.java"
if [ -f "$CERT_MATCH_SRC" ]; then
    # Patch the single key generation line directly (more robust than matching the full loop).
    perl -0777 -i -pe '
        s~keyPairs\.put\(algorithm, algorithm\.generateKeyPair\(\)\);~
\t\t\ttry {
\t\t\t\tkeyPairs.put(algorithm, algorithm.generateKeyPair());
\t\t\t}
\t\t\tcatch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
\t\t\t\t// wolfJSSE FIPS test image: skip unsupported algorithms (e.g. DSA/EdDSA)
\t\t\t}~s
    ' "$CERT_MATCH_SRC"

    # Fallback for upstream formatting changes: remove unsupported algorithms from the list.
    if ! grep -q 'skip unsupported algorithms' "$CERT_MATCH_SRC"; then
        sed -i 's/Stream.of("RSA", "DSA", "ed25519", "ed448")/Stream.of("RSA")/' "$CERT_MATCH_SRC"
        echo "  Patched CertificateMatchingTestSource.java (fallback: removed unsupported algorithms)"
    else
        echo "  Patched CertificateMatchingTestSource.java to skip unsupported algorithms"
    fi
fi

# PemSslStoreBundleTests: Most tests work with RSA PEM from classpath. Patch explicit
# PKCS12/short-password cases for WKS+FIPS, and disable only the remaining incompatible tests.
PEM_STORE_TESTS="${BOOT_TEST}/ssl/pem/PemSslStoreBundleTests.java"
if [ -f "$PEM_STORE_TESTS" ]; then
    # createWithDetailsWhenHasStoreType: explicit PKCS12 is not available in FIPS image.
    # Keep the test intent (explicit store type honored) but use WKS.
    sed -i '/createWithDetailsWhenHasStoreType/,/^\t}/ s/"PKCS12"/"WKS"/g' "$PEM_STORE_TESTS"

    # createWithDetailsWhenHasKeyStoreDetailsAndTrustStoreDetailsAndKeyPassword:
    # Short passwords ("kss"/"tss") violate FIPS minimum. Use the standard FIPS test password.
    sed -i '/createWithDetailsWhenHasKeyStoreDetailsAndTrustStoreDetailsAndKeyPassword/,/^\t}/ s/withPassword(\"kss\")/withPassword(\"'"${FIPS_PASSWORD}"'\")/g' "$PEM_STORE_TESTS"
    sed -i '/createWithDetailsWhenHasKeyStoreDetailsAndTrustStoreDetailsAndKeyPassword/,/^\t}/ s/withPassword(\"tss\")/withPassword(\"'"${FIPS_PASSWORD}"'\")/g' "$PEM_STORE_TESTS"
    # Update assertion passwords too (WKS key retrieval requires the actual entry password).
    sed -i '/createWithDetailsWhenHasKeyStoreDetailsAndTrustStoreDetailsAndKeyPassword/,/^\t}/ s/"kss"\\.toCharArray()/"'"${FIPS_PASSWORD}"'".toCharArray()/g' "$PEM_STORE_TESTS"
    sed -i '/createWithDetailsWhenHasKeyStoreDetailsAndTrustStoreDetailsAndKeyPassword/,/^\t}/ s/"tss"\\.toCharArray()/"'"${FIPS_PASSWORD}"'".toCharArray()/g' "$PEM_STORE_TESTS"

    # Fallback if sed did not match due to source formatting changes.
    perl -0777 -i -pe '
        s|(void createWithDetailsWhenHasKeyStoreDetailsAndTrustStoreDetailsAndKeyPassword\(\) \{.*?assertThat\(bundle\.getKeyStore\(\)\)\.satisfies\(storeContainingCertAndKey\("ksa", )"kss"\.toCharArray\(\)(\)\);)|$1"'"${FIPS_PASSWORD}"'".toCharArray()$2|s;
        s|(void createWithDetailsWhenHasKeyStoreDetailsAndTrustStoreDetailsAndKeyPassword\(\) \{.*?assertThat\(bundle\.getTrustStore\(\)\)\.satisfies\(storeContainingCertAndKey\("tsa", )"tss"\.toCharArray\(\)(\)\);)|$1"'"${FIPS_PASSWORD}"'".toCharArray()$2|s;
    ' "$PEM_STORE_TESTS"

    # Null/empty store cases: WKS/FIPS returns a non-null keystore password because
    # WKS always uses password-based protection. Preserve test intent (no stores).
    sed -i '/createWithDetailsWhenNullStores/,/^\t}/ s/assertThat(bundle.getKeyStorePassword()).isNull();/assertThat(bundle.getKeyStorePassword()).isNotNull();/' "$PEM_STORE_TESTS"
    sed -i '/createWithDetailsWhenStoresHaveNoValues/,/^\t}/ s/assertThat(bundle.getKeyStorePassword()).isNull();/assertThat(bundle.getKeyStorePassword()).isNotNull();/' "$PEM_STORE_TESTS"

    # createWithDetailsWhenHasKeyStoreDetailsAndTrustStoreDetailsWithoutKey:
    # WKS may assign non-JKS alias names and include multiple cert-only aliases.
    # Preserve test intent by asserting the trust store contains only cert entries
    # (no private keys) and at least one certificate, without alias-specific checks.
    perl -0777 -i -pe '
        s|assertThat\(bundle\.getTrustStore\(\)\)\.satisfies\(storeContainingCert\("ssl"\)\);|
\t\tassertThat(bundle.getTrustStore()).satisfies(ThrowingConsumer.of((keyStore) -> {
\t\t\tassertThat(keyStore).isNotNull();
\t\t\tassertThat(keyStore.getType()).isEqualTo(KeyStore.getDefaultType());
\t\t\tassertThat(keyStore.size()).isGreaterThanOrEqualTo(1);
\t\t\tboolean sawCert = false;
\t\t\tjava.util.Enumeration<String> aliases = keyStore.aliases();
\t\t\twhile (aliases.hasMoreElements()) {
\t\t\t\tString alias = aliases.nextElement();
\t\t\t\tif (keyStore.getCertificate(alias) != null) {
\t\t\t\t\tsawCert = true;
\t\t\t\t}
\t\t\t\tassertThat(keyStore.getKey(alias, EMPTY_KEY_PASSWORD)).isNull();
\t\t\t}
\t\t\tassertThat(sawCert).isTrue();
\t\t}));|s
    ' "$PEM_STORE_TESTS"
fi
disable_test_method "${BOOT_TEST}/ssl/pem/PemSslStoreBundleTests.java" \
    "createWithDetailsWhenHasKeyStoreDetailsCertAndEncryptedKey" "wolfJCE FIPS: PBES2 encrypted key"

# JKS tests use PBEWithMD5AndTripleDES (not FIPS-approved)
disable_test_class "${BOOT_TEST}/ssl/jks/JksSslStoreBundleTests.java" \
    "FIPS: JKS keystore format uses non-approved algorithms"

# ==============================================================================
# SECTION 6: Disable incompatible test methods and classes
# ==============================================================================
echo ""
echo "=== SECTION 6: Disabling incompatible test methods ==="

# SslInfoTests: Patch to use FIPS-compatible WKS keystores with self-signed certs.
# The Dockerfile creates keystores in /app/certs/sslinfo/ with exact validity dates
# (valid, expired, not-yet-valid, soon-to-expire) using keytool start dates + WksUtil.
# We patch: classpath references -> absolute file paths, createKeyStore -> copy WKS,
# validCertificatesShouldProvideSslInfo assertions (1 chain not 4), cert count in multipleBundles.
SSLINFO_FILE="${BOOT_TEST}/info/SslInfoTests.java"
if [ -f "$SSLINFO_FILE" ]; then
    # Simple string replacements (classpath -> absolute paths, cert count)
    sed -i \
        -e 's|"classpath:test.wks"|"/app/certs/sslinfo/valid.wks"|g' \
        -e 's|"classpath:test-expired.wks"|"/app/certs/sslinfo/expired.wks"|g' \
        -e 's|"classpath:test-not-yet-valid.wks"|"/app/certs/sslinfo/not-yet-valid.wks"|g' \
        -e 's|assertThat(certs).hasSize(5)|assertThat(certs).hasSize(4)|g' \
        "$SSLINFO_FILE"

    # Multiline replacements using perl (already installed in builder stage):
    # 1. Rewrite validCertificatesShouldProvideSslInfo method body
    # 2. Replace createKeyStore to copy pre-built WKS instead of running keytool
    # 3. Remove createProcessBuilder method (no longer needed)
    perl -0777 -i -pe '
        # Rewrite validCertificatesShouldProvideSslInfo: our valid.wks has 1 key entry
        # (alias "spring-boot") instead of the original JKS 2 key + 2 trusted cert entries
        s|\tvoid validCertificatesShouldProvideSslInfo\(\) \{.*?\n\t\}|
\tvoid validCertificatesShouldProvideSslInfo() {
\t\tSslInfo sslInfo = createSslInfo("/app/certs/sslinfo/valid.wks");
\t\tassertThat(sslInfo.getBundles()).hasSize(1);
\t\tBundleInfo bundle = sslInfo.getBundles().get(0);
\t\tassertThat(bundle.getName()).isEqualTo("test-0");
\t\tassertThat(bundle.getCertificateChains()).hasSize(1);
\t\tCertificateChainInfo chain = bundle.getCertificateChains().get(0);
\t\tassertThat(chain.getAlias()).isEqualTo("spring-boot");
\t\tassertThat(chain.getCertificates()).hasSize(1);
\t\tCertificateInfo cert = chain.getCertificates().get(0);
\t\tassertThat(cert.getSubject()).isEqualTo("CN=localhost,OU=Spring,O=VMware,L=Palo Alto,ST=California,C=US");
\t\tassertThat(cert.getIssuer()).isEqualTo(cert.getSubject());
\t\tassertThat(cert.getSerialNumber()).isNotEmpty();
\t\tassertThat(cert.getVersion()).isEqualTo("V3");
\t\tassertThat(cert.getSignatureAlgorithmName()).isEqualTo("SHA256withRSA");
\t\tassertThat(cert.getValidityStarts()).isInThePast();
\t\tassertThat(cert.getValidityEnds()).isInTheFuture();
\t\tassertThat(cert.getValidity()).isNotNull();
\t\tassertThat(cert.getValidity().getStatus()).isSameAs(Status.VALID);
\t\tassertThat(cert.getValidity().getMessage()).isNull();
\t}|s;

        # Replace createKeyStore: copy pre-built WKS instead of running keytool
        s|\tprivate Path createKeyStore\(Path directory\).*?\n\t\}|
\tprivate Path createKeyStore(Path directory) throws IOException, InterruptedException {
\t\tPath keyStore = directory.resolve("test.wks");
\t\tjava.nio.file.Files.copy(java.nio.file.Path.of("/app/certs/sslinfo/soon-to-expire.wks"), keyStore);
\t\treturn keyStore;
\t}|s;

        # Remove createProcessBuilder method (no longer needed)
        s|\n\tprivate ProcessBuilder createProcessBuilder\(Path keystore\).*?\n\t\}\n|\n|s;
    ' "$SSLINFO_FILE"
    echo "  Patched SslInfoTests.java for FIPS WKS keystores"
fi

# sslWithPemCertificates: Client uses Reactor Netty's InsecureTrustManagerFactory
# through compiled jars. Native wolfSSL verification rejects the cert before the
# Java TrustManager callback fires, causing SSLHandshakeException.
disable_test_method "${BOOT_TEST}/web/reactive/server/AbstractReactiveWebServerFactoryTests.java" \
    "sslWithPemCertificates" "Reactor Netty client InsecureTMF in compiled jars"

# TLSv1.1 disabled by JDK security policy
disable_test_method "${BOOT_TEST}/web/embedded/tomcat/SslConnectorCustomizerTests.java" \
    "sslEnabledMultipleProtocolsConfiguration" "TLSv1.1 disabled by JDK policy"

# wolfSSL doesn't support static RSA cipher suites (no forward secrecy)
disable_test_method "${BOOT_TEST}/web/embedded/undertow/UndertowServletWebServerFactoryTests.java" \
    "sslRestrictedProtocolsRSATLS12Success" "wolfSSL: Static RSA ciphers not supported"

# PEM getSsl() (2-arg version) doesn't set keyPassword. WKS requires the correct
# password to retrieve private keys. Add keyPassword to match FIPS_DEFAULT_PASSWORD.
SERVLET_TESTS="${BOOT_TEST}/web/servlet/server/AbstractServletWebServerFactoryTests.java"
if [ -f "$SERVLET_TESTS" ] && ! grep -A1 'ssl\.setTrustCertificate(cert);' "$SERVLET_TESTS" | grep -q 'setKeyPassword'; then
    sed -i '/ssl\.setTrustCertificate(cert);/{
a\		ssl.setKeyPassword("'"${FIPS_PASSWORD}"'");
}' "$SERVLET_TESTS"
    echo "  Added keyPassword to getSsl(cert,key) in AbstractServletWebServerFactoryTests.java"
fi

# JKS/SUN provider tests
disable_test_method "${AUTOCONFIG_TEST}/ssl/PropertiesSslBundleTests.java" \
    "jksPropertiesAreMappedToSslBundle" "FIPS: JKS requires SUN provider"
disable_test_method "${AUTOCONFIG_TEST}/ssl/PropertiesSslBundleTests.java" \
    "getWithResourceLoader" "FIPS: JKS requires SUN provider"
# pemPropertiesAreMappedToSslBundle: Replace ed25519 with rsa (not FIPS-approved)
PROPS_BUNDLE="${AUTOCONFIG_TEST}/ssl/PropertiesSslBundleTests.java"
if [ -f "$PROPS_BUNDLE" ]; then
    sed -i 's/ed25519-cert\.pem/rsa-cert.pem/g; s/ed25519-key\.pem/rsa-key.pem/g' "$PROPS_BUNDLE"
    echo "  Replaced ed25519 with rsa in PropertiesSslBundleTests.java"
fi
# WKS requires the correct password to retrieve keys (unlike JKS which allows empty).
PROPS_BUNDLE_TESTS="${AUTOCONFIG_TEST}/ssl/PropertiesSslBundleTests.java"
if [ -f "$PROPS_BUNDLE_TESTS" ]; then
    if grep -q 'EMPTY_KEY_PASSWORD = new char\[\] {}' "$PROPS_BUNDLE_TESTS"; then
        sed -i 's/EMPTY_KEY_PASSWORD = new char\[\] {}/EMPTY_KEY_PASSWORD = "'"${FIPS_PASSWORD}"'".toCharArray()/' "$PROPS_BUNDLE_TESTS"
        echo "  Fixed EMPTY_KEY_PASSWORD in PropertiesSslBundleTests.java"
    fi
fi

# Fix EMPTY_KEY_PASSWORD in PemSslStoreBundleTests too (same issue)
PEM_STORE_TESTS="${BOOT_TEST}/ssl/pem/PemSslStoreBundleTests.java"
if [ -f "$PEM_STORE_TESTS" ]; then
    if grep -q 'EMPTY_KEY_PASSWORD = new char\[\] {}' "$PEM_STORE_TESTS"; then
        sed -i 's/EMPTY_KEY_PASSWORD = new char\[\] {}/EMPTY_KEY_PASSWORD = "'"${FIPS_PASSWORD}"'".toCharArray()/' "$PEM_STORE_TESTS"
        echo "  Fixed EMPTY_KEY_PASSWORD in PemSslStoreBundleTests.java"
    fi
fi

# SslAutoConfigurationTests: Replace ed25519 with rsa (not FIPS-approved)
# and fix short passwords in property strings.
SSL_AUTO_TESTS="${AUTOCONFIG_TEST}/ssl/SslAutoConfigurationTests.java"
if [ -f "$SSL_AUTO_TESTS" ]; then
    if grep -q "ed25519" "$SSL_AUTO_TESTS"; then
        sed -i 's/ed25519-cert\.pem/rsa-cert.pem/g; s/ed25519-key\.pem/rsa-key.pem/g' "$SSL_AUTO_TESTS"
        echo "  Replaced ed25519 with rsa in SslAutoConfigurationTests.java"
    fi
    # Fix short passwords that don't meet FIPS HMAC minimum
    sed -i 's/password=secret1"/password='"${FIPS_PASSWORD}"'"/g; s/password=secret2"/password='"${FIPS_PASSWORD}"'"/g' "$SSL_AUTO_TESTS"
    # Fix assertion strings to match patched values
    sed -i 's/isEqualTo("PKCS12")/isEqualTo("WKS")/g' "$SSL_AUTO_TESTS"
    sed -i 's/isEqualTo("secret1")/isEqualTo("'"${FIPS_PASSWORD}"'")/g' "$SSL_AUTO_TESTS"
    sed -i 's/isEqualTo("secret2")/isEqualTo("'"${FIPS_PASSWORD}"'")/g' "$SSL_AUTO_TESTS"
    echo "  Fixed type and password assertions in SslAutoConfigurationTests.java"
fi
disable_test_method "${AUTOCONFIG_TEST}/ssl/SslPropertiesBundleRegistrarTests.java" \
    "shouldUseResourceLoader" "FIPS: JKS requires SUN provider"

# RSocket shouldUseSslWhenRocketServerSslIsConfigured: Test only provides keyPassword
# but WKS requires keyStorePassword to load. Inject the missing property.
RSOCKET_TEST="${AUTOCONFIG_TEST}/rsocket/RSocketServerAutoConfigurationTests.java"
if [ -f "$RSOCKET_TEST" ]; then
    if grep -q 'shouldUseSslWhenRocketServerSslIsConfigured' "$RSOCKET_TEST" && \
       ! grep -q 'keyStorePassword' "$RSOCKET_TEST"; then
        # Insert keyStorePassword property before port=0 in the withPropertyValues() call
        sed -i 's|"spring.rsocket.server.ssl.keyPassword=[^"]*", "spring.rsocket.server.port=0"|"spring.rsocket.server.ssl.keyPassword='"${FIPS_PASSWORD}"'", "spring.rsocket.server.ssl.keyStorePassword='"${FIPS_PASSWORD}"'", "spring.rsocket.server.port=0"|' "$RSOCKET_TEST"
        echo "  Patched RSocketServerAutoConfigurationTests: added keyStorePassword property"
    fi
fi

# RabbitMQ SSL tests: Most pass with WKS/password fixes and JKS/PKCS12->WKS patching.
# NonExisting keystore/truststore error-path tests: Spring AMQP's compiled
# RabbitConnectionFactoryBean calls KeyStore.getInstance("PKCS12") which fails in FIPS
# (PKCS12 not available). Error is "PKCS12 not found" instead of "foo does not exist".
# Cannot patch compiled Spring AMQP jars.
disable_test_method "${AUTOCONFIG_TEST}/amqp/RabbitAutoConfigurationTests.java" \
    "enableSslWithNonExistingKeystoreShouldFail" \
    "Spring AMQP compiled jar uses KeyStore.getInstance(PKCS12) - not available in FIPS"
disable_test_method "${AUTOCONFIG_TEST}/amqp/RabbitAutoConfigurationTests.java" \
    "enableSslWithNonExistingTrustStoreShouldFail" \
    "Spring AMQP compiled jar uses KeyStore.getInstance(PKCS12) - not available in FIPS"

# ==============================================================================
# SECTION 7: Patch HTTP Client Tests for broader exception handling
# ==============================================================================
echo ""
echo "=== SECTION 7: HTTP Client test exception handling ==="

# The tests expect SSLHandshakeException specifically, but wolfJSSE may throw
# different exception types. Patch to accept IOException (parent of SSL exceptions).
HTTP_CLIENT_TEST="${BOOT_TEST}/http/client/AbstractClientHttpRequestFactoryBuilderTests.java"
if [ -f "$HTTP_CLIENT_TEST" ]; then
    # Change SSLHandshakeException.class to IOException.class for the insecure request test
    if grep -q "assertThatExceptionOfType(SSLHandshakeException.class)" "$HTTP_CLIENT_TEST"; then
        sed -i 's/assertThatExceptionOfType(SSLHandshakeException.class)/assertThatExceptionOfType(IOException.class)/g' "$HTTP_CLIENT_TEST"
        echo "  Patched exception type in AbstractClientHttpRequestFactoryBuilderTests.java"
    fi
fi

WEB_CLIENT_TEST="${BOOT_TEST}/web/client/AbstractClientHttpRequestFactoriesTests.java"
if [ -f "$WEB_CLIENT_TEST" ]; then
    if grep -q "assertThatExceptionOfType(SSLHandshakeException.class)" "$WEB_CLIENT_TEST"; then
        sed -i 's/assertThatExceptionOfType(SSLHandshakeException.class)/assertThatExceptionOfType(IOException.class)/g' "$WEB_CLIENT_TEST"
        echo "  Patched exception type in AbstractClientHttpRequestFactoriesTests.java"
    fi
fi

# PemCertificateParserTests: test-cert.pem now contains the full chain (server cert
# + CA cert) so client-auth tests have the CA cert in the trust material. The
# parseCertificate() test expects hasSize(1) but the chain has 2 certs.
PEM_PARSER_TESTS="${BOOT_TEST}/ssl/pem/PemCertificateParserTests.java"
if [ -f "$PEM_PARSER_TESTS" ]; then
    sed -i '/parseCertificate/,/hasSize(1)/{s/hasSize(1)/hasSize(2)/}' "$PEM_PARSER_TESTS"
    echo "  Patched PemCertificateParserTests: test-cert.pem now has chain (2 certs)"
fi

# ==============================================================================
# SECTION 8: Patch TrustSelfSignedStrategy -> TrustAllStrategy
# ==============================================================================
echo ""
echo "=== SECTION 8: Trust strategy patches for CA-signed certs ==="

# We use CA-signed certs; TrustSelfSignedStrategy only works when Issuer==Subject
patch_trust_strategy() {
    local file="$1"
    [ ! -f "$file" ] && return 0
    if grep -q "TrustSelfSignedStrategy" "$file"; then
        grep -q "TrustAllStrategy" "$file" || \
            sed -i '/^package /a\import org.apache.hc.client5.http.ssl.TrustAllStrategy;' "$file"
        sed -i 's/new TrustSelfSignedStrategy()/TrustAllStrategy.INSTANCE/g' "$file"
        echo "  Patched: $(basename "$file")"
    fi
}

patch_trust_strategy "${BOOT_TEST}/web/servlet/server/AbstractServletWebServerFactoryTests.java"
patch_trust_strategy "${BOOT_TEST}/web/embedded/tomcat/TomcatServletWebServerFactoryTests.java"
patch_trust_strategy "${BOOT_TEST}/web/embedded/jetty/JettyServletWebServerFactoryTests.java"
patch_trust_strategy "${BOOT_TEST}/web/embedded/undertow/UndertowServletWebServerFactoryTests.java"
patch_trust_strategy "${BOOT_TEST}/web/reactive/server/AbstractReactiveWebServerFactoryTests.java"

# ==============================================================================
# SECTION 9: Disable Netty/Reactor SSL tests (InsecureTrustManagerFactory)
# ==============================================================================
echo ""
echo "=== SECTION 9: Disabling Netty/Reactor SSL tests ==="

# InsecureTrustManagerFactory fails through compiled Reactor Netty jars because
# native wolfSSL verification rejects the cert before the Java TrustManager
# callback fires. Cannot patch compiled jars to use explicit trust material.

# NettyRSocketServerFactory: PEM certificate tests fail (client InsecureTMF),
# but WKS keystore/bundle tests pass. Disable only the failing PEM cert methods.
for method in tcpTransportBasicSslCertificateFromClassPath \
              tcpTransportBasicSslCertificateFromFileSystem \
              websocketTransportBasicSslCertificateFromClassPath \
              websocketTransportBasicSslCertificateFromFileSystem; do
    disable_test_method "${BOOT_TEST}/rsocket/netty/NettyRSocketServerFactoryTests.java" \
        "$method" "Reactor Netty client InsecureTMF in compiled jars"
done

# ClientHttpRequestFactoriesReactor: both connectWithSslBundle tests fail
disable_test_class "${BOOT_TEST}/web/client/ClientHttpRequestFactoriesReactorTests.java" \
    "Reactor Netty client InsecureTMF path in compiled jars (cannot patch here)"

# ReactorClientHttpRequestFactoryBuilder: uses Reactor Netty InsecureTMF
disable_test_class "${BOOT_TEST}/http/client/ReactorClientHttpRequestFactoryBuilderTests.java" \
    "Reactor Netty client InsecureTMF path in compiled jars (cannot patch here)"

# NettyReactiveWebServerFactory: most tests PASS (basicSsl, clientAuth, etc.),
# only the SSL bundle reload test fails with IllegalStateException.
disable_test_method "${BOOT_TEST}/web/embedded/netty/NettyReactiveWebServerFactoryTests.java" \
    "whenSslBundleIsUpdatedThenSslIsReloaded" "Reactor Netty SSL bundle reload not supported with wolfJSSE"

echo ""
echo "=== Spring Boot FIPS Fixes Applied ==="
