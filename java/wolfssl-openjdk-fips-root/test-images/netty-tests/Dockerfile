# ==============================================================================
# Netty SSL Test Image with wolfJSSE - FIPS Mode
# ==============================================================================
# Runs Netty SSL tests with wolfJSSE in FIPS mode, OpenSSL disabled.
#
# Test Modules:
# - handler: All SSL handler tests (OpenSSL tests patched to skip)
# - handler-proxy: Proxy handler tests (including HTTPS proxy)
# - testsuite: Integration tests (SSL transport tests)
#
# Build: docker build -t netty-wolfjsse:latest .
# ==============================================================================

ARG FIPS_BASE_IMAGE=wolfssl-openjdk-fips-root:latest
ARG NETTY_REPO=https://github.com/netty/netty.git
# Pin to a specific Netty release tag for reproducible builds
ARG NETTY_TAG=netty-4.1.115.Final

# ------------------------------------------------------------------------------
# Stage 1: Build Netty with patches
# ------------------------------------------------------------------------------
FROM rootpublic/openjdk:19-jdk-bookworm-slim AS netty-builder

RUN apt-get update && apt-get install -y build-essential maven git perl && rm -rf /var/lib/apt/lists/*

ENV MAVEN_OPTS="-Xmx2048m"
ENV JAVA_HOME=/usr/local/openjdk-19
ENV PATH=$JAVA_HOME/bin:$PATH

WORKDIR /app/netty
ARG NETTY_REPO
ARG NETTY_TAG
# Clone specific release tag (shallow clone for speed)
RUN git clone --depth 1 --branch ${NETTY_TAG} ${NETTY_REPO} .

# Download BouncyCastle jars (needed by KeyUtil for PBES2 key encryption)
RUN ./mvnw dependency:get -Dartifact=org.bouncycastle:bcprov-jdk15on:1.69 && \
  ./mvnw dependency:get -Dartifact=org.bouncycastle:bcpkix-jdk15on:1.69 && \
  ./mvnw dependency:get -Dartifact=org.bouncycastle:bcutil-jdk15on:1.69

# Copy patching script and apply FIPS compatibility fixes
COPY apply_netty_fips_fixes.sh /tmp/apply_netty_fips_fixes.sh
RUN chmod +x /tmp/apply_netty_fips_fixes.sh && /tmp/apply_netty_fips_fixes.sh /app/netty

# Build handler, handler-proxy, and testsuite with all dependencies
RUN ./mvnw clean install -DskipTests -Dcheckstyle.skip=true -Djapicmp.skip=true -Danimal.sniffer.skip=true \
  -pl handler,handler-proxy,transport-sctp,transport-udt,testsuite -am -T 1C

# Resolve all test dependencies
RUN ./mvnw dependency:resolve -DincludeScope=test -pl handler,handler-proxy,transport-sctp,transport-udt,testsuite -am
RUN ./mvnw dependency:resolve-plugins -pl handler,handler-proxy,transport-sctp,transport-udt,testsuite
RUN ./mvnw dependency:get -Dartifact=org.apache.maven.surefire:surefire-junit-platform:3.5.3
RUN ./mvnw dependency:get -Dartifact=org.apache.maven.surefire:surefire-junit-platform:2.22.2
RUN ./mvnw dependency:get -Dartifact=org.apache.maven.surefire:surefire-api:2.22.2
RUN ./mvnw dependency:get -Dartifact=org.junit.platform:junit-platform-launcher:1.10.2
RUN ./mvnw test-compile -Dcheckstyle.skip=true -Danimal.sniffer.skip=true -pl handler,handler-proxy,transport-sctp,transport-udt,testsuite -am

# ------------------------------------------------------------------------------
# Stage 2: Runtime Image (FIPS base)
# ------------------------------------------------------------------------------
FROM ${FIPS_BASE_IMAGE}

RUN apt-get update && apt-get install -y maven git && rm -rf /var/lib/apt/lists/*

COPY --from=netty-builder /app/netty /app/netty
COPY --from=netty-builder /root/.m2 /root/.m2

# Copy all generated certs from builder (CA, FQDN-specific, alt-CA)
COPY --from=netty-builder /app/certs/ /app/certs/

WORKDIR /app/netty

# FIPS environment
# Ensure the base image performs its FIPS verification check on container start.
ENV FIPS_CHECK=true
ENV MAVEN_OPTS="-Xmx1g -XX:MaxMetaspaceSize=512m -Djava.security.egd=file:/dev/urandom -Dio.netty.handler.ssl.noOpenSsl=true"

ENV JAVA_TOOL_OPTIONS="-Xbootclasspath/a:/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar \
  -Djava.library.path=/usr/lib/jni:/usr/local/lib \
  -Dio.netty.handler.ssl.noOpenSsl=true \
  --add-modules=jdk.crypto.ec \
  --add-exports=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED \
  --add-opens=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED \
  --add-opens=java.base/java.security=ALL-UNNAMED \
  --add-opens=java.base/sun.security.provider=ALL-UNNAMED \
  --add-opens=java.base/sun.security.util=ALL-UNNAMED \
  --add-opens=java.base/sun.security.rsa=ALL-UNNAMED \
  --add-exports=java.base/sun.security.provider=ALL-UNNAMED \
  --add-exports=java.base/sun.security.rsa=ALL-UNNAMED \
  --add-exports=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED"

# Symlink native libs (must be before WKS conversion which loads wolfJCE)
RUN ln -sf /usr/lib/jni/libwolfssljni.so /usr/local/openjdk-19/lib/libwolfssljni.so && \
  ln -sf /usr/lib/jni/libwolfcryptjni.so /usr/local/openjdk-19/lib/libwolfcryptjni.so && \
  ln -sf /usr/local/lib/libwolfssl.so /usr/local/openjdk-19/lib/libwolfssl.so

# Stage 2 of PKCS12→WKS: compile WksImport with wolfJCE (FIPS JDK)
# and convert PEM exports (from builder stage) into .wks keystores.
# The builder exported each .p12 to a .p12.pem/ directory with PEM
# files and an aliases.txt manifest.
RUN javac --release 17 \
      -cp /usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar \
      WksImport.java -d /tmp/wksimport && \
    SSL_RES="handler/src/test/resources/io/netty/handler/ssl" && \
    for pemdir in ${SSL_RES}/*.p12.pem; do \
      [ -d "$pemdir" ] || continue; \
      base="${pemdir%.p12.pem}"; \
      wks="${base}.wks"; \
      p=$(cat "${pemdir}/password.txt"); \
      echo "  WKS: $(basename "$wks")"; \
      java -cp /tmp/wksimport WksImport "$pemdir" "$wks" "$p"; \
    done && \
    rm -rf /tmp/wksimport WksImport.java

# Test runner script (embedded)
RUN cat > /app/run-tests.sh <<'EOF' && chmod +x /app/run-tests.sh
#!/bin/bash
cd /app/netty

HANDLER_RESULT=0
PROXY_RESULT=0
TESTSUITE_RESULT=0

RUNS=()

run_mvn() {
  local name="$1"
  shift
  RUNS+=("$name")

  echo ""
  echo "============================================================"
  echo "=== Running: ${name}"
  echo "============================================================"

  # Run tests and filter out fork cleanup error messages
  # These appear when wolfJSSE native threads don't terminate cleanly
  # but don't indicate actual test failures
  set -o pipefail
  "$@" 2>&1 | tee "/tmp/${name}.raw.log" | grep -v -E \
    'ForkStarter|forked process|forked VM terminated|SurefireBooterForkException|ExecutionException|Java heap space|Crashed tests:|There are test failures|dump files|surefire-reports' \
    | tee "/tmp/${name}.log"
  local rc=${PIPESTATUS[0]}
  set +o pipefail
  return $rc
}

extract_summary_line() {
  local name="$1"
  grep -E 'Tests run: [0-9]+, Failures: [0-9]+, Errors: [0-9]+, Skipped: [0-9]+' "/tmp/${name}.raw.log" | tail -n 1 || true
}

add_totals_from_line() {
  local line="$1"
  if [[ "$line" =~ Tests\ run:\ ([0-9]+),\ Failures:\ ([0-9]+),\ Errors:\ ([0-9]+),\ Skipped:\ ([0-9]+) ]]; then
    TOTAL_RUN=$((TOTAL_RUN + BASH_REMATCH[1]))
    TOTAL_FAIL=$((TOTAL_FAIL + BASH_REMATCH[2]))
    TOTAL_ERR=$((TOTAL_ERR + BASH_REMATCH[3]))
    TOTAL_SKIP=$((TOTAL_SKIP + BASH_REMATCH[4]))
  fi
}

# Surefire fork settings to handle native library cleanup timing
SUREFIRE_OPTS='-DforkCount=1 -DreuseForks=false -Dsurefire.shutdown=exit'
SUREFIRE_OPTS="$SUREFIRE_OPTS -DforkedProcessExitTimeoutInSeconds=60"
SUREFIRE_OPTS="$SUREFIRE_OPTS -DforkedProcessTimeoutInSeconds=3600"
SUREFIRE_OPTS="$SUREFIRE_OPTS -DuseSystemClassLoader=false"
SUREFIRE_OPTS="$SUREFIRE_OPTS -DtrimStackTrace=false"
# Heap settings: 5g for isolated large test classes, 3g for smaller runs.
# JUnit5 Platform runs all classes in a single fork regardless of reuseForks,
# so large test classes must be isolated into their own mvn invocations.
# Maven parent uses 1g, so total peak = 1g + 5g = 6g (fits in 7.75GB).
ARGLINE_LARGE='-Xmx5g -Dio.netty.allocator.type=unpooled -XX:SoftRefLRUPolicyMSPerMB=0'
ARGLINE_COMMON='-Xmx3g -Dio.netty.allocator.type=unpooled -XX:SoftRefLRUPolicyMSPerMB=0'

# Redirect GC logging to file to avoid corrupting surefire's fork protocol
# (PrintGCDetails writes to stdout, which breaks surefire's communication)
GC_OPTS='-DargLine.printGC=-Xlog:gc*:file=/tmp/gc.log:time'

# Common mvn options
MVN_COMMON="-Dcheckstyle.skip=true -Danimal.sniffer.skip=true -DfailIfNoTests=false -Dmaven.test.failure.ignore=true"

# Handler module - split into 2 runs to avoid OOM
# JUnit5 Platform runs all test classes in a single JVM fork. JdkSslEngineTest
# (65 methods x 12 TLS params = 780 invocations) exhausts heap from BouncyCastle
# PEM parsing, so it must run in its own isolated 5g JVM.
# -Dtest=ClassName selects ONLY that class for an isolated JVM.
# Note: -Dtest=SslHandlerTest doesn't work (surefire 2.22.2 + JUnit5 plain @Test
# returns 0 tests), so SslHandlerTest runs in the "rest" group instead.

run_mvn "handler-engine" ./mvnw -o test -pl handler $MVN_COMMON \
  -Dsurefire.timeout=3600 $SUREFIRE_OPTS $GC_OPTS \
  "-DargLine.common=$ARGLINE_LARGE" \
  -Dtest=JdkSslEngineTest "$@" || HANDLER_RESULT=1

# For the remaining handler tests (including SslHandlerTest), add an exclude
# to pom.xml so JdkSslEngineTest doesn't run again (it already ran above).
# -Dtest=ClassName overrides includes, but there's no clean way to EXCLUDE
# specific classes via command line in surefire 2.22.2, so we patch the POM.
sed -i 's|<exclude>\*\*/\*TestUtil\*</exclude>|<exclude>**/*TestUtil*</exclude>\n            <exclude>**/JdkSslEngineTest.java</exclude>|' pom.xml

run_mvn "handler-rest" ./mvnw -o test -pl handler $MVN_COMMON \
  -Dsurefire.timeout=600 $SUREFIRE_OPTS $GC_OPTS \
  "-DargLine.common=$ARGLINE_COMMON" "$@" || HANDLER_RESULT=1

# Handler-Proxy tests (TLS via ProxyHandlerTest)
run_mvn "handler-proxy" ./mvnw -o test -pl handler-proxy $MVN_COMMON \
  -Dsurefire.timeout=120 $SUREFIRE_OPTS $GC_OPTS \
  "-DargLine.common=$ARGLINE_COMMON" "$@" || PROXY_RESULT=1

# Testsuite (must stay JDK/wolfJSSE-only; no tcnative/OpenSSL)
run_mvn "testsuite" ./mvnw -o test -pl testsuite $MVN_COMMON \
  -Dsurefire.timeout=300 $SUREFIRE_OPTS $GC_OPTS \
  "-DargLine.common=$ARGLINE_COMMON" "$@" || TESTSUITE_RESULT=1

echo ""
echo "============================================================"
echo "=== AGGREGATE TEST SUMMARY (all mvn runs) ==="
echo "============================================================"

TOTAL_RUN=0
TOTAL_FAIL=0
TOTAL_ERR=0
TOTAL_SKIP=0

for name in "${RUNS[@]}"; do
  line="$(extract_summary_line "$name")"
  if [ -z "$line" ]; then
    echo "- ${name}: (no surefire summary line found)"
  else
    echo "- ${name}: ${line}"
    add_totals_from_line "$line"
  fi
done

echo ""
echo "TOTAL: Tests run: ${TOTAL_RUN}, Failures: ${TOTAL_FAIL}, Errors: ${TOTAL_ERR}, Skipped: ${TOTAL_SKIP}"

echo ""
echo "========================================"
echo "=== ALL TESTS COMPLETE ==="
echo "========================================"

# Fail on Maven infrastructure errors (OOM, fork crashes, etc.)
if [ $HANDLER_RESULT -ne 0 ] || [ $PROXY_RESULT -ne 0 ] || [ $TESTSUITE_RESULT -ne 0 ]; then
  echo "FAIL: Maven infrastructure error (non-zero exit code)."
  exit 1
fi

# Fail if no tests ran (means surefire summary lines were missing - possible crash)
if [ $TOTAL_RUN -eq 0 ]; then
  echo "FAIL: No test results found (TOTAL_RUN=0). Check for build/fork crashes."
  exit 1
fi

# Fail on actual test failures/errors (maven.test.failure.ignore=true means
# Maven exits 0 even with test failures, so we must check parsed counts)
if [ $TOTAL_FAIL -ne 0 ] || [ $TOTAL_ERR -ne 0 ]; then
  echo "FAIL: ${TOTAL_FAIL} test failures, ${TOTAL_ERR} test errors."
  exit 1
fi

echo "PASS: All ${TOTAL_RUN} tests passed (${TOTAL_SKIP} skipped)."
EOF

# Default: run all tests
CMD ["/app/run-tests.sh"]
