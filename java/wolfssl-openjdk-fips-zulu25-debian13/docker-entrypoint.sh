#!/bin/bash
#
# Docker entrypoint script for wolfSSL FIPS 140-3 (Certificate #5548) compliant
# Java container (using wolfJCE and wolfJSSE with wolfCrypt FIPS underneath)
#
# This entrypoint script performs the following tasks:
#    1. Configures debug logging based on environment variables:
#        - `WOLFJCE_DEBUG`
#        - `WOLFJSSE_DEBUG`
#        - `WOLFJSSE_ENGINE_DEBUG`
#    2. Sets library paths for JNI libraries.
#    3. Verifies integrity of FIPS libraries before loading them:
#        - Checksums of wolfSSL native libraries (.so files)
#        - Checksums of provider JNI native libraries (.so files)
#        - Checksums of provider JAR files (wolfJCE, wolfJSSE)
#    4. Conducts FIPS container sanity checks (FipsInitCheck.java)
#        - List out all currently installed Java Security providers
#        - Verify wolfJCE is installed as provider at priority 1
#        - Verify wolfJSSE is installed as provider at priority 2
#        - Verify Java /lib/security/cacerts file is WKS format
#        - Forces run of FIPS POST by calling wolfJCE via MessageDigest class
#        - Sanity check java.security providers, ensure no non-compliant
#          providers are present
#        - Verify all JCA algorithms/services use wolfSSL providers
set -e

# Function to handle signals for graceful shutdown
cleanup() {
    echo "Shutting down gracefully..."
    exit 0
}

trap cleanup SIGTERM SIGINT

# Configure debug logging based on environment variables
# Support both friendly environment variables and direct JAVA_OPTS
if [ "$WOLFJCE_DEBUG" = "true" ]; then
    echo "Enabling wolfJCE debug logging"
    JAVA_OPTS="$JAVA_OPTS -Dwolfjce.debug=true"
fi

if [ "$WOLFJSSE_DEBUG" = "true" ]; then
    echo "Enabling wolfJSSE debug logging"
    JAVA_OPTS="$JAVA_OPTS -Dwolfjsse.debug=true"
fi

if [ "$WOLFJSSE_ENGINE_DEBUG" = "true" ]; then
    echo "Enabling wolfJSSE SSLEngine debug logging"
    JAVA_OPTS="$JAVA_OPTS -Dwolfsslengine.debug=true"
fi

# Support direct JAVA_OPTS from user (appends to our base JAVA_OPTS)
if [ -n "$USER_JAVA_OPTS" ]; then
    echo "Adding user-provided JAVA_OPTS: $USER_JAVA_OPTS"
    JAVA_OPTS="$JAVA_OPTS $USER_JAVA_OPTS"
fi

# The provider JARs are loaded from the JVM module path set in the image's
# JAVA_TOOL_OPTIONS (see the Dockerfile), not from CLASSPATH. Warn if
# JAVA_TOOL_OPTIONS was replaced instead of appended to: without the module
# path settings no JVM in the container has the wolfSSL providers.
case "$JAVA_TOOL_OPTIONS" in
    *--add-modules=com.wolfssl.wolfcrypt,com.wolfssl,com.wolfssl.security.providers*) ;;
    *)
        echo "WARNING: JAVA_TOOL_OPTIONS does not contain this image's provider module"
        echo "         settings (--module-path / --add-modules). It was probably replaced"
        echo "         instead of appended to, so the wolfSSL FIPS providers will not load."
        echo "         Append options to the image default JAVA_TOOL_OPTIONS instead."
        ;;
esac

export LD_LIBRARY_PATH=/usr/lib/jni:/usr/local/lib:$LD_LIBRARY_PATH
export JAVA_LIBRARY_PATH=/usr/lib/jni:/usr/local/lib

# Add library path to Java options for all Java processes
JAVA_OPTS="$JAVA_OPTS -Djava.library.path=$JAVA_LIBRARY_PATH"

# Split JAVA_OPTS into words once, without glob expansion, for the java and
# jshell commands below. An unquoted $JAVA_OPTS would also expand wildcards
# such as "-cp /app/lib/*" against the file system.
read -r -a JAVA_OPTS_ARR <<< "$JAVA_OPTS"

# Run FIPS verification checks unless FIPS_CHECK is "false". Any other value,
# including an unset or mistyped will runs them.
if [ "${FIPS_CHECK,,}" != "false" ]; then
    # Verify library integrity before loading/using any libraries
    echo ""
    echo "================================================================================"
    echo "|                       Library Checksum Verification                          |"
    echo "================================================================================"
    echo ""
    if ! /usr/local/bin/integrity-check.sh; then
        echo ""
        echo "ERROR: FIPS library integrity verification failed! Container will terminate."
        exit 1
    fi

    # Run FIPS container verification
    echo ""
    echo "================================================================================"
    echo "|                        FIPS Container Verification                           |"
    echo "================================================================================"
    echo ""
    echo "JAVA_TOOL_OPTIONS: $JAVA_TOOL_OPTIONS"
    # No provider JARs on -cp: FipsInitCheck loads the providers from the
    # module path, the same way applications do. FipsInitCheck exits with
    # the requested code only after all checks pass, so launcher options in
    # JAVA_OPTS that exit before main() (such as -version) cannot pass.
    FIPS_CHECK_PASS_CODE=42
    rc=0
    java "${JAVA_OPTS_ARR[@]}" -cp "/opt/wolfssl-fips/bin" FipsInitCheck \
        --pass-exit-code=$FIPS_CHECK_PASS_CODE || rc=$?
    if [ "$rc" -ne "$FIPS_CHECK_PASS_CODE" ]; then
        echo ""
        echo "ERROR: FIPS build checks failed! Container will terminate."
        exit 1
    fi

    echo ""
    echo "================================================================================"
    echo "|                         All Container Tests Passed                           |"
    echo "================================================================================"
    echo ""
else
    echo ""
    echo "================================================================================"
    echo "|                        FIPS Verification Disabled                            |"
    echo "================================================================================"
    echo ""
    echo "WARNING: FIPS_CHECK=false - Skipping FIPS verification tests"
    echo "This mode is intended for development/testing only and should not be used in production"
    echo ""
fi

# Execute the provided command
echo "Executing command: $@"
echo "JAVA_OPTS: $JAVA_OPTS"

# Export JAVA_OPTS so it's available to Java processes
export JAVA_OPTS

# If the command starts with 'java' or uses full path to java,
# we need to add JAVA_OPTS
if [ "$(basename "$1")" = "java" ] || [[ "$1" == */java ]]; then
    echo "Detected java command, merging JAVA_OPTS"
    # Reconstruct the command with JAVA_OPTS inserted
    JAVA_CMD="$1"
    shift
    echo "Final java command: $JAVA_CMD $JAVA_OPTS $*"
    exec "$JAVA_CMD" "${JAVA_OPTS_ARR[@]}" "$@"
elif [ "$(basename "$1")" = "jshell" ]; then
    # jshell runs snippets in a separate JVM. Pass each JAVA_OPTS option to
    # that JVM (-R), where user code runs. jshell's own JVM keeps its
    # defaults, so debug logs show only snippet activity, not jshell
    # internals. Add -J options on the command line to debug jshell itself.
    echo "Detected jshell command, passing JAVA_OPTS to the snippet JVM with -R"
    JSHELL_CMD="$1"
    shift
    JSHELL_OPTS=()
    for opt in "${JAVA_OPTS_ARR[@]}"; do
        JSHELL_OPTS+=("-R$opt")
    done
    echo "Final jshell command: $JSHELL_CMD ${JSHELL_OPTS[*]} $*"
    exec "$JSHELL_CMD" "${JSHELL_OPTS[@]}" "$@"
else
    echo "Non-java command, executing directly"
    exec "$@"
fi

