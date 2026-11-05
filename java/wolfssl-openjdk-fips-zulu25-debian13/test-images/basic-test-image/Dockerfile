# Simple FIPS Test Application Docker Image
# Extends the wolfssl-openjdk-fips-zulu25-debian13 base image to provide basic testing
# of JCA cryptographic operations and TLS functionality

# Base image is configurable so the test image can be built against any tag
# or variant of the base image (build.sh passes this via -b/--base)
ARG BASE_IMAGE=wolfssl-openjdk-fips-zulu25-debian13:latest
FROM ${BASE_IMAGE}

LABEL maintainer="wolfSSL Inc. <support@wolfssl.com>"
LABEL description="FIPS-compliant wolfSSL Java test application demonstrating JCA and TLS usage"

# The base image runs as non-root user 10001. Switch to root for the build
# steps, then back to the base image user below.
USER root

# Create application directory
RUN mkdir -p /app/test

# Copy test application source files
COPY src/main/*.java /app/test/

# Compile the test application
WORKDIR /app/test
RUN javac -cp "/opt/wolfssl-fips/bin:/usr/share/java/*" \
    *.java

# Set the working directory back to /app
WORKDIR /app

# Application classes on CLASSPATH. The base image loads the wolfSSL providers
# from the module path (JAVA_TOOL_OPTIONS), so they are not listed here.
ENV CLASSPATH="/app/test"

# Run as the base image's non-root user
USER 10001:10001

# Default command runs the comprehensive FIPS test suite
# Users can override this to run individual test classes
CMD ["java", "FipsUserApplication"]

# Alternative commands for running specific test suites:
# docker run wolfssl-fips-zulu25-basic-test-image:latest java CryptoTestSuite
# docker run wolfssl-fips-zulu25-basic-test-image:latest java TlsTestSuite
