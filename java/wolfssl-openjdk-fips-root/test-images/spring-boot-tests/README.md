# Spring Boot SSL Tests with wolfJSSE FIPS

This directory contains a Docker image for running Spring Boot SSL/TLS test suites using wolfJSSE and wolfJCE in FIPS 140-3 mode.

## Overview

This Docker image builds and runs Spring Boot's SSL-related test suites with wolfSSL's FIPS 140-3 validated cryptographic library (Certificate #4718), replacing all non-FIPS compliant Java cryptography providers with wolfJCE and wolfJSSE.

## Prerequisites

- The wolfssl-openjdk-fips-root base image built and available

## Building the Image

```bash
docker build -t spring-boot-wolfjsse-fips .
```

You can specify a different Spring Boot version using build args:

```bash
docker build --build-arg SPRING_BOOT_TAG=v3.4.1 -t spring-boot-wolfjsse-fips .
```

## Running Tests

To run the SSL test suite:

```bash
docker run --rm spring-boot-wolfjsse-fips
```

The container will automatically:
1. Apply FIPS-compatibility patches to Spring Boot source
2. Convert JKS/PKCS12 keystores to WKS format
3. Generate CA-signed test certificates
4. Run SSL-related tests from spring-boot, spring-boot-autoconfigure, and spring-boot-actuator

## FIPS Modifications

The image includes several modifications for FIPS compliance:

### Keystore Format
- All JKS and PKCS12 keystores are converted to WKS (wolfSSL KeyStore) format
- WKS is the only keystore format that works with wolfJSSE in FIPS mode

### Password Requirements
- All keystore passwords are changed to meet FIPS requirements (minimum 14 characters)
- Default password: `wolfSSLFIPSPwd2024`

### Certificate Requirements
- All test certificates are CA-signed (self-signed certificates fail native wolfSSL validation)
- Certificates include proper Subject Alternative Names (SAN) for localhost

### Test Exclusions
Some tests are disabled due to FIPS incompatibilities:
- Tests using non-FIPS algorithms (DSA, EdDSA, PBES2)
- Tests requiring JKS format with PBEWithMD5AndTripleDES
- Netty/Reactor SSL tests (InsecureTrustManagerFactory incompatible)

## Test Results

The container outputs a summary showing:
- Number of tests run per module
- Pass/fail/skip counts
- Detailed logs are saved in `/tmp/*.log` within the container
