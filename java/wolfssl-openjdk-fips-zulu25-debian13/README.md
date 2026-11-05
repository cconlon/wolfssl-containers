# wolfSSL OpenJDK 25 FIPS Container (Azul Zulu, Debian 13)

This is an OpenJDK 25 Docker image based on the Docker Official Image
[azul-zulu:25.36-25.0.4.1-jdk-debian13](https://hub.docker.com/_/azul-zulu)
(Azul Zulu 25.0.4.1 on Debian 13 "trixie") that integrates wolfSSL's FIPS
140-3 validated cryptographic library (Certificate #5548), replacing all
non-FIPS compliant Java cryptography providers with wolfJCE and wolfJSSE. Only
Java-based cryptography is in scope for FIPS compliance in this container.

This image mirrors the wolfSSL OpenJDK 19 FIPS image
(`../wolfssl-openjdk-fips-root`), but adjusted to JDK 25 and Debian 13.
Differences that JDK 25 requires are described in
[Changes for JDK 25](#changes-for-jdk-25-compared-to-the-openjdk-19-image).
Behavior that differs from a stock JDK 25 is described in
[Known Gaps Compared to a Stock JDK 25](#known-gaps-compared-to-a-stock-jdk-25).

An active wolfCrypt FIPS license is needed to use this container. The associated
.7z archive password will also be provided when the appropriate FIPS license
is acquired from wolfSSL Inc. Please contact fips@wolfssl.com for more
information.

## Features

- **FIPS 140-3 Validated Cryptography**: Uses wolfSSL's FIPS validated wolfCrypt
cryptographic module, [FIPS Certificate #5548](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5548).
- **Multi-stage Build**: Optimized for minimal final image size.
- **Automatic Container Tests**: FIPS Power-On Self Test and container
verification tests executed on container startup.
- **Debug Support**: Configurable debug logging for JCE/JSSE providers.
- **Security Hardened**: Non-FIPS providers disabled or filtered, leaving
wolfJCE and wolfJSSE (wolfCrypt FIPS 140-3) as the only implementations of
cryptographic services. Some available algorithms are restricted or not claimed
by the Security Policy, see [FIPS Compliance](#fips-compliance).

## Components

- **Base Image**: `azul-zulu:25.36-25.0.4.1-jdk-debian13` (Azul Zulu OpenJDK
  25.0.4.1, Debian 13). The base image is published for amd64 and arm64,
  this FIPS image has been built and tested on amd64.
- **Native wolfSSL/wolfCrypt**: Configured for FIPS 140-3 with JNI support
- **wolfCrypt JNI/JCE**: Java Cryptography Extension (JCE) provider
- **wolfSSL JNI/JSSE**: Java Secure Socket Extension (JSSE) provider
- **Filtered Sun Providers**: Custom wrappers for Sun providers that expose
non-cryptographic functionality (SunEC, SunRsaSign, SUN) while blocking
non-FIPS compliant cryptography services and algorithms. Maintained in the
[wolfcrypt-jni](https://github.com/wolfSSL/wolfcrypt-jni) repository under
`examples/filtered-providers` and built as part of the wolfcrypt-jni build
- **WKS cacerts**: System CA certificates converted to WolfSSL KeyStore format
and protected with read-only file permissions
- **Integrity-checked, read-only FIPS files and a non-root user**: the native
libraries, JNI libraries, provider JARs, `java.security`, `cacerts` and
`krb5.conf` are root-owned and checksum-verified at startup, and the
container runs as non-root user `10001` (`wolfssl`)

## Directory Layout

```
wolfssl-openjdk-fips-zulu25-debian13/
├── README.md                       # Image documentation and details
├── build.sh                        # Docker image build script
├── Dockerfile                      # Container definition
├── docker-entrypoint.sh            # Container entry point script
├── java.security                   # FIPS Java security configuration
├── java.security.original          # Stock Azul Zulu 25.0.4.1 java.security
├── krb5.conf                       # FIPS Kerberos configuration (AES only)
├── scripts/
│   ├── integrity-check.sh          # Startup integrity verification script
│   └── update-integrity-checksums.sh  # Generates the integrity manifest (root)
├── src/
│   └── main/
│       └── FipsInitCheck.java      # FIPS POST and container tests
└── test-images/
    └── basic-test-image/           # Example application / JCA + TLS tests
```

## Container Structure

When built, the container organizes files as follows:

```
/
├── etc/
│   └── krb5.conf                   # FIPS Kerberos configuration
├── usr/
│   ├── lib/
│   │   ├── jni/                    # JNI libraries
│   │   │   ├── libwolfcryptjni.so  # wolfJCE JNI library
│   │   │   └── libwolfssljni.so    # wolfJSSE JNI library
│   │   └── jvm/zulu25/             # JAVA_HOME (symlink to zulu25-ca-<arch>)
│   │       ├── conf/security/
│   │       │   └── java.security   # FIPS Java security configuration
│   │       └── lib/security/
│   │           └── cacerts         # CA certificates in WKS format
│   ├── local/lib/
│   │   └── libwolfssl.so*          # Native wolfSSL FIPS library
│   ├── local/bin/
│   │   ├── integrity-check.sh      # Startup integrity verification script
│   │   └── update-integrity-checksums.sh  # Regenerates the manifest (root)
│   └── share/java/                 # JAR files (Std. Debian location)
│       ├── wolfcrypt-jni.jar       # wolfJCE provider
│       ├── wolfssl-jsse.jar        # wolfJSSE provider
│       └── filtered-providers.jar  # Filtered Sun provider wrappers
├── opt/
│   └── wolfssl-fips/
│       ├── bin/                    # Compiled Java classes
│       │   └── FipsInitCheck.class
│       └── checksums/
│           └── libraries.sha256    # Integrity check manifest (libraries,
│                                   # JARs, java.security, cacerts, krb5.conf)
├── home/wolfssl/                   # Home and WORKDIR of user 10001 (wolfssl)
└── docker-entrypoint.sh            # Container entrypoint
```

## Changes for JDK 25 Compared to the OpenJDK 19 Image

The following changes were required to move from JDK 19 to JDK 25:

1. **Base image and JAVA_HOME**: `azul-zulu:25.36-25.0.4.1-jdk-debian13`,
   `JAVA_HOME=/usr/lib/jvm/zulu25`.
2. **SunEC moved into java.base (JDK 22)**: the filtered provider EC module
   flags now target `java.base/sun.security.ec` instead of the (now empty)
   `jdk.crypto.ec` module. See [JVM Module Requirements](#jvm-module-requirements).
3. **Restricted JNI (JEP 472, JDK 24)**: `--enable-native-access` is set for
   the wolfJCE and wolfJSSE modules (and `ALL-UNNAMED` for application JNI
   code), so loading the JNI libraries does not print `WARNING: A restricted
   method in java.lang.System has been called`. Future JDK releases will block
   such calls unless native access is enabled.
4. **java.security rebased on Azul Zulu 25.0.4.1**: all FIPS settings from
   the OpenJDK 19 image are applied unchanged on top of the JDK 25 file. The
   JDK 25 default `jdk.tls.disabledAlgorithms` additions (`DTLSv1.0`, `ECDH`,
   `TLS_RSA_*`, and SHA-1 `usage HandshakeSignature` entries) are merged into
   the FIPS list. JDK 25 removed the `policy.provider`, `policy.url.*` and
   `package.access` properties (Security Manager removal, JEP 486).
5. **New JDK service types**: `KEM` (JDK 21) and `KDF` (JDK 25) are covered
   by the startup checks, so a `KEM`/`KDF` service from any provider other
   than wolfJCE or wolfJSSE fails them. On the commercial v5.2.3 build no
   `KEM` or `KDF` service exists.
6. **Security Manager**: permanently disabled in JDK 24+ (JEP 486).
   `-Djava.security.manager` makes the JVM exit at startup, so do not pass it
   in `JAVA_OPTS` / `USER_JAVA_OPTS`. The startup checks no longer report the
   Security Manager state.

Changed on purpose compared to the OpenJDK 19 image (not required by JDK 25):

7. **Providers on the module path instead of `CLASSPATH`**: the provider JARs
   are loaded from the JVM module path, set in `JAVA_TOOL_OPTIONS`. Every JVM
   in the container gets the providers with no application changes, including
   `java -jar`, applications with their own class path, and JDK tools that
   ignore `CLASSPATH` (`keytool`, `jar`, `jarsigner`, `jshell`). The filtered
   providers' reflection access to JDK internals is granted to their own module
   only, instead of to all class path code. See
   [Provider Discovery](#provider-discovery-module-path-and-serviceloader).
8. **Non-root user and wider integrity check**: the container runs as non-root
   user `10001` (`wolfssl`, home and working directory `/home/wolfssl`) instead
   of root. The integrity check now also covers the two JNI libraries,
   `java.security`, `cacerts` and `/etc/krb5.conf`, all of which are root-owned
   and read-only. The integrity check script runs as non-root. See
   [Derived Images](#derived-images).
9. **Stronger startup checks**: FipsInitCheck adds or tightens these checks:
   - **FIPS module state**: Checks that wolfJCE's wolfCrypt is a FIPS build
     (`Fips.enabled`) whose module version matches the image's
     `WOLFSSL_FIPS_VARIANT` (`Fips.fipsVersion`), checks the FIPS algorithm
     self tests (CASTs) passed, and that the module is not in an error state
     (`wolfCrypt_GetStatus_fips`, which is checked again after all checks).
   - **Provider origin**: checks that the providers were loaded from JARs in
     `/usr/share/java`, and the native libraries from `/usr/local/lib` and
     `/usr/lib/jni`.
   - **Every provider service**: every service of every provider is checked
     for a fixed list of service types. The filtered providers are only able to
     offer their listed services, plus any granted in `java.security` (see
     [Granting Additional Sun Services](#granting-additional-sun-services)).
     Any other copy of a Sun service fails startup, even one an application can
     reach only by naming the provider (for example
     `MessageDigest.getInstance("SHA-256", "FilteredSun")`). A missing filtered
     provider service also fails startup.
   - **Unavailable algorithms**: the list depends on the FIPS variant, covers
     all JCA APIs, and accepts only the "not available" exception each API
     documents. A service granted in `java.security` is allowed from the
     granting filtered provider, and reported as granted. KeyStore JKS and
     PKCS12 are allowed from wolfJCE when `java.security` maps them to WKS
     (see [WolfSSLKeyStore (WKS) Format](#wolfsslkeystore-wks-format)), and
     reported as mapped.
   - **TLS cipher suites**: the default `SSLContext` must not enable or
     support a cipher suite that uses a cipher or MAC outside the wolfCrypt
     FIPS module (RC4, RC2, DES / 3DES, IDEA, MD5, ChaCha20-Poly1305,
     Camellia, ARIA, SEED, SM4 / SM3). The startup log lists the enabled
     suites, and the TLS protocols for information. This replaces the
     OpenJDK 19 image's check of three 3DES suites.
   - **Expected algorithms**: the check verifies where each one comes from.
     Its code and output no longer call them FIPS approved, since being
     available does not make an algorithm approved (see
     [FIPS Compliance](#fips-compliance)).
10. **Default command `jshell`**: left the same as the base image, instead of
    the OpenJDK 19 image's `java -version`. The entrypoint runs the startup
    checks first, then starts jshell with `JAVA_OPTS` (including the debug
    settings) passed to the JVM that runs the snippets. Use `docker run -it`
    for an interactive session.
11. **SASL NTLM disabled**: `jdk.sasl.disabledMechanisms=NTLM` in
    `java.security`. NTLM needs DES, which is not available in this image, so
    creating an NTLM client or server failed with an `AssertionError`. It is
    now reported as not available, like any unsupported mechanism. CRAM-MD5
    and DIGEST-MD5 stay enabled: they need MD5, so they fail with a
    `SaslException` unless MD5 is granted (see
    [Granting Additional Sun Services](#granting-additional-sun-services)).
    DIGEST-MD5's encryption (`auth-conf`) is never available, since its
    ciphers (3DES, RC4, DES) are not in the image.

## Custom Filtered Security Providers

wolfJCE and wolfJSSE consume several non-cryptographic services from a few
of the default Sun providers. This dependency exists so wolfJCE and wolfJSSE
do not need to re-implement stable working functionality from base providers.
In order to protect Java applications from accidentally using non-FIPS compliant
cryptographic services from these Sun providers, this container installs custom
filtered provider wrappers that only expose non-cryptographic services from
these providers. The primary providers are then removed from java.security and
unregistered. The filtered providers use reflection to look up original
providers, get appropriate service and alias information, then use that to
create the delegating services.

The filtered provider sources are maintained in the
[wolfcrypt-jni](https://github.com/wolfSSL/wolfcrypt-jni) repository under
`examples/filtered-providers/`. The wolfcrypt-jni `build-jce-release` ant
target compiles them into `lib/filtered-providers/filtered-providers.jar`,
which this image's build copies into the runtime image at
`/usr/share/java/filtered-providers.jar`.

Cryptography added to the JDK in JDK 20-25 is blocked by two mechanisms:
SunJCE (ML-KEM, DHKEM, HKDF, PBEWithHmac) is removed from the provider list
entirely, and the filters are allow-lists, so new algorithms in SUN (ML-DSA,
HSS/LMS, SHAKE) and SunEC (EdDSA, XDH) are not copied without any change. The
following services are left exposed:

**SunEC** (FilteredSunEC.java):
- AlgorithmParameters (EC)

**SunRsaSign** (FilteredSunRsaSign.java):
- KeyFactory (RSASSA-PSS)

**SUN** (FilteredSun.java):
- CertStore (Collection)
- CertStore (com.sun.security.IndexedCollection)
- CertificateFactory (X.509)
- Configuration (JavaLoginConfig)

`Policy (JavaPolicy)` is still on the FilteredSun allow-list, but JDK 24+ no
longer registers it (JEP 486), so it is not exposed on this image.

The startup checks require these services from the filtered providers. A
missing service, or an extra one that `java.security` does not grant, stops
the container. Changing the list also means updating
`FILTERED_PROVIDER_SERVICES` in `FipsInitCheck.java`.

### Granting Additional Sun Services

> **WARNING:** Granting a service may invalidate FIPS 140-3 compliance. A
> granted service is Sun's implementation, outside the wolfCrypt FIPS 140-3
> boundary, and is not FIPS validated. Grant a service only when an approved
> exception covers that specific use (for example, from your customer or
> compliance authority), and use it only for that purpose. The startup checks
> allow and report grants, but cannot tell whether a grant is justified.

When an application needs a Sun service the filters do not expose, and it has
an approved exception for using it outside the FIPS boundary, grant the
service in `java.security` with the filtered provider's `additionalServices`
property: a comma-separated list of canonical `Type.Algorithm` names. For
example, Sun's MD5 through FilteredSun:

```
wolfssl.filtered.sun.additionalServices=MessageDigest.MD5
```

The wolfJCE properties which can be used for these grants are:
- `wolfssl.filtered.sun.additionalServices`,
- `wolfssl.filtered.sunec.additionalServices`
- `wolfssl.filtered.sunrsasign.additionalServices`

- **Application use**: `getInstance()` returns the granted service from the
  filtered provider (for example `MessageDigest.getInstance("MD5")` returns
  FilteredSun's MD5, and `java.util.UUID.nameUUIDFromBytes()` works).
- **Startup checks**: they read the same properties. The startup log lists
  each grant under "Filtered provider grants" with a warning, and marks
  granted services `[granted by ...]` in the service and unavailable algorithm
  checks. Granted services are allowed only from the filtered provider that
  grants them. The same algorithm from any other provider still fails. An entry
  that matches no Sun service is ignored, and the filtered provider prints a
  warning naming it.
- **Where to set it**: add the line to this directory's `java.security` before
  building the image, or change `java.security` in a derived image (see
  [Derived Images](#derived-images)). Both update the integrity checksums.
  `-Djava.security.properties` is ignored in this image
  (`security.overridePropertiesFile=false`).

### JVM Module Requirements

The providers are registered through JVM flags set in `JAVA_TOOL_OPTIONS` in
the Dockerfile. The JVM reads `JAVA_TOOL_OPTIONS` for every launcher (`java`,
`keytool`, `jar`, `jarsigner`, `jshell`, ...):

- `--module-path=/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar` - provider JARs
- `--add-modules=com.wolfssl.wolfcrypt,com.wolfssl,com.wolfssl.security.providers` - resolve the wolfJCE, wolfJSSE and filtered provider modules
- `--enable-native-access=com.wolfssl.wolfcrypt,com.wolfssl,ALL-UNNAMED` - JNI library loading without JEP 472 warnings (JDK 24+)
- `--add-exports=java.base/sun.security.ec=com.wolfssl.security.providers` - SunEC provider package access (JDK 22+ location)
- `--add-opens=java.base/sun.security.ec=com.wolfssl.security.providers` - SunEC provider classes reflection access
- `--add-opens=java.base/java.security=com.wolfssl.security.providers` - Provider.Service field access
- `--add-opens=java.base/sun.security.provider=com.wolfssl.security.providers` - Sun provider classes
- `--add-opens=java.base/sun.security.util=com.wolfssl.security.providers` - Sun security utility classes
- `--add-opens=java.base/sun.security.rsa=com.wolfssl.security.providers` - SunRsaSign provider classes
- `-Djava.library.path=/usr/lib/jni:/usr/local/lib` - JNI library path configuration

The module names are `com.wolfssl.wolfcrypt` (wolfcrypt-jni.jar),
`com.wolfssl` (wolfssl-jsse.jar) and `com.wolfssl.security.providers`
(filtered-providers.jar). The image build verifies them, and sets
`Automatic-Module-Name: com.wolfssl.security.providers` when a wolfcrypt-jni
version without the filtered providers module descriptor is used.

The `--add-exports` / `--add-opens` flags target the filtered providers module
only. Application code on the class path (`ALL-UNNAMED`) does not get
reflection access to these JDK security internals.

The JDK 9-21 flags used by the OpenJDK 19 image (`--add-modules=jdk.crypto.ec`
and the `jdk.crypto.ec/sun.security.ec` export/open) must not be used on JDK
25: they print `WARNING: package sun.security.ec not in jdk.crypto.ec` and
FilteredSunEC cannot access SunEC. For the per-flag rationale see
`examples/filtered-providers/docs/add-opens.md` in the wolfcrypt-jni
repository.

Every JVM started in the container prints `Picked up JAVA_TOOL_OPTIONS: ...`
to stderr. This is normal JVM behavior.

## Build Process

### Prerequisites

- Docker installed and running
- wolfSSL commercial FIPS package password (required for default build)
    + Commercial wolfCrypt packages are provided directly via wolfSSL
    + This package has been tested with Certificate #5548 / FIPS 140-3 (v5.2.3)
    + Password must be supplied at image build time to extract .7z
    + Not required when building with `--fips=ready` (see
      [FIPS Ready Builds](#fips-ready-builds))

### Build Options

The build script supports several options for customizing the build. If no
custom repo or branch are specified, and no local path is specified, the build
will default to cloning the master branch from wolfcrypt-jni and wolfssljni
repositories to pull in the latest JCE/JSSE provider code.

**Repository Configuration:**
- `--wolfcrypt-jni-repo URL` - Custom wolfcrypt-jni repository URL
- `--wolfcrypt-jni-branch BRANCH` - Custom wolfcrypt-jni branch or tag
- `--wolfssl-jni-repo URL` - Custom wolfssljni repository URL
- `--wolfssl-jni-branch BRANCH` - Custom wolfssljni branch or tag

**Local Development:**
- `--wolfcrypt-jni PATH` - Use local wolfcrypt-jni directory
- `--wolfssl-jni PATH` - Use local wolfssljni directory

**Build Configuration:**
- `--fips VARIANT` (or `--fips=VARIANT`) - wolfSSL FIPS variant to build,
  mirroring wolfSSL's `--enable-fips` configure values: `v5.2.3` (commercial
  FIPS bundle, default) or `ready` (public GPLv3 wolfSSL FIPS Ready bundle,
  no password required)
- `--no-cache` - Disable Docker build cache
- `--cache-from IMAGE` - Use cache from existing image
- `-v, --verbose` - Enable verbose build output and debug logging

### Build the Image

```bash
# Basic build
./build.sh -p your_wolfssl_password

# With custom name and tag
./build.sh -p your_wolfssl_password -n myapp -t v1.0

# Verbose build output and wolfSSL debug logging in the post-build test
./build.sh -p your_wolfssl_password -v

# Using custom repository and branch
./build.sh -p your_wolfssl_password --wolfcrypt-jni-repo https://github.com/myuser/wolfcrypt-jni.git --wolfcrypt-jni-branch feature-branch

# Using release tags of the JNI repositories
./build.sh -p your_wolfssl_password --wolfcrypt-jni-branch v1.12.0-stable --wolfssl-jni-branch v1.19.0-stable

# Using local development directories
./build.sh -p your_wolfssl_password --wolfcrypt-jni ../wolfcrypt-jni-dev --wolfssl-jni ../wolfssljni-dev

# Evaluation build using the GPLv3 FIPS Ready bundle (no password)
./build.sh --fips=ready
```

### FIPS Ready Builds

By default this container builds against the commercial wolfSSL FIPS bundle,
which is password-protected and distributed directly by wolfSSL to customers.
For users who want to evaluate the container without a commercial bundle, the
`--fips=ready` option builds against the publicly downloadable, GPLv3-licensed
[wolfSSL FIPS Ready](https://www.wolfssl.com/license/fips/) bundle instead:

```bash
./build.sh --fips=ready
```

FIPS Ready builds compile the wolfCrypt FIPS module code shipped in the FIPS
Ready bundle and run it in FIPS Ready mode (`./configure --enable-fips=ready`),
including the FIPS in-core integrity check and power-on self tests. However,
**FIPS Ready is NOT a FIPS validated module** and must not be used where
validated cryptography is required. For production/compliance use, build with
the commercial FIPS bundle (contact fips@wolfssl.com).

The 5.9.4 FIPS Ready bundle contains the newer wolfCrypt FIPS v7 module, so
the available algorithms differ noticeably from Certificate #5548 (v5.2.3):

- Additionally available from wolfJCE: ML-KEM (`KEM`), ML-DSA, SLH-DSA, LMS,
  XMSS, Ed25519/Ed448 signatures, SHAKE128/SHAKE256 digests, AES-XTS, AES-CFB,
  AES Key Wrap.
- Not available: Diffie-Hellman (no `DiffieHellman` KeyAgreement /
  KeyPairGenerator / KeyFactory, no DHE TLS cipher suites) and `SHA1withECDSA`
  (FIPS 186-5).
- TLS 1.3 offers the hybrid ML-KEM groups `SecP384r1MLKEM1024` and
  `SecP256r1MLKEM768`, and EdDSA / ML-DSA / SLH-DSA signature algorithms.

The container startup checks (`FipsInitCheck`) adjust their expectations based
on the `WOLFSSL_FIPS_VARIANT` environment variable baked into the image. They
fail if it does not match the native FIPS module version (`Fips.fipsVersion`:
5 for `v5.2.3`, 7 for `ready`), so changing it at run time stops the container.
Images record the bundle variant they were built from in the
`com.wolfssl.fips.variant` label (`v5.2.3` or `ready`):

```bash
docker inspect --format '{{index .Config.Labels "com.wolfssl.fips.variant"}}' wolfssl-openjdk-fips-zulu25-debian13:latest
```

### Run the Container

```bash
# Basic run (runs startup checks, then opens jshell)
docker run -it wolfssl-openjdk-fips-zulu25-debian13:latest

# Show Java version info instead of opening jshell
docker run --rm wolfssl-openjdk-fips-zulu25-debian13:latest java -version

# With debug logging (also applies to jshell)
docker run -it -e WOLFJCE_DEBUG=true \
           -e WOLFJSSE_DEBUG=true \
           wolfssl-openjdk-fips-zulu25-debian13:latest

# Skip FIPS validation on startup (not recommended for production)
docker run -it -e FIPS_CHECK=false wolfssl-openjdk-fips-zulu25-debian13:latest

# Run a Java application from a mounted directory
docker run -v /path/to/your/app:/app \
           -e CLASSPATH=/app \
           wolfssl-openjdk-fips-zulu25-debian13:latest \
           java MyApplication
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JAVA_OPTS` | JVM options added by the entrypoint to `java` commands, and to `jshell` commands as `-R` options (the JVM that runs snippets) | `-Xmx512m` |
| `USER_JAVA_OPTS` | Extra JVM options appended to `JAVA_OPTS` by the entrypoint | unset |
| `JAVA_TOOL_OPTIONS` | Provider module path, module access and native access flags. Append to it, do not replace it (see [Provider Discovery](#provider-discovery-module-path-and-serviceloader)) | See Dockerfile |
| `CLASSPATH` | Application class path only; the provider JARs are not on it | unset |
| `WOLFSSL_FIPS_VARIANT` | wolfSSL FIPS bundle variant the image was built from (set at build time, used by startup FIPS checks). Do not change it: the startup checks fail if it does not match the native FIPS module version | `v5.2.3` or `ready` |
| `WOLFJCE_DEBUG` | Enable wolfJCE debug logging | `false` |
| `WOLFJSSE_DEBUG` | Enable wolfJSSE debug logging | `false` |
| `WOLFJSSE_ENGINE_DEBUG` | Enable wolfJSSE SSLEngine debug logging | `false` |
| `FIPS_CHECK` | Run FIPS validation on startup | `true` |

## Test and Example Application Images

A simple test application image is available under the
`./test-images/basic-test-image/` directory that runs basic JCA and SSL/TLS
tests on top of this base image, and demonstrates simple example usage.

```bash
# Build the base image first
./build.sh -p YOUR_WOLFSSL_PASSWORD

# Build the test application
cd test-images/basic-test-image
./build.sh

# Run complete test suite
docker run --rm wolfssl-fips-zulu25-basic-test-image:latest
```

For details see [`./test-images/basic-test-image/README.md`](./test-images/basic-test-image/README.md).
The netty, OkHttp and Spring Boot test images of the OpenJDK 19 image have
not been ported to this image.

## FIPS Compliance

### Cryptographic Operations

Cryptographic operations requested through the Java Cryptography Architecture
(by algorithm name, or by the name of a registered provider) are handled by
wolfSSL's FIPS validated wolfCrypt module via wolfJCE (cryptography) and
wolfJSSE (SSL/TLS). wolfJSSE does not call down through the JCE level, and
instead operates directly on native wolfSSL SSL/TLS APIs, which use native
wolfCrypt internally. See
[Scope of the provider restrictions](#scope-of-the-provider-restrictions) for
JDK code paths that do not go through the configured provider list.

See wolfJCE's [README\_JCE.md](https://github.com/wolfSSL/wolfcrypt-jni/blob/master/README_JCE.md)
file for supported cryptographic services and algorithms. Reference wolfCrypt's
[FIPS 140-3 Security Policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5548.pdf) (Certificate #5548, document version 1.5,
CAVP certificate A7470) for underlying module validation details.

An algorithm being available from wolfJCE or wolfJSSE does not make it FIPS
approved. The providers register what the native wolfCrypt FIPS build provides,
and some Security Policy restrictions are documented rather than enforced in
code. The Security Policy defines which algorithms are validated and how they
may be used, and applications are responsible for following it. The startup
checks verify where algorithms come from, not whether a use is approved.

### JDK 25 APIs Without a FIPS Implementation

These JDK APIs throw `NoSuchAlgorithmException` on this image (commercial
v5.2.3 build), because the algorithms are not provided by wolfJCE and the Sun
implementations are removed:

- `javax.crypto.KDF` (JDK 25, JEP 510), e.g. `KDF.getInstance("HKDF-SHA256")`.
  Native HKDF is used internally by TLS 1.3 in wolfSSL, but is not exposed as
  a Java `KDF` service.
- `javax.crypto.KEM` (`ML-KEM`, `DHKEM`). FIPS Ready builds provide ML-KEM.
- ML-DSA, HSS/LMS, EdDSA and XDH (X25519/X448) on the commercial build.
- PEM encoding of encrypted private keys (JEP 470 preview), which uses
  `jdk.epkcs8.defaultAlgorithm=PBEWithHmacSHA256AndAES_128`, a PBES2 cipher
  that wolfJCE does not implement.

## Operational Environment

For complete and proper FIPS validation compliance, the Operating Environment
that this container runs on must be added to the Security Policy for
wolfCrypt FIPS Certificate #5548. Its tested operational environments
include Debian 12.5 and Ubuntu 22.04 on Intel Xeon, but not Debian 13.
wolfSSL regularly adds OEs to existing FIPS certificates. Contact
fips@wolfssl.com for more information.

## Random Entropy

Native wolfSSL and wolfCrypt default to using /dev/urandom and /dev/random
for seeding the higher-level PRNG (Hash\_DRBG) implementation.

Native wolfCrypt uses the internal `wc_GenerateSeed()` function to call down
to the system entropy source. This native function behavior can be changed
at native wolfSSL build time, depending on Operating Environment validation.

For questions on native entropy sources, contact support@wolfssl.com or
fips@wolfssl.com.

## Security Configuration

The container modifies the base image and Java security configuration with
the following changes:

1. Set wolfJCE as the primary security provider
2. Set wolfJSSE as the secondary security provider
3. Install filtered Sun provider wrappers (FilteredSun, FilteredSunRsaSign, FilteredSunEC):
   - Expose only non-cryptographic services
   - Use delegating service pattern to maintain compatibility with wolfJCE/JSSE
   - Block/remove access to non-FIPS cryptographic operations
4. Disable original Sun crypto providers (SunJCE, SunJSSE, SunPKCS11, SunPCSC,
   etc.) by removing them from java.security.
5. Set JVM module access and native access flags for the providers
6. Convert system cacerts from PKCS12 to WKS format for FIPS compliance
7. Set default KeyStore type to WKS for FIPS compliance
8. Configure Kerberos (krb5) to use only FIPS-compliant encryption types

The complete set of property changes can be seen by diffing `java.security`
against `java.security.original` (the stock Azul Zulu 25.0.4.1 file).

### Kerberos Configuration

The container includes a FIPS-compliant Kerberos configuration file
(`/etc/krb5.conf`) that restricts Kerberos to use only AES-based encryption
types. This is necessary because the default Java Kerberos implementation
attempts to generate keys for all encryption types including DES, 3DES, and
RC4, which are not within the wolfCrypt FIPS boundary.

**Permitted Encryption Types:**
- `aes256-cts-hmac-sha1-96` (etype 18)
- `aes128-cts-hmac-sha1-96` (etype 17)

**Disabled Encryption Types:**
- DES-CBC-CRC (etype 1)
- DES-CBC-MD5 (etype 3)
- DES3-CBC-SHA1 (etype 16)
- RC4-HMAC (etype 23)
- All other non-AES encryption types

The configuration also sets `allow_weak_crypto = false` to prevent fallback
to weak encryption algorithms. Applications using Kerberos will automatically
inherit these restrictions.

**Note:** Applications that override the system krb5.conf with their own
configuration should ensure they only permit AES-based encryption types to
maintain FIPS compliance. The AES Kerberos encryption types use AES in CTS
mode (`AES/CTS/NoPadding`). The CTS step native wolfSSL runs outside the
FIPS module on top of the module's FIPS validated AES-CBC, and PBKDF2 is used
for password-based keys. Neither CTS nor PBKDF2 is in the Certificate #5548
approved algorithm table (see [FIPS Compliance](#fips-compliance)).

**Password length:** Kerberos derives AES keys from passwords with PBKDF2-HMAC,
using the password as the HMAC key. wolfCrypt FIPS requires HMAC keys of at
least 14 bytes, so deriving a key from a shorter password (for example
`new KerberosKey(principal, password, "aes256-cts-hmac-sha1-96")`, or a JAAS
`Krb5LoginModule` password login) fails with `FIPS Mode HMAC Minimum Key or
Salt Length error`. Use passwords of 14 or more characters, or keytabs. Keys
read from a keytab are not derived from a password and are not affected.

`policy.allowSystemProperty=false` is kept from the OpenJDK 19 image. On JDK
24+ its only effect is that a JAAS login configuration cannot be passed with
`-Djava.security.auth.login.config=...`; use `login.config.url.N` in
java.security instead.

### Provider Discovery, Module Path and ServiceLoader

The provider JARs are loaded from the JVM module path, set in the image's
`JAVA_TOOL_OPTIONS` (see [JVM Module Requirements](#jvm-module-requirements)),
not from the application class path. Every JVM in the container reads
`JAVA_TOOL_OPTIONS`, so the `java.security` provider list and
`ServiceLoader.load(Provider.class)` find the providers without any
application changes, for all launch forms:

```bash
docker run wolfssl-openjdk-fips-zulu25-debian13:latest java -cp /app/myapp.jar com.example.MyApplication
docker run wolfssl-openjdk-fips-zulu25-debian13:latest java -jar /app/myapp.jar
docker run -e CLASSPATH=/app/myapp.jar wolfssl-openjdk-fips-zulu25-debian13:latest java MyApp
```

JDK tools that ignore the `CLASSPATH` environment variable (`keytool`, `jar`,
`jarsigner`, `jshell`) also get the providers.

Adding the provider JARs to the class path as well (for example
`-cp "/app/myapp.jar:/usr/share/java/*"`) still works: the modules on the
module path take precedence.

All providers include `META-INF/services/java.security.Provider` service
registrations (`provides java.security.Provider` in the module descriptors):
- `com.wolfssl.provider.jce.WolfCryptProvider`
- `com.wolfssl.provider.jsse.WolfSSLProvider`
- `com.wolfssl.security.providers.FilteredSun`
- `com.wolfssl.security.providers.FilteredSunRsaSign`
- `com.wolfssl.security.providers.FilteredSunEC`

Two rules for applications and deployments:

- **Append to `JAVA_TOOL_OPTIONS`, do not replace it.** For example, use
  `-e JAVA_TOOL_OPTIONS="<image value> -Xmx2g"`, or pass JVM options through
  `JAVA_OPTS` / `USER_JAVA_OPTS` (see [Environment Variables](#environment-variables)).
  Tools that inject agents through `JAVA_TOOL_OPTIONS` (APM agents,
  Kubernetes operators) must append to the image value. If it is replaced,
  no JVM gets the wolfSSL providers. The entrypoint prints a warning, and the
  startup checks fail.
- **Applications with their own `--module-path`** must include the three
  provider JARs, because the last `--module-path` option wins. Otherwise the
  JVM does not start (`Module com.wolfssl.security.providers not found`):

  ```bash
  java --module-path=/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar:/app/mods ...
  ```

### WolfSSLKeyStore (WKS) Format

For FIPS 140-3 compliance, wolfJCE requires the use of WolfSSLKeyStore (WKS)
format for all KeyStore objects and files. The container automatically converts
the Java system cacerts file (PKCS12 in JDK 25) to WKS format during build.

**WKS Format Features:**
- Custom KeyStore implementation designed for FIPS 140-2/140-3 compatibility
- Uses AES-CBC-256 with HMAC-SHA512 in Encrypt-then-MAC mode for key protection
- PBKDF2-HMAC-SHA512 with 210,000 iterations (default) for key derivation
  (PBKDF2 is not in the Certificate #5548 approved algorithm table; see
  [FIPS Compliance](#fips-compliance))
- 16-byte random salt per key storage operation
- Stores PrivateKey, Certificate, and SecretKey objects securely

**FIPS Requirement:**
WKS format is required when using wolfJCE in FIPS mode. Standard Java KeyStore
formats (JKS, PKCS12) are not compatible with FIPS-validated cryptographic
operations and must be converted to WKS format prior to use with this
container.

**JKS / PKCS12 mapped to WKS:**
For application code that requests a `JKS` or `PKCS12` KeyStore and cannot be
changed, wolfJCE can register those types as WKS. Set either or both in
`java.security` (before building the image, or in a derived image, see
[Derived Images](#derived-images)):

```
wolfjce.mapJKStoWKS=true
wolfjce.mapPKCS12toWKS=true
```

`KeyStore.getInstance("JKS")` then returns wolfJCE's WKS KeyStore, so any
KeyStore file loaded through it must already be in WKS format. The startup
checks read the same properties: they allow that type from wolfJCE and mark it
`[mapped to WKS by ...]`, with no changes to `FipsInitCheck.java`.

For more details on WKS format, see the wolfJCE documentation:

[WolfSSLKeyStore Implementation Details and Usage](https://github.com/wolfSSL/wolfcrypt-jni/blob/master/README_JCE.md#wolfsslkeystore-wks-implementation-details-and-usage)

[wolfSSL KeyStore Design Notes](https://github.com/wolfSSL/wolfcrypt-jni/blob/master/docs/design/WolfSSLKeyStore.md)

**Using keytool in the container:**
`keytool` loads wolfJCE (WKS, crypto) and the filtered providers (X.509
CertificateFactory) from the module path like any other JVM, so no extra
options are needed:

```bash
keytool -genkeypair -alias server -keyalg EC -groupname secp256r1 -dname CN=server \
    -storetype WKS -keystore server.wks \
    -storepass changeitchangeit -keypass changeitchangeit

keytool -list -cacerts -storepass changeitchangeit
```

WKS passwords must be at least 14 characters (FIPS minimum HMAC key length).

**System-wide WKS Configuration:**
The container configures `keystore.type=WKS` in java.security, so
applications creating KeyStore instances without explicitly specifying a type
use WKS. The WKS cacerts password is `changeitchangeit` (wolfCrypt FIPS
requires HMAC keys of at least 14 bytes, so the default `changeit` is
doubled).

**Protection Against Overwrites:**
The WKS cacerts file is root-owned with read-only permissions (444), and its
checksum is verified at startup. The container runs as a non-root user, so
applications cannot modify it. In this base image, `cacerts` is a regular
file owned by the Azul `zulu25-ca-jre-headless` package (it is not managed by
`ca-certificates` / `ca-certificates-java`). To add CA certificates in a
derived image, see [WKS cacerts File Issues](#wks-cacerts-file-issues).

## Known Gaps Compared to a Stock JDK 25

wolfJSSE implements TLS with native wolfSSL, and wolfJCE implements
certificate path validation with native wolfSSL, so some JDK security
properties that SunJSSE / the SUN PKIX implementation honor have no effect
here. The same applies to the OpenJDK 19 image.

### TLS Restrictions: Where Each Is Enforced

| Restriction | Stock JDK 25 | This image |
|---|---|---|
| Protocol versions in `jdk.tls.disabledAlgorithms` (SSLv3, TLSv1, TLSv1.1) | SunJSSE | wolfJSSE (exact wolfSSL protocol names); native build also has no TLS 1.0/1.1 |
| `DTLSv1.0` in `jdk.tls.disabledAlgorithms` | SunJSSE | No effect (wolfSSL calls it `DTLSv1`). wolfJSSE always disables DTLS 1.0 and 1.2 itself; **DTLS 1.3 is available** (`SSLContext.getInstance("DTLSv1.3")`) |
| `DH keySize < 2048`, `EC keySize < 224` in `jdk.tls.disabledAlgorithms` | SunJSSE | wolfJSSE passes them to native wolfSSL (handshake and peer certificate keys). The client still offers the `secp224r1` group, although Certificate #5548 approves ECDH for P-256, P-384 and P-521 only |
| RSA minimum key size for TLS | SunJSSE (no `RSA keySize` token in the stock or FIPS property) | No `RSA keySize <` token is set, so the native wolfSSL default minimum of 1024 bits applies. Certificate #5548 approves RSA signatures with 2048-bit and larger keys only |
| `jdk.tls.ephemeralDHKeySize=2048` | SunJSSE | Not read by wolfJSSE; the DH minimum comes from `DH keySize < 2048` above |
| `TLS_RSA_*`, `ECDH` (static), 3DES, RC4, NULL, anon cipher suites | SunJSSE | Native wolfSSL FIPS build: these suites are not compiled in. The startup checks fail if the default SSLContext enables or supports a 3DES or RC4 suite (a cipher outside the module); the others are native compile-time choices |
| SHA-1 handshake signatures (`rsa_pkcs1_sha1`, `ecdsa_sha1` `usage HandshakeSignature`) | SunJSSE | Native wolfSSL: SHA-1 signature algorithms are not offered in the ClientHello |
| `jdk.certpath.disabledAlgorithms` for TLS peer chains (e.g. `SHA1 jdkCA & usage TLSServer`) | SunJSSE + PKIX | **Not enforced**: wolfJSSE verifies peer chains with the native wolfSSL certificate manager, and does not call a CertPathValidator. A SHA-1 signed server chain is accepted |
| `jdk.security.caDistrustPolicies` (SYMANTEC\_TLS, ENTRUST\_TLS, CAMERFIRMA\_TLS, CHUNGHWA\_TLS) | SunJSSE | **Not enforced** (see below) |
| `lib/security/blocked.certs` | SunJSSE + PKIX | **Not enforced** |
| `jdk.tls.keyLimits`, `jdk.tls.legacyAlgorithms` | SunJSSE | Not used by wolfJSSE |

`jdk.certpath.disabledAlgorithms` is honored by the wolfJCE
`CertPathValidator` (PKIX) for application-level certificate path validation.

### Distrusted Certificate Authorities

Stock JDK 25 distrusts TLS server certificates issued after per-CA cutoff
dates and anchored by the following roots, which are still present in the JDK
cacerts file and therefore in this image's WKS cacerts:

- SYMANTEC\_TLS (cutoff 2019-04-16): `geotrustglobalca`, `geotrustprimaryca`,
  `geotrustprimarycag2`, `geotrustprimarycag3`, `geotrustuniversalca`,
  `thawteprimaryrootca`, `thawteprimaryrootcag2`, `thawteprimaryrootcag3`,
  `verisignclass3g3ca`, `verisignclass3g4ca`, `verisignclass3g5ca`,
  `verisignuniversalrootca`
- ENTRUST\_TLS (cutoff 2024-11-11): `entrust2048ca`, `entrustevca`,
  `entrustrootcaec1`, `entrustrootcag2`, `entrustrootcag4`
- CAMERFIRMA\_TLS (cutoff 2025-04-15): `camerfirmachambersca`
- CHUNGHWA\_TLS (cutoff 2026-03-17): `chunghwaepkirootca`

wolfJSSE does not implement `jdk.security.caDistrustPolicies` yet, so these
roots are fully trusted for TLS in this image. The stock property value is kept
in java.security so that it takes effect once wolfJSSE supports it. Until
then, applications that must not trust these roots should use a custom WKS
trust store without them.

### Extended Master Secret (TLS 1.2)

The v5.2.3 Security Policy requires the TLS 1.2 Extended Master Secret (EMS,
RFC 7627) for the TLS 1.2 KDF in the approved mode of operation. wolfJSSE
offers and accepts EMS in every TLS 1.2 handshake, but it does not currently
refuse peers that do not support EMS: both a wolfJSSE client and a wolfJSSE
server complete TLS 1.2 handshakes with a non-EMS peer, using the legacy TLS
1.2 master secret. TLS 1.3 is not affected.

### Scope of the Provider Restrictions

The provider configuration controls which implementation the JDK returns for
`getInstance(algorithm)` and `getInstance(algorithm, "registeredName")` calls.
It does not control:

- **Signed JAR verification**: the JDK verifies signed JARs with a fixed list
  of its built-in providers (SUN, SunRsaSign, SunEC, SunJCE), independent of
  java.security.
- **Explicit Provider objects**: application code cannot construct the stock
  Sun providers directly, because `sun.security.provider`,
  `sun.security.rsa` and `sun.security.ec` are not exported to it. (The
  image's `--add-opens` / `--add-exports` flags target only the filtered
  providers module, unlike the OpenJDK 19 image, which opened these packages
  to all class path code.) An application that adds its own `--add-exports`
  / `--add-opens` flags, or bundles another provider such as Bouncy Castle
  and uses it explicitly, can still bypass the provider list. No JDK 24+
  mechanism prevents this, since the Security Manager is removed.
- **JDK-internal private providers**: for example Kerberos `rc4-hmac` key
  derivation uses an internal MD4 implementation directly. The Kerberos
  configuration in this image does not permit `rc4-hmac`.
- **Launch configuration**: the image's defaults decide what happens when
  nothing interferes. The protected files cannot be changed by the non-root
  container user, and changes made as root (`docker run --user root`, or a
  derived image) fail the startup integrity check unless the checksums are
  regenerated. The startup checks run once, in their own JVM, before the
  application starts. They detect a look-alike provider module or native
  library that comes in through the environment (`JAVA_TOOL_OPTIONS`,
  `JAVA_OPTS`, library paths). They do not see options that appear only on
  the application's own `java` command line, for example a different module
  named `com.wolfssl.wolfcrypt` on its own `--module-path`. Overriding the
  entrypoint or setting `FIPS_CHECK=false` skips the startup checks.

  Replacing or unsetting `JAVA_TOOL_OPTIONS`, or removing wolfJCE at
  runtime, fails closed: the JVM then has no cryptography providers at all.
  Enforcing the launch configuration belongs to deployment policy, for
  example admission control that forbids running as root and forbids command
  and environment overrides, and a read-only root filesystem.

## Derived Images

- Do not upgrade the `zulu25*` packages (`apt-get upgrade`) in derived images.
  The Azul apt repository is configured in the base image. `java.security` and
  `cacerts` are not dpkg configuration files, so an upgrade replaces them with
  stock (non-FIPS) versions, and the startup checks will then fail. Consider
  `apt-mark hold` on the `zulu25*` packages in derived images.
- Keep the image's `JAVA_TOOL_OPTIONS` (`ENV JAVA_TOOL_OPTIONS="$JAVA_TOOL_OPTIONS
  <your options>"`), since it carries the provider module path. See
  [Provider Discovery](#provider-discovery-module-path-and-serviceloader).
- The image runs as non-root user `10001:10001` (`wolfssl`), with
  `WORKDIR /home/wolfssl`. Derived images switch to `USER root` for steps
  that install packages or write outside `/home/wolfssl` (for example
  creating `/app`), and back to `USER 10001:10001` at the end, as the
  [basic test image](test-images/basic-test-image/Dockerfile) does. Running
  with another non-root `--user` also works.
- The integrity check covers `libwolfssl.so*`, the JNI libraries, the
  provider JARs, `java.security`, `cacerts` and `/etc/krb5.conf`. A derived
  image that intentionally changes one of these files (for example adding a
  CA certificate to `cacerts`) runs
  `/usr/local/bin/update-integrity-checksums.sh` as root after the change,
  otherwise the container fails its startup integrity check. For example, to
  grant Sun's MD5, which is not FIPS validated and needs an approved exception
  (see [Granting Additional Sun Services](#granting-additional-sun-services)):

  ```dockerfile
  USER root
  RUN JS=$JAVA_HOME/conf/security/java.security \
      && chmod 644 $JS \
      && echo "wolfssl.filtered.sun.additionalServices=MessageDigest.MD5" >> $JS \
      && chmod 444 $JS \
      && /usr/local/bin/update-integrity-checksums.sh
  USER 10001:10001
  ```

## FIPS Container Verification Tests / Docker Entrypoint

The container includes verification tests of the FIPS container that run
when the container is started via the Docker entrypoint script
(docker-entrypoint.sh). This script performs the following:

1. Configures debug logging based on environment variables:
    - `WOLFJCE_DEBUG`
    - `WOLFJSSE_DEBUG`
    - `WOLFJSSE_ENGINE_DEBUG`
2. Sets library paths for JNI libraries in standard Debian locations, and
   warns if `JAVA_TOOL_OPTIONS` no longer carries the provider module
   settings.
3. Verifies integrity of the FIPS native libraries, JNI libraries, provider
   JARs, `java.security`, `cacerts` and `/etc/krb5.conf` against the
   checksums in `/opt/wolfssl-fips/checksums/libraries.sha256`.
4. Conducts FIPS container sanity checks (FipsInitCheck.java)
    - List out all currently installed Java Security providers (Informational)
    - Verify wolfJCE is installed as provider at priority 1
    - Verify wolfJSSE is installed as provider at priority 2
    - Verify the wolfSSL provider modules were loaded from their JARs in
      `/usr/share/java`, and the native libraries from `/usr/local/lib` and
      `/usr/lib/jni` (detects look-alike modules or libraries that come in
      through the environment)
    - Verify wolfJCE reports a native wolfCrypt FIPS build (`Fips.enabled`)
    - Verify the native FIPS module version (`Fips.fipsVersion`) matches
      `WOLFSSL_FIPS_VARIANT` (5 for `v5.2.3`, 7 for `ready`); a changed or
      missing value fails
    - Verify the FIPS conditional algorithm self tests (CASTs) passed, and
      that the module is not in an error state (`wolfCrypt_GetStatus_fips`)
    - Verify Java /lib/security/cacerts file is WKS format. If it is not, the
      format it is in is listed in the error message (JKS, JCEKS or PKCS12)
    - Forces run of wolfCrypt FIPS POST by calling one service (MessageDigest)
    - Sanity check java.security providers, ensure no non-compliant providers are present
    - Instantiate the expected algorithms without naming a provider (message
      digests, MACs, ciphers, signatures, `SSLContext`, `KeyManagerFactory`,
      `TrustManagerFactory`, PKIX `CertPathBuilder` / `CertPathValidator`,
      `KeyStore` WKS), and verify each one comes from wolfJCE or wolfJSSE
    - Verify that algorithms outside the FIPS boundary are unavailable. Each
      `getInstance()` must report the algorithm as not available with the
      exception that API documents (for example `NoSuchAlgorithmException`).
      Any other exception fails the check. An algorithm granted in
      `java.security` is allowed from the granting filtered provider
    - List every service of every registered provider, and verify each one is
      allowed for its provider: wolfJCE and wolfJSSE may offer any service,
      FilteredSun / FilteredSunEC / FilteredSunRsaSign exactly the services
      listed in [Custom Filtered Security Providers](#custom-filtered-security-providers)
      (all required) plus any granted in `java.security`
      ([Granting Additional Sun Services](#granting-additional-sun-services)),
      and the JDK providers SunJGSS, SunSASL, JdkSASL, XMLDSig and JdkLDAP
      only their non-cryptographic service types. Any other provider or
      service fails the check.
    - Verify `SecureRandom.getInstanceStrong()` comes from wolfJCE and
      `SSLContext.getDefault()` from wolfJSSE
    - List the default `SSLContext`'s TLS protocols (informational), and
      verify it enables and supports no cipher suite with a cipher or MAC
      outside the wolfCrypt FIPS module (listed in
      Changes item 9)

### Running FIPS Container Verification Tests Manually

```bash
# Run FIPS Container Verification Tests
docker run wolfssl-openjdk-fips-zulu25-debian13:latest java -cp /opt/wolfssl-fips/bin FipsInitCheck

# Run the integrity check
docker run -it wolfssl-openjdk-fips-zulu25-debian13:latest /usr/local/bin/integrity-check.sh
```

## Troubleshooting

### Container Fails to Start

If the container exits with FIPS POST failure:

1. Check the wolfSSL password is correct
2. Verify the wolfSSL commercial FIPS package is valid
3. Enable debug logging: `WOLFJCE_DEBUG=true` and `WOLFJSSE_DEBUG=true`

If the startup checks report `native wolfCrypt FIPS module version ... does
not match WOLFSSL_FIPS_VARIANT` or `WOLFSSL_FIPS_VARIANT is ...`, the
variable was changed or unset at run time (for example with `docker run -e`
or a Kubernetes `env:` entry). Remove the override, the image already sets
the right value.

If a provider is missing at runtime, rerun with
`-Djava.security.debug=provider`; the JDK silently skips providers that fail
to load (for example when `JAVA_TOOL_OPTIONS` was replaced instead of
appended to, which drops the provider module path and module flags).

### WKS cacerts File Issues

If you encounter cacerts-related errors in derived images:

1. **"Permission denied" when modifying cacerts**: The file is root-owned and
   read-only, and the container runs as a non-root user. Change it in a
   derived image Dockerfile as root, then regenerate the integrity
   checksums, otherwise the container fails its startup integrity check
   (`cacerts - INTEGRITY FAILURE`):

   ```dockerfile
   USER root
   COPY my-ca.der /tmp/my-ca.der
   RUN chmod 644 $JAVA_HOME/lib/security/cacerts \
       && keytool -importcert -noprompt -alias my-ca -file /tmp/my-ca.der \
           -cacerts -storepass changeitchangeit \
       && chmod 444 $JAVA_HOME/lib/security/cacerts \
       && rm -f /tmp/my-ca.der \
       && /usr/local/bin/update-integrity-checksums.sh
   USER 10001:10001
   ```

2. **"Unable to load system cacerts file as WKS: it is in PKCS12 format"**
   (or JKS / JCEKS, the message ends with the WKS error "Invalid magic
   number ..., KeyStore not of type WKS"): The cacerts file was overwritten
   - Most likely by an upgrade of the `zulu25*` packages, which ship a PKCS12
     cacerts (see [Derived Images](#derived-images))
   - Use the base image's WKS format cacerts file instead

### Algorithms Unavailable

wolfCrypt FIPS 140-3 certificates are validated with a specific set of
algorithms defined inside the cryptographic boundary. If Java applications
try to use non-FIPS validated algorithms, these will not be available from
the wolfJCE or wolfJSSE providers, and Java application code may need to
be changed to use compliant algorithms or KeyStore types.

### Debug Logging

Enable debug logging by setting the `WOLFJCE_DEBUG`, `WOLFJSSE_DEBUG`, or
`WOLFJSSE_ENGINE_DEBUG` environment variables to `true`. `WOLFJCE_DEBUG` will
enable wolfJCE debug logs. `WOLFJSSE_DEBUG` will enable wolfJSSE debug logs.
`WOLFJSSE_ENGINE_DEBUG` will enable SSLEngine logs. The entrypoint applies
these settings to `java` and `jshell` commands, and to the startup checks.

```bash
docker run -it -e WOLFJCE_DEBUG=true \
           -e WOLFJSSE_DEBUG=true \
           wolfssl-openjdk-fips-zulu25-debian13:latest
```

## Version Information

- **wolfSSL**: 5.9.4 Commercial FIPS v5.2.3 (default), or 5.9.4 GPLv3 FIPS
  Ready (with `--fips=ready`, not FIPS validated)
- **Base Image**: `azul-zulu:25.36-25.0.4.1-jdk-debian13` (Azul Zulu 25.0.4.1,
  Debian 13)
- **wolfcrypt-jni**: Master branch (GitHub)
- **wolfssljni**: Master branch (GitHub)
- **FIPS Certificate**: #5548 (commercial FIPS builds; CAVP certificate A7470)

## Documentation

In addition to this README, the wolfJCE and wolfJSSE User Manuals can be
found online here:

[wolfCrypt JNI/JCE Manual](https://www.wolfssl.com/documentation/manuals/wolfcryptjni/)
[wolfSSL JNI/JSSE Manual](https://www.wolfssl.com/documentation/manuals/wolfssljni/)

## Support

For issues specific to this container implementation, please check:

1. Container logs for FIPS error messages
2. wolfSSL documentation for FIPS module requirements
3. Java security provider documentation

Email support@wolfssl.com for wolfSSL-specific issues or questions.
