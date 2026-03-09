# syntax=docker/dockerfile:1
# Spring Boot SSL Tests with wolfJSSE FIPS
# Build: docker build -t spring-boot-wolfjsse-fips .

ARG FIPS_BASE_IMAGE=wolfssl-openjdk-fips-root:latest
ARG SPRING_BOOT_TAG=v3.4.1

# Stage 1: Build Spring Boot with FIPS patches
FROM rootpublic/openjdk:19-jdk-bookworm-slim AS builder
RUN apt-get update && apt-get install -y build-essential git perl && rm -rf /var/lib/apt/lists/*
WORKDIR /app/spring-boot
ARG SPRING_BOOT_TAG
RUN git clone --depth 1 --branch ${SPRING_BOOT_TAG} https://github.com/spring-projects/spring-boot.git .
COPY apply_spring_fips_fixes.sh /tmp/
RUN chmod +x /tmp/apply_spring_fips_fixes.sh && /tmp/apply_spring_fips_fixes.sh /app/spring-boot
# Pre-compile test sources to warm the Gradle cache. Failures are tolerated because
# they do not affect the runtime image, but a warning is logged if this step fails.
RUN if ! ./gradlew :spring-boot-project:spring-boot:compileTestJava \
    :spring-boot-project:spring-boot-autoconfigure:compileTestJava \
    :spring-boot-project:spring-boot-actuator:compileTestJava \
    --no-daemon -x checkstyleMain -x checkstyleTest -x checkFormat; then \
      echo "WARNING: Gradle compileTestJava tasks failed; continuing Docker build because tests are not required for the runtime image."; \
    fi
# Resolve test runtime classpath dependencies. Failures are tolerated but logged,
# since these dependencies are only needed for test execution, not for running the image.
RUN if ! ./gradlew :spring-boot-project:spring-boot:dependencies --configuration testRuntimeClasspath --no-daemon; then \
      echo "WARNING: Gradle dependencies (testRuntimeClasspath) resolution failed; continuing Docker build because tests are not required for the runtime image."; \
    fi

# Stage 2: Runtime with FIPS base
FROM ${FIPS_BASE_IMAGE}
RUN apt-get update && apt-get install -y git openjdk-17-jdk-headless && rm -rf /var/lib/apt/lists/*
ENV GRADLE_JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
COPY --from=builder /app/spring-boot /app/spring-boot
COPY --from=builder /root/.gradle /root/.gradle

# Get wolfSSL certs and generate test certs with localhost SAN
RUN git clone --depth 1 --filter=blob:none --sparse https://github.com/wolfSSL/wolfssl.git /tmp/wolfssl && \
    cd /tmp/wolfssl && git sparse-checkout set certs && cp -r certs /app/certs && rm -rf /tmp/wolfssl && \
    for f in /app/certs/*.pem; do [ -f "$f" ] && grep -q "BEGIN" "$f" && sed -n '/-----BEGIN/,/-----END/p' "$f" > "$f.tmp" && mv "$f.tmp" "$f"; done

RUN mkdir -p /app/certs/test

WORKDIR /app/spring-boot
ENV FIPS_CHECK=true GRADLE_OPTS="-Xmx4g -XX:MaxMetaspaceSize=512m"
ENV WOLFJSSE_TEST_OPTS="-Xbootclasspath/a:/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar \
    -Djava.library.path=/usr/lib/jni:/usr/local/lib \
    -Djavax.net.ssl.trustStore=/app/spring-boot/spring-boot-project/spring-boot/src/test/resources/truststore.wks \
    -Djavax.net.ssl.trustStorePassword=wolfSSLFIPSPwd2024 -Djavax.net.ssl.trustStoreType=WKS \
    --add-modules=jdk.crypto.ec \
    --add-exports=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED \
    --add-opens=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED \
    --add-opens=java.base/java.security=ALL-UNNAMED \
    --add-opens=java.base/sun.security.provider=ALL-UNNAMED \
    --add-opens=java.base/sun.security.util=ALL-UNNAMED \
    --add-opens=java.base/sun.security.rsa=ALL-UNNAMED"

RUN ln -sf /usr/lib/jni/libwolfssljni.so /usr/local/openjdk-19/lib/ && \
    ln -sf /usr/lib/jni/libwolfcryptjni.so /usr/local/openjdk-19/lib/ && \
    ln -sf /usr/local/lib/libwolfssl.so /usr/local/openjdk-19/lib/

# Gradle security config: Uses standard SUN providers (not wolfSSL) because Gradle
# needs MD5 checksums for dependency verification, which is not FIPS-approved.
# This config is ONLY used by the Gradle daemon JVM, not by test JVMs.
# The test JVMs use the FIPS base image's java.security which already has
# WolfCryptProvider and WolfSSLProvider registered at high priority.
# WKS is set as default keystore type for compatibility with our converted keystores.
RUN cat > /usr/local/openjdk-19/conf/security/java.security.gradle <<'EOF'
security.provider.1=SUN
security.provider.2=SunRsaSign
security.provider.3=SunEC
security.provider.4=SunJSSE
security.provider.5=SunJCE
keystore.type=WKS
keystore.type.compat=true
EOF

# Gradle init for wolfJSSE test configuration
RUN mkdir -p /root/.gradle/init.d && cat > /root/.gradle/init.d/wolfjsse.gradle <<'EOF'
allprojects {
    // Skip buildSrc tests - they fail due to FIPS environment (MD5 checksums, etc.)
    if (project.name == 'buildSrc' || project.path.startsWith(':buildSrc')) {
        tasks.withType(Test) { enabled = false }
    }
    tasks.withType(Test) {
        executable = '/usr/local/openjdk-19/bin/java'
        def opts = System.getenv('WOLFJSSE_TEST_OPTS')
        if (opts) jvmArgs opts.split(/\s+/).findAll { it.trim() }
        systemProperty 'junit.jupiter.execution.timeout.default', '120s'
        testLogging { events "passed", "skipped", "failed"; showExceptions = true }
    }
}
EOF

# WKS keystore utilities
RUN mkdir -p /app/util && cat > /app/util/WksUtil.java <<'JAVA'
import java.io.*; import java.nio.charset.StandardCharsets; import java.nio.file.*; import java.security.*; import java.security.cert.Certificate; import java.security.spec.*; import java.util.*;
public class WksUtil {
    static {
        // Register WolfCryptProvider if on classpath but not yet in security providers
        // (needed when running under java-17 with -Xbootclasspath/a)
        try {
            if (Security.getProvider("wolfJCE") == null) {
                Security.addProvider((Provider) Class.forName(
                    "com.wolfssl.provider.jce.WolfCryptProvider").getConstructor().newInstance());
            }
        } catch (Exception e) { /* not on classpath, skip */ }
    }
    static final char[] FIPS_PWD = "wolfSSLFIPSPwd2024".toCharArray();
    public static void main(String[] a) throws Exception {
        if ("combined".equals(a[0])) combined(a[1],a[2],a[3],a[4],a[5],a[6].toCharArray());
        else if ("selfsigned".equals(a[0])) selfsigned(a[1],a[2],a[3],a[4],a[5].toCharArray());
        else if ("trust".equals(a[0])) trust(a[1],a[2],a[3],a[4].toCharArray());
        else if ("convert".equals(a[0])) convert(a[1],a[2].toCharArray(),a[3],a[4].toCharArray());
        else if ("addca".equals(a[0])) addca(a[1],a[2],a[3],a[4]);
        else if ("exportpem".equals(a[0])) exportpem(a[1],a[2].toCharArray(),a[3],a[4],a[5],a.length > 6 ? a[6] : null);
    }
    static void combined(String cert, String key, String ca, String out, String alias, char[] pwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("WKS"); ks.load(null, pwd);
        ks.setKeyEntry(alias, loadKey(key), pwd, new java.security.cert.Certificate[]{loadCert(cert), loadCert(ca)});
        ks.setCertificateEntry("ca", loadCert(ca));
        try (FileOutputStream f = new FileOutputStream(out)) { ks.store(f, pwd); }
        System.out.println("Created combined keystore+truststore: " + out);
    }
    static void selfsigned(String cert, String key, String out, String alias, char[] pwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("WKS"); ks.load(null, pwd);
        ks.setKeyEntry(alias, loadKey(key), pwd, new java.security.cert.Certificate[]{loadCert(cert)});
        try (FileOutputStream f = new FileOutputStream(out)) { ks.store(f, pwd); }
        System.out.println("Created self-signed keystore: " + out);
    }
    static void trust(String cert, String out, String alias, char[] pwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("WKS"); ks.load(null, pwd);
        ks.setCertificateEntry(alias, loadCert(cert));
        try (FileOutputStream f = new FileOutputStream(out)) { ks.store(f, pwd); }
        System.out.println("Created truststore: " + out);
    }
    static void convert(String in, char[] srcPwd, String out, char[] dstPwd) throws Exception {
        String type = in.toLowerCase().endsWith(".p12") ? "PKCS12" : "JKS";
        KeyStore src = KeyStore.getInstance(type);
        try (FileInputStream f = new FileInputStream(in)) { src.load(f, srcPwd); }
        KeyStore dst = KeyStore.getInstance("WKS"); dst.load(null, dstPwd);
        for (Enumeration<String> e = src.aliases(); e.hasMoreElements();) {
            String a = e.nextElement();
            if (src.isKeyEntry(a)) dst.setKeyEntry(a, src.getKey(a, srcPwd), dstPwd, src.getCertificateChain(a));
            else dst.setCertificateEntry(a, src.getCertificate(a));
        }
        try (FileOutputStream f = new FileOutputStream(out)) { dst.store(f, dstPwd); }
        System.out.println("Converted: " + in + " -> " + out);
    }
    static void addca(String ksPath, String caPath, String pwd, String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance("WKS");
        try (FileInputStream f = new FileInputStream(ksPath)) { ks.load(f, pwd.toCharArray()); }
        if (!ks.containsAlias(alias)) {
            ks.setCertificateEntry(alias, loadCert(caPath));
            try (FileOutputStream f = new FileOutputStream(ksPath)) { ks.store(f, pwd.toCharArray()); }
            System.out.println("  Added test CA to cacerts as: " + alias);
        }
        System.out.println("Done. cacerts now has " + ks.size() + " entries");
    }
    static void exportpem(String in, char[] srcPwd, String alias, String certOut, String keyOut, String chainOut) throws Exception {
        KeyStore src = KeyStore.getInstance(storeTypeFor(in));
        try (FileInputStream f = new FileInputStream(in)) { src.load(f, srcPwd); }
        Key key = src.getKey(alias, srcPwd);
        if (!(key instanceof PrivateKey)) throw new IllegalArgumentException("Alias has no private key: " + alias);
        Certificate cert = src.getCertificate(alias);
        Certificate[] chain = src.getCertificateChain(alias);
        writePem("PRIVATE KEY", key.getEncoded(), keyOut);
        if (cert != null) writePem("CERTIFICATE", cert.getEncoded(), certOut);
        if (chainOut != null && chain != null && chain.length > 0) {
            try (Writer w = new OutputStreamWriter(new FileOutputStream(chainOut), StandardCharsets.US_ASCII)) {
                for (Certificate c : chain) writePem(w, "CERTIFICATE", c.getEncoded());
            }
        }
        System.out.println("Exported PEM key/cert for alias " + alias + " from " + in);
    }
    static String storeTypeFor(String path) {
        String p = path.toLowerCase();
        if (p.endsWith(".p12") || p.endsWith(".pfx")) return "PKCS12";
        if (p.endsWith(".wks")) return "WKS";
        return "JKS";
    }
    static void writePem(String type, byte[] der, String out) throws Exception {
        try (Writer w = new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.US_ASCII)) {
            writePem(w, type, der);
        }
    }
    static void writePem(Writer w, String type, byte[] der) throws Exception {
        w.write("-----BEGIN " + type + "-----\n");
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        w.write(b64);
        if (!b64.endsWith("\n")) w.write("\n");
        w.write("-----END " + type + "-----\n");
    }
    static java.security.cert.Certificate loadCert(String f) throws Exception {
        try (FileInputStream in = new FileInputStream(f)) {
            return java.security.cert.CertificateFactory.getInstance("X.509", "FilteredSun").generateCertificate(in);
        }
    }
    static PrivateKey loadKey(String f) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(f)))
            .replace("-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----","").replaceAll("\\s","");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem));
        try { return KeyFactory.getInstance("RSA").generatePrivate(spec); }
        catch (Exception e) { return KeyFactory.getInstance("EC").generatePrivate(spec); }
    }
}
JAVA
RUN cd /app/util && /usr/local/openjdk-19/bin/javac --release 17 -cp /usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar WksUtil.java

# Generate CA-signed test certificates with localhost SAN (openssl-free)
RUN cd /app/certs/test && \
    KT=/usr/lib/jvm/java-17-openjdk-amd64/bin/keytool && \
    JRUN17="/usr/lib/jvm/java-17-openjdk-amd64/bin/java -cp /app/util" && \
    P=wolfSSLFIPSPwd2024 && \
    $KT -genkeypair -alias ca -keyalg RSA -keysize 2048 -sigalg SHA256withRSA \
        -storetype PKCS12 -keystore ca.p12 -storepass "$P" -keypass "$P" \
        -dname "CN=Test CA" -validity 3650 \
        -ext bc:c=ca:true -ext ku:c=keyCertSign,cRLSign && \
    $KT -exportcert -rfc -alias ca -keystore ca.p12 -storetype PKCS12 \
        -storepass "$P" -file ca-cert.pem && \
    for alias in server client; do \
        CN=$([ "$alias" = server ] && echo localhost || echo client) && \
        $KT -genkeypair -alias "$alias" -keyalg RSA -keysize 2048 -sigalg SHA256withRSA \
            -storetype PKCS12 -keystore "$alias.p12" -storepass "$P" -keypass "$P" \
            -dname "CN=$CN" -validity 3650 -ext san=dns:localhost,ip:127.0.0.1 && \
        $KT -certreq -alias "$alias" -keystore "$alias.p12" -storetype PKCS12 \
            -storepass "$P" -file "$alias.csr" && \
        $KT -gencert -alias ca -keystore ca.p12 -storetype PKCS12 -storepass "$P" \
            -infile "$alias.csr" -rfc -outfile "$alias-signed.pem" -validity 3650 \
            -ext bc=ca:false -ext ku:c=digitalSignature,keyEncipherment \
            -ext eku=serverAuth,clientAuth -ext san=dns:localhost,ip:127.0.0.1 && \
        $KT -importcert -noprompt -alias ca -keystore "$alias.p12" -storetype PKCS12 \
            -storepass "$P" -file ca-cert.pem && \
        $KT -importcert -noprompt -alias "$alias" -keystore "$alias.p12" -storetype PKCS12 \
            -storepass "$P" -file "$alias-signed.pem" && \
        $JRUN17 WksUtil exportpem "$alias.p12" "$P" "$alias" "$alias-cert.pem" "$alias-key.pem"; \
    done && \
    rm -f *.csr *-signed.pem ca.p12 server.p12 client.p12

# Create WKS keystores script
RUN cat > /app/create-wks.sh <<'WKSEOF' && chmod +x /app/create-wks.sh
#!/bin/bash
FIPS_PWD="wolfSSLFIPSPwd2024"; CERTS="/app/certs/test"; SP="/app/spring-boot/spring-boot-project"
run() { /usr/local/openjdk-19/bin/java -cp /app/util:/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar -Djava.library.path=/usr/lib/jni:/usr/local/lib WksUtil "$@"; }
conv() { /usr/lib/jvm/java-17-openjdk-amd64/bin/java -Xbootclasspath/a:/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar -Djava.library.path=/usr/lib/jni:/usr/local/lib -cp /app/util:/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar WksUtil "$@"; }

echo "=== Converting JKS/P12 to WKS ==="
find "$SP" \( -name "*.jks" -o -name "*.p12" \) 2>/dev/null | while read -r f; do
    w="${f%.*}.wks"; for p in password secret changeit; do conv convert "$f" "$p" "$w" "$FIPS_PWD" 2>/dev/null && break; done
done
# Delete old JKS/P12 files after conversion to avoid loading wrong format
echo "=== Deleting old JKS/P12 files ==="
find "$SP" -name "*.jks" -delete 2>/dev/null
find "$SP" -name "*.p12" -delete 2>/dev/null

echo "=== Creating WKS keystores ==="
for d in "$SP/spring-boot/src/test/resources" "$SP/spring-boot-autoconfigure/src/test/resources" "$SP/spring-boot-actuator/src/test/resources"; do
    [ -d "$d" ] && for n in test restricted test-expired test-not-yet-valid; do
        [ ! -f "$d/$n.wks" ] && run combined "$CERTS/server-cert.pem" "$CERTS/server-key.pem" "$CERTS/ca-cert.pem" "$d/$n.wks" "test-alias" "$FIPS_PWD" 2>/dev/null
    done && run trust "$CERTS/ca-cert.pem" "$d/truststore.wks" "ca" "$FIPS_PWD" 2>/dev/null
done

for sub in rsocket amqp ssl cassandra data/redis data/mongo mongo mail; do
    d="$SP/spring-boot-autoconfigure/src/test/resources/org/springframework/boot/autoconfigure/$sub"
    mkdir -p "$d" 2>/dev/null; [ -d "$d" ] && {
        [ ! -f "$d/test.wks" ] && run combined "$CERTS/server-cert.pem" "$CERTS/server-key.pem" "$CERTS/ca-cert.pem" "$d/test.wks" "test-alias" "$FIPS_PWD" 2>/dev/null
        [ ! -f "$d/keystore.wks" ] && run combined "$CERTS/server-cert.pem" "$CERTS/server-key.pem" "$CERTS/ca-cert.pem" "$d/keystore.wks" "test-alias" "$FIPS_PWD" 2>/dev/null
        [ ! -f "$d/truststore.wks" ] && run trust "$CERTS/ca-cert.pem" "$d/truststore.wks" "ca" "$FIPS_PWD" 2>/dev/null
    }
done

for d in "$SP/spring-boot/src/test/resources" "$SP/spring-boot-autoconfigure/src/test/resources"; do
    [ -d "$d" ] && {
        [ ! -f "$d/client.wks" ] && run combined "$CERTS/client-cert.pem" "$CERTS/client-key.pem" "$CERTS/ca-cert.pem" "$d/client.wks" "client" "$FIPS_PWD" 2>/dev/null
        [ ! -f "$d/server-with-client-trust.wks" ] && run combined "$CERTS/server-cert.pem" "$CERTS/server-key.pem" "$CERTS/ca-cert.pem" "$d/server-with-client-trust.wks" "server" "$FIPS_PWD" 2>/dev/null
    }
done
# Create WKS at direct classpath resource paths (not full package paths)
# Some tests reference e.g. "classpath:rsocket/test.wks" which maps to
# src/test/resources/rsocket/test.wks, not the org/springframework/... path.
AUTOCONFIG_RES="$SP/spring-boot-autoconfigure/src/test/resources"
for sub in rsocket amqp ssl; do
    mkdir -p "$AUTOCONFIG_RES/$sub" 2>/dev/null
    [ ! -f "$AUTOCONFIG_RES/$sub/test.wks" ] && run combined "$CERTS/server-cert.pem" "$CERTS/server-key.pem" "$CERTS/ca-cert.pem" "$AUTOCONFIG_RES/$sub/test.wks" "test-alias" "$FIPS_PWD" 2>/dev/null
done

echo "=== WKS setup complete: $(find "$SP" -name "*.wks" 2>/dev/null | wc -l) files ==="
WKSEOF
RUN /app/create-wks.sh

# Add test CA to all truststores
RUN cat > /app/add-ca.sh <<'ADDEOF' && chmod +x /app/add-ca.sh
#!/bin/bash
FIPS_PWD="wolfSSLFIPSPwd2024"; CA="/app/certs/test/ca-cert.pem"; SP="/app/spring-boot/spring-boot-project"
run() { /usr/local/openjdk-19/bin/java -cp /app/util:/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar -Djava.library.path=/usr/lib/jni:/usr/local/lib WksUtil addca "$1" "$CA" "$FIPS_PWD" "test-ca" 2>/dev/null; }
echo "Adding test CA to all test truststores..."
find "$SP" \( -name "truststore.wks" -o -name "test.wks" \) 2>/dev/null | while read -r f; do echo "  Checking: $f"; run "$f"; done
echo "Done adding test CA to truststores"
ADDEOF
RUN /app/add-ca.sh || true

# Replace test PEM files with CA-signed certificates
# This is critical because Spring Boot tests that load PEM directly need CA-signed certs
RUN CERTS="/app/certs/test" && SP="/app/spring-boot/spring-boot-project" && \
    # Create certificate chain (server cert + CA cert)
    cat "$CERTS/server-cert.pem" "$CERTS/ca-cert.pem" > /tmp/test-cert-chain.pem && \
    # Replace PEM files in all test resource directories
    for d in "$SP/spring-boot/src/test/resources" \
             "$SP/spring-boot-autoconfigure/src/test/resources" \
             "$SP/spring-boot-actuator/src/test/resources"; do \
        [ -d "$d" ] && { \
            cp /tmp/test-cert-chain.pem "$d/test-cert.pem" 2>/dev/null || true; \
            cp "$CERTS/server-key.pem" "$d/test-key.pem" 2>/dev/null || true; \
            cp /tmp/test-cert-chain.pem "$d/test-cert-chain.pem" 2>/dev/null || true; \
            echo "Replaced PEM files in $d"; \
        }; \
    done && rm -f /tmp/test-cert-chain.pem && \
    echo "=== PEM file replacement complete ==="

# Generate RSA certs for SSL reload test (replacing ED25519 originals which aren't FIPS-approved)
RUN cd /app/certs/test && \
    KT=/usr/lib/jvm/java-17-openjdk-amd64/bin/keytool && \
    JRUN17="/usr/lib/jvm/java-17-openjdk-amd64/bin/java -cp /app/util" && \
    P=wolfSSLFIPSPwd2024 && \
    for CN in 1 2; do \
        $KT -genkeypair -alias "reload${CN}" -keyalg RSA -keysize 2048 -sigalg SHA256withRSA \
            -storetype PKCS12 -keystore "reload${CN}.p12" -storepass "$P" -keypass "$P" \
            -dname "CN=${CN}" -validity 3650 && \
        $JRUN17 WksUtil exportpem "reload${CN}.p12" "$P" "reload${CN}" "reload${CN}-cert.pem" "reload${CN}-key.pem"; \
    done && \
    rm -f reload1.p12 reload2.p12 && \
    SP="/app/spring-boot/spring-boot-project" && \
    TOMCAT_RES="$SP/spring-boot/src/test/resources/org/springframework/boot/web/embedded/tomcat" && \
    cp reload1-cert.pem "$TOMCAT_RES/1.crt" && cp reload1-key.pem "$TOMCAT_RES/1.key" && \
    cp reload2-cert.pem "$TOMCAT_RES/2.crt" && cp reload2-key.pem "$TOMCAT_RES/2.key" && \
    echo "=== SSL reload test certs replaced (ED25519 -> RSA) ==="

# Generate SslInfoTests-specific WKS keystores with self-signed certs and exact validity dates.
# Uses JDK keytool start dates (openssl/faketime not required).
RUN mkdir -p /app/certs/sslinfo && cd /app/certs/sslinfo && \
    KT=/usr/lib/jvm/java-17-openjdk-amd64/bin/keytool && \
    JRUN17="/usr/lib/jvm/java-17-openjdk-amd64/bin/java -cp /app/util" && \
    JRUN19="/usr/local/openjdk-19/bin/java -cp /app/util:/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar -Djava.library.path=/usr/lib/jni:/usr/local/lib" && \
    P=wolfSSLFIPSPwd2024 && \
    DNAME="CN=localhost, OU=Spring, O=VMware, L=Palo Alto, ST=California, C=US" && \
    for name in valid expired not-yet-valid soon-to-expire; do \
        case "$name" in \
            valid)          SD="" V=3650 ;; \
            expired)        SD="-startdate 2020/01/01" V=30 ;; \
            not-yet-valid)  SD="-startdate 2030/01/01" V=3650 ;; \
            soon-to-expire) SD="" V=5 ;; \
        esac && \
        $KT -genkeypair -alias spring-boot -keyalg RSA -keysize 2048 -sigalg SHA256withRSA \
            -storetype PKCS12 -keystore "${name}.p12" -storepass "$P" -keypass "$P" \
            -dname "$DNAME" $SD -validity $V && \
        $JRUN17 WksUtil exportpem "${name}.p12" "$P" "spring-boot" "${name}-cert.pem" "${name}-key.pem" && \
        $JRUN19 WksUtil selfsigned "${name}-cert.pem" "${name}-key.pem" "/app/certs/sslinfo/${name}.wks" "spring-boot" "$P"; \
    done && \
    rm -f *.p12 *.pem && \
    echo "=== SslInfoTests WKS keystores created ==="

# Test runner
RUN cat > /app/run-tests.sh <<'EOF' && chmod +x /app/run-tests.sh
#!/bin/bash
cd /app/spring-boot; export JAVA_HOME="${GRADLE_JAVA_HOME}"; unset JAVA_TOOL_OPTIONS
RUNS=()
run() { local name="$1"; shift; RUNS+=("$name"); echo -e "\n=== Running: $name ==="; "$@" 2>&1 | tee "/tmp/${name}.log"; }
summary() {
    for n in "${RUNS[@]}"; do
        local p f s t
        p=$(grep -c ' PASSED$' "/tmp/$n.log" 2>/dev/null) || p=0
        f=$(grep -c ') FAILED$' "/tmp/$n.log" 2>/dev/null) || f=0
        s=$(grep -c ' SKIPPED$' "/tmp/$n.log" 2>/dev/null) || s=0
        t=$((p + f + s))
        [ "$t" -gt 0 ] && echo "- $n: $t tests: $p passed, $f failed, $s skipped"
    done
}

./gradlew :spring-boot-project:spring-boot:clean :spring-boot-project:spring-boot-autoconfigure:clean :spring-boot-project:spring-boot-actuator:clean --no-daemon 2>/dev/null || true

run spring-boot ./gradlew :spring-boot-project:spring-boot:test --tests "*Ssl*" --tests "*ssl*" --tests "*Pem*" --tests "*Jks*" --tests "*Keystore*" --tests "*KeyStore*" --no-daemon -x checkstyleMain -x checkstyleTest -x checkFormat -x :buildSrc:test -x :buildSrc:check --continue || true
run spring-boot-autoconfigure ./gradlew :spring-boot-project:spring-boot-autoconfigure:test --tests "*Ssl*" --tests "*ssl*" --no-daemon -x checkstyleMain -x checkstyleTest -x checkFormat -x :buildSrc:test -x :buildSrc:check --continue || true
run spring-boot-actuator ./gradlew :spring-boot-project:spring-boot-actuator:test --tests "*Ssl*" --tests "*ssl*" --no-daemon -x checkstyleMain -x checkstyleTest -x checkFormat -x :buildSrc:test -x :buildSrc:check --continue || true

echo -e "\n=== TEST SUMMARY ==="; summary
EOF

CMD ["/app/run-tests.sh"]
