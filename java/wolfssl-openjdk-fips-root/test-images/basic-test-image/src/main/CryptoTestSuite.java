/* CryptoTestSuite.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * JCA cryptographic operations test suite for wolfSSL FIPS.
 * This class demonstrates usage of JCA APIs with the wolfJCE provider
 * and verifies that all operations use FIPS-validated algorithms.
 */
public class CryptoTestSuite {

    private static final String TEST_DATA =
        "This is test data for FIPS cryptographic operations";
    private static final String PROVIDER_WOLFJCE = "wolfJCE";

    public static void main(String[] args) {
        CryptoTestSuite suite = new CryptoTestSuite();
        suite.runAllTests();
    }

    public void runAllTests() {
        System.out.println(
            "=== wolfSSL FIPS JCA Cryptographic Operations Test Suite ===\n");

        try {
            /* Verify provider setup */
            verifyProviderSetup();

            /* Test message digest operations */
            testMessageDigestOperations();

            /* Test symmetric encryption (AES) */
            testSymmetricEncryption();

            /* Test asymmetric encryption (RSA) */
            testAsymmetricEncryption();

            /* Test MAC operations */
            testMacOperations();

            /* Test digital signatures */
            testDigitalSignatures();

            /* Test key generation */
            testKeyGeneration();

            /* Test key agreement protocols */
            testKeyAgreement();

            /* Test algorithm parameter generators */
            testAlgorithmParameterGenerators();

            /* Test secure random */
            testSecureRandom();

            System.out.println("\n=== All JCA Cryptographic Tests PASSED ===");

        } catch (Exception e) {
            System.err.println("\nERROR: JCA Cryptographic test failed!");
            System.err.println("Exception: " + e.getClass().getName() +
                ": " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void verifyProviderSetup()
        throws SecurityException {

        System.out.println("Verifying wolfJCE Provider Setup:");

        Provider wolfJCE = Security.getProvider(PROVIDER_WOLFJCE);
        if (wolfJCE == null) {
            throw new SecurityException("wolfJCE provider not found");
        }

        System.out.println("   wolfJCE provider found: " + wolfJCE.getName() +
            " v" + wolfJCE.getVersion());
        System.out.println("   Provider info: " + wolfJCE.getInfo());
        System.out.println();
    }

    private void testMessageDigestOperations()
        throws Exception {

        System.out.println("Testing Message Digest Operations:");

        String[] algorithms = {
            "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
        };

        for (String algorithm : algorithms) {
            MessageDigest md = MessageDigest.getInstance(algorithm);

            /* Verify using wolfJCE */
            if (!PROVIDER_WOLFJCE.equals(md.getProvider().getName())) {
                throw new SecurityException("MessageDigest " + algorithm +
                    " not using wolfJCE provider");
            }

            byte[] digest = md.digest(TEST_DATA.getBytes());
            System.out.println("   " + algorithm + ": " +
                bytesToHex(digest).substring(0, 16) + "... (wolfJCE)");
        }
        System.out.println();
    }

    private void testSymmetricEncryption()
        throws Exception {

        System.out.println("Testing Symmetric Encryption (AES):");

        /* Test AES modes */
        testAesGcm();
        testAesCbc();
        testAesEcb();
        testAesCtr();
        testAesOfb();
        testAesCcm();

        System.out.println();
    }

    private void testAesGcm()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        /* Verify using wolfJCE */
        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "AES/GCM cipher not using wolfJCE provider");
        }

        /* Generate explicit IV for GCM mode */
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        /* Encrypt */
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] encrypted = cipher.doFinal(TEST_DATA.getBytes());

        /* Decrypt */
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!TEST_DATA.equals(new String(decrypted))) {
            throw new SecurityException(
                "AES-GCM encryption/decryption failed");
        }

        System.out.println(
            "   AES-GCM 256-bit: Encryption/Decryption successful (wolfJCE)");
    }

    private void testAesCbc()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        /* Verify using wolfJCE */
        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "AES/CBC cipher not using wolfJCE provider");
        }

        /* Encrypt */
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(TEST_DATA.getBytes());

        /* Decrypt */
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!TEST_DATA.equals(new String(decrypted))) {
            throw new SecurityException(
                "AES-CBC encryption/decryption failed");
        }

        System.out.println(
            "   AES-CBC 256-bit: Encryption/Decryption successful (wolfJCE)");
    }

    private void testAesEcb()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        /* Verify using wolfJCE */
        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "AES/ECB cipher not using wolfJCE provider");
        }

        /* Encrypt */
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(TEST_DATA.getBytes());

        /* Decrypt */
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!TEST_DATA.equals(new String(decrypted))) {
            throw new SecurityException(
                "AES-ECB encryption/decryption failed");
        }

        System.out.println(
            "   AES-ECB 256-bit: Encryption/Decryption successful (wolfJCE)");
    }

    private void testAesCtr()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

        /* Verify using wolfJCE */
        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "AES/CTR cipher not using wolfJCE provider");
        }

        /* Encrypt */
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(TEST_DATA.getBytes());

        /* Decrypt */
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!TEST_DATA.equals(new String(decrypted))) {
            throw new SecurityException(
                "AES-CTR encryption/decryption failed");
        }

        System.out.println(
            "   AES-CTR 256-bit: Encryption/Decryption successful (wolfJCE)");
    }

    private void testAesOfb()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");

        /* Verify it's using wolfJCE */
        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "AES/OFB cipher not using wolfJCE provider");
        }

        /* Encrypt */
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(TEST_DATA.getBytes());

        /* Decrypt */
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!TEST_DATA.equals(new String(decrypted))) {
            throw new SecurityException(
                "AES-OFB encryption/decryption failed");
        }

        System.out.println(
            "   AES-OFB 256-bit: Encryption/Decryption successful (wolfJCE)");
    }

    private void testAesCcm()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding");

        /* Verify it's using wolfJCE */
        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "AES/CCM cipher not using wolfJCE provider");
        }

        /* Generate explicit IV and parameters for CCM mode */
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        /* CCM uses similar parameters to GCM */
        GCMParameterSpec ccmSpec = new GCMParameterSpec(128, iv);

        /* Encrypt */
        cipher.init(Cipher.ENCRYPT_MODE, key, ccmSpec);
        byte[] encrypted = cipher.doFinal(TEST_DATA.getBytes());

        /* Decrypt */
        cipher.init(Cipher.DECRYPT_MODE, key, ccmSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!TEST_DATA.equals(new String(decrypted))) {
            throw new SecurityException(
                "AES-CCM encryption/decryption failed");
        }

        System.out.println(
            "   AES-CCM 256-bit: Encryption/Decryption successful (wolfJCE)");

    }

    private void testAsymmetricEncryption()
        throws Exception {

        System.out.println("Testing Asymmetric Encryption (RSA):");

        /* Test basic RSA */
        testRsaBasic();

        /* Test RSA with explicit padding */
        testRsaPkcs1Padding();

        System.out.println();
    }

    private void testRsaBasic()
        throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        Cipher cipher = Cipher.getInstance("RSA");

        /* Verify using wolfJCE */
        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "RSA cipher not using wolfJCE provider");
        }

        /* Encrypt with public key */
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted = cipher.doFinal("Hello FIPS!".getBytes());

        /* Decrypt with private key */
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!"Hello FIPS!".equals(new String(decrypted))) {
            throw new SecurityException("RSA encryption/decryption failed");
        }

        System.out.println(
            "   RSA 2048-bit: Encryption/Decryption successful (wolfJCE)");
    }

    private void testRsaPkcs1Padding()
        throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        /* Verify it's using wolfJCE */
        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "RSA/ECB/PKCS1Padding cipher not using wolfJCE provider");
        }

        /* Encrypt with public key */
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted = cipher.doFinal("Hello FIPS!".getBytes());

        /* Decrypt with private key */
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!"Hello FIPS!".equals(new String(decrypted))) {
            throw new SecurityException(
                "RSA/PKCS1 encryption/decryption failed");
        }

        System.out.println(
            "   RSA/ECB/PKCS1Padding 2048-bit: Encryption/Decryption " +
            "successful (wolfJCE)");
    }

    private void testMacOperations()
        throws Exception {

        System.out.println("Testing MAC Operations:");

        String[] algorithms = {
            "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512",
            "AESCMAC", "AES-CMAC", "AESGMAC", "AES-GMAC"
        };

        for (String algorithm : algorithms) {
            KeyGenerator keyGen;
            if (algorithm.equals("AESCMAC") ||
                algorithm.equals("AES-CMAC") ||
                algorithm.equals("AESGMAC") ||
                algorithm.equals("AES-GMAC")) {

                keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
            } else {
                keyGen = KeyGenerator.getInstance(algorithm);
            }

            SecretKey key = keyGen.generateKey();
            Mac mac = Mac.getInstance(algorithm);

            /* Verify using wolfJCE */
            if (!PROVIDER_WOLFJCE.equals(mac.getProvider().getName())) {
                throw new SecurityException("MAC " + algorithm +
                    " not using wolfJCE provider");
            }

            /* AES-GMAC requires GCMParameterSpec with IV */
            if (algorithm.equals("AESGMAC") ||
                algorithm.equals("AES-GMAC")) {

                SecureRandom random = new SecureRandom();
                byte[] iv = new byte[12];
                random.nextBytes(iv);
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
                mac.init(key, gcmSpec);
            } else {
                mac.init(key);
            }
            byte[] macValue = mac.doFinal(TEST_DATA.getBytes());

            System.out.println("   " + algorithm + ": " +
                bytesToHex(macValue).substring(0, 16) + "... (wolfJCE)");

        }
        System.out.println();
    }

    private void testDigitalSignatures()
        throws Exception {

        System.out.println("Testing Digital Signatures:");

        /* Test RSA signatures */
        testRsaSignatures();

        /* Test ECDSA signatures */
        testEcdsaSignatures();

        /* Test RSASSA-PSS signatures */
        testRsaPssSignatures();

        System.out.println();
    }

    private void testRsaSignatures()
        throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        String[] algorithms = {
            "SHA1withRSA", "SHA224withRSA", "SHA256withRSA", "SHA384withRSA",
            "SHA512withRSA", "SHA3-224withRSA", "SHA3-256withRSA",
            "SHA3-384withRSA", "SHA3-512withRSA"
        };

        for (String algorithm : algorithms) {
            Signature signature = Signature.getInstance(algorithm);

            /* Verify using wolfJCE */
            if (!PROVIDER_WOLFJCE.equals(signature.getProvider().getName())) {
                throw new SecurityException(
                    "Signature " + algorithm + " not using wolfJCE provider");
            }

            /* Sign */
            signature.initSign(keyPair.getPrivate());
            signature.update(TEST_DATA.getBytes());
            byte[] signatureBytes = signature.sign();

            /* Verify */
            signature.initVerify(keyPair.getPublic());
            signature.update(TEST_DATA.getBytes());
            boolean verified = signature.verify(signatureBytes);

            if (!verified) {
                throw new SecurityException(
                    "Signature verification failed for " + algorithm);
            }

            System.out.println("   " + algorithm +
                ": Sign/Verify successful (wolfJCE)");
        }
    }

    private void testEcdsaSignatures() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");

        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyPairGen.initialize(ecSpec);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        String[] algorithms = {
            "SHA1withECDSA", "SHA224withECDSA", "SHA256withECDSA",
            "SHA384withECDSA", "SHA512withECDSA", "SHA3-224withECDSA",
            "SHA3-256withECDSA", "SHA3-384withECDSA", "SHA3-512withECDSA"
        };

        for (String algorithm : algorithms) {
            Signature signature = Signature.getInstance(algorithm);

            /* Verify using wolfJCE */
            if (!PROVIDER_WOLFJCE.equals(signature.getProvider().getName())) {
                throw new SecurityException("Signature " + algorithm +
                    " not using wolfJCE provider");
            }

            /* Sign */
            signature.initSign(keyPair.getPrivate());
            signature.update(TEST_DATA.getBytes());
            byte[] signatureBytes = signature.sign();

            /* Verify */
            signature.initVerify(keyPair.getPublic());
            signature.update(TEST_DATA.getBytes());
            boolean verified = signature.verify(signatureBytes);

            if (!verified) {
                throw new SecurityException(
                    "Signature verification failed for " + algorithm);
            }

            System.out.println("   " + algorithm +
                ": Sign/Verify successful (wolfJCE)");
        }
    }

    private void testRsaPssSignatures()
        throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        String[] algorithms = {
            "RSASSA-PSS", "SHA224withRSA/PSS", "SHA256withRSA/PSS",
            "SHA384withRSA/PSS", "SHA512withRSA/PSS"
        };

        for (String algorithm : algorithms) {
            Signature signature = Signature.getInstance(algorithm);

            /* Verify it's using wolfJCE */
            if (!PROVIDER_WOLFJCE.equals(
                    signature.getProvider().getName())) {
                throw new SecurityException(
                    "Signature " + algorithm + " not using wolfJCE provider");
            }

            /* RSASSA-PSS requires explicit parameter specification */
            if (algorithm.equals("RSASSA-PSS")) {
                /* Set PSS parameters for basic RSASSA-PSS */
                PSSParameterSpec pssSpec = new PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
                signature.setParameter(pssSpec);
            }

            /* Sign */
            signature.initSign(keyPair.getPrivate());
            signature.update(TEST_DATA.getBytes());
            byte[] signatureBytes = signature.sign();

            /* Verify - need to set parameters again for verification */
            signature.initVerify(keyPair.getPublic());
            if (algorithm.equals("RSASSA-PSS")) {
                PSSParameterSpec pssSpec = new PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
                signature.setParameter(pssSpec);
            }
            signature.update(TEST_DATA.getBytes());
            boolean verified = signature.verify(signatureBytes);

            if (!verified) {
                throw new SecurityException(
                    "Signature verification failed for " + algorithm);
            }

            System.out.println("   " + algorithm +
                ": Sign/Verify successful (wolfJCE)");
        }
    }

    private void testKeyGeneration()
        throws Exception {

        System.out.println("Testing Key Generation:");

        /* Test symmetric key generation */
        testSymmetricKeyGeneration();

        /* Test asymmetric key generation */
        testAsymmetricKeyGeneration();

        System.out.println();
    }

    private void testSymmetricKeyGeneration()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");

        /* Test different key sizes */
        int[] keySizes = {128, 192, 256};
        for (int keySize : keySizes) {
            keyGen.init(keySize);
            SecretKey key = keyGen.generateKey();

            if (key.getEncoded().length != keySize / 8) {
                throw new SecurityException(
                    "Generated AES key has wrong size");
            }

            System.out.println("   AES-" + keySize +
                " key generated successfully");
        }
    }

    private void testAsymmetricKeyGeneration()
        throws Exception {

        /* Test multiple RSA key sizes */
        testRsaKeyGeneration();

        /* Test multiple EC curves */
        testEcKeyGeneration();
    }

    private void testRsaKeyGeneration()
        throws Exception {

        int[] keySizes = {2048, 3072, 4096};

        for (int keySize : keySizes) {
            KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
            rsaKeyGen.initialize(keySize);
            KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();
            System.out.println("   RSA-" + keySize +
                " key pair generated successfully");
        }
    }

    private void testEcKeyGeneration()
        throws Exception {

        String[] curves = {
            "secp256r1",                /* P-256 */
            "secp384r1",                /* P-384 */
            "secp521r1"                 /* P-521 */
        };

        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");

        for (String curveName : curves) {
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            ecKeyGen.initialize(ecSpec);
            KeyPair ecKeyPair = ecKeyGen.generateKeyPair();
            System.out.println("   EC-" + curveName +
                " key pair generated successfully");
        }
    }

    private void testKeyAgreement()
        throws Exception {

        System.out.println("Testing Key Agreement Protocols:");

        testEcdhKeyAgreement();

        System.out.println();
    }

    private void testEcdhKeyAgreement()
        throws Exception {

        /* Generate two EC key pairs for key agreement */
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");

        ECGenParameterSpec ecSpec;
        ecSpec = new ECGenParameterSpec("secp256r1");
        keyPairGen.initialize(ecSpec);

        KeyPair keyPairA = keyPairGen.generateKeyPair();
        KeyPair keyPairB = keyPairGen.generateKeyPair();

        /* Perform key agreement from side A */
        KeyAgreement keyAgreementA = KeyAgreement.getInstance("ECDH");

        /* Verify using wolfJCE */
        if (!PROVIDER_WOLFJCE.equals(keyAgreementA.getProvider().getName())) {
            throw new SecurityException(
                "KeyAgreement ECDH not using wolfJCE provider");
        }

        keyAgreementA.init(keyPairA.getPrivate());
        keyAgreementA.doPhase(keyPairB.getPublic(), true);
        byte[] sharedSecretA = keyAgreementA.generateSecret();

        /* Perform key agreement from side B */
        KeyAgreement keyAgreementB = KeyAgreement.getInstance("ECDH");
        keyAgreementB.init(keyPairB.getPrivate());
        keyAgreementB.doPhase(keyPairA.getPublic(), true);
        byte[] sharedSecretB = keyAgreementB.generateSecret();

        /* Verify both parties computed the same shared secret */
        if (!java.util.Arrays.equals(sharedSecretA, sharedSecretB)) {
            throw new SecurityException("ECDH shared secrets do not match");
        }

        System.out.println("   ECDH Key Agreement: Shared secret computed " +
            "successfully (wolfJCE)");
        System.out.println("   Shared secret length: " +
            sharedSecretA.length + " bytes");
        System.out.println("   Shared secret sample: " +
            bytesToHex(sharedSecretA).substring(0, 16) + "...");
    }

    private void testAlgorithmParameterGenerators()
        throws Exception {

        System.out.println("Testing Algorithm Parameter Generators:");

        /* Test DH parameter generation */
        /* TODO - wolfJCE does not implement DH AlgorithmParameterGenerator */
        //testDhParameterGeneration();

        System.out.println(
            "   DH Parameter Generation: Not implemented in wolfJCE");
        System.out.println();
    }

    private void testDhParameterGeneration()
        throws Exception {

        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH");

        /* Verify using wolfJCE */
        if (!PROVIDER_WOLFJCE.equals(paramGen.getProvider().getName())) {
            throw new SecurityException(
                "DH AlgorithmParameterGenerator not using wolfJCE provider");
        }

        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();

        System.out.println("   DH Parameter Generation: 1024-bit parameters " +
            "generated (wolfJCE)");
        System.out.println("   Algorithm: " + params.getAlgorithm());

    }

    private void testSecureRandom()
        throws Exception {

        System.out.println("Testing Secure Random:");

        /* Test default SecureRandom */
        testDefaultSecureRandom();

        /* Test specific SecureRandom algorithms if available */
        testSpecificSecureRandomAlgorithms();

        System.out.println();
    }

    private void testDefaultSecureRandom()
        throws Exception {

        /* Use default SecureRandom */
        SecureRandom random = new SecureRandom();

        /* Check what algorithm is actually being used */
        String algorithm = random.getAlgorithm();
        String providerName = random.getProvider().getName();
        System.out.println("   Default SecureRandom algorithm: " +
            algorithm + " (" + providerName + ")");

        /* Generate multiple random byte arrays and verify entropy */
        testRandomnessQuality(random, "Default SecureRandom");
    }

    private void testSpecificSecureRandomAlgorithms()
        throws Exception {

        String[] algorithms = {
            "DEFAULT", "HashDRBG"
        };

        for (String algorithm : algorithms) {
            SecureRandom random = SecureRandom.getInstance(algorithm);
            String providerName = random.getProvider().getName();
            System.out.println("   " + algorithm +
                " available from: " + providerName);

            /* Basic entropy test */
            byte[] testBytes = new byte[16];
            random.nextBytes(testBytes);
            System.out.println("     Generated entropy: " +
                bytesToHex(testBytes));
        }
    }

    private void testRandomnessQuality(SecureRandom random, String name)
        throws Exception {

        /* Generate multiple byte arrays and check for patterns */
        byte[][] samples = new byte[5][32];
        for (int i = 0; i < 5; i++) {
            random.nextBytes(samples[i]);
        }

        /* Verify no duplicate samples */
        for (int i = 0; i < samples.length; i++) {
            for (int j = i + 1; j < samples.length; j++) {
                if (java.util.Arrays.equals(samples[i], samples[j])) {
                    throw new SecurityException(
                        "SecureRandom generated duplicate samples");
                }
            }
        }

        /* Check for non-zero bytes */
        boolean hasNonZero = false;
        for (byte[] sample : samples) {
            for (byte b : sample) {
                if (b != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            if (hasNonZero) break;
        }

        if (!hasNonZero) {
            throw new SecurityException("SecureRandom generated all zeros");
        }

        /* Test different generation methods */
        int randomInt = random.nextInt();
        long randomLong = random.nextLong();
        double randomDouble = random.nextDouble();

        System.out.println("   " + name + ": Quality checks passed");
        System.out.println("   Generated 5 unique 256-bit samples");
        System.out.println("   Sample entropy methods: int=" + randomInt +
            ", long=" + randomLong + ", double=" +
            String.format("%.6f", randomDouble));
        System.out.println("   Sample bytes: " +
            bytesToHex(samples[0]).substring(0, 32) + "...");
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}

