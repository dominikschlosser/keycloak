package org.keycloak.tests.conformance.oid4vci;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.def.DefaultCryptoProvider;
import org.keycloak.common.util.PemUtils;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

final class OID4VCITestSigningKey {

    static final String KEY_ALIAS = "oid4vci-conformance-signing";
    static final String PASSWORD = "password";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Material MATERIAL = create();

    private OID4VCITestSigningKey() {
    }

    static String keyStorePath() {
        return MATERIAL.keyStorePath().toString();
    }

    static String caCertificatePem() {
        return MATERIAL.caCertificatePem();
    }

    private static Material create() {
        try {
            if (!CryptoIntegration.isInitialised()) {
                CryptoIntegration.setProvider(new DefaultCryptoProvider());
            }

            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("EC");
            keyGenerator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair caKeyPair = keyGenerator.generateKeyPair();
            KeyPair leafKeyPair = keyGenerator.generateKeyPair();

            X509Certificate caCertificate = generateCaCertificate(caKeyPair);
            X509Certificate leafCertificate = generateLeafCertificate(leafKeyPair, caKeyPair, caCertificate);

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry(KEY_ALIAS, leafKeyPair.getPrivate(), PASSWORD.toCharArray(),
                    new Certificate[] { leafCertificate, caCertificate });

            Path keyStorePath = Files.createTempFile("keycloak-oid4vci-conformance-signing", ".p12");
            try (OutputStream output = Files.newOutputStream(keyStorePath)) {
                keyStore.store(output, PASSWORD.toCharArray());
            }
            keyStorePath.toFile().deleteOnExit();

            String caCertificatePem = PemUtils.addCertificateBeginEnd(PemUtils.encodeCertificate(caCertificate));
            return new Material(keyStorePath, caCertificatePem);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create OID4VCI conformance signing key", e);
        }
    }

    private static X509Certificate generateCaCertificate(KeyPair caKeyPair) throws Exception {
        X500Name caName = new X500Name("CN=OID4VCI Conformance CA");
        X509v3CertificateBuilder builder = certificateBuilder(caName, caName, caKeyPair);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return sign(builder, caKeyPair);
    }

    private static X509Certificate generateLeafCertificate(KeyPair leafKeyPair, KeyPair caKeyPair,
            X509Certificate caCertificate) throws Exception {
        X500Name caName = new X500Name(caCertificate.getSubjectX500Principal().getName());
        X500Name leafName = new X500Name("CN=OID4VCI Conformance Issuer");
        X509v3CertificateBuilder builder = certificateBuilder(caName, leafName, leafKeyPair);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        return sign(builder, caKeyPair);
    }

    private static X509v3CertificateBuilder certificateBuilder(X500Name issuer, X500Name subject, KeyPair keyPair) {
        Instant now = Instant.now();
        return new X509v3CertificateBuilder(
                issuer,
                new BigInteger(160, RANDOM),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
    }

    private static X509Certificate sign(X509v3CertificateBuilder builder, KeyPair signingKeyPair) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(signingKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private record Material(Path keyStorePath, String caCertificatePem) {
    }
}
