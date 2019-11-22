package com.workday;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;

public class Main {

    private static final String WORKDAY_CERT_ALIAS = "powerOfOne";
    private static final String DEFAULT_ALGORITHM = "SHA384withRSA";

    public static void main(String[] args) {
        try {
            final KeyStore keyStore = KeyStore.getInstance("Windows-ROOT");
            keyStore.load(null, null);
            System.out.println("Provider Class Name:" + keyStore.getProvider().getClass().getName());


            System.out.println("contain aliass:" + keyStore.containsAlias(WORKDAY_CERT_ALIAS));
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
            final KeyPair keyPair =  keyPairGenerator.generateKeyPair();

            final X509v3CertificateBuilder v3CertificateBuilder = new JcaX509v3CertificateBuilder(
                    new X500Name("CN=AgentSelfsignCA"),
                    BigInteger.valueOf(System.currentTimeMillis()),
                    new Date(System.currentTimeMillis() - 1000L * 5),
                    new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 3650)), // ten years
                    new X500Name("CN=Agent"),
                    keyPair.getPublic());

            final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(DEFAULT_ALGORITHM);

            X509Certificate x509Cert =  new JcaX509CertificateConverter()
                    .getCertificate(v3CertificateBuilder.build(signerBuilder.build(keyPair.getPrivate())));

            keyStore.setCertificateEntry(WORKDAY_CERT_ALIAS, x509Cert);
            keyStore.setKeyEntry(WORKDAY_CERT_ALIAS, keyPair.getPrivate(), "".toCharArray(), new X509Certificate[]{x509Cert});
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            System.out.println("error:" + e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }
    }
}
