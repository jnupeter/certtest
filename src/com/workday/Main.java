package com.workday;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class Main {

    private static final String WORKDAY_CERT_ALIAS = "powerOfOne";
    public static void main(String[] args) {
        try {
            final KeyStore keyStore = KeyStore.getInstance("Windows-ROOT");
            keyStore.load(null, null);
            System.out.println("Provider Class Name:" + keyStore.getProvider().getClass().getName());

            System.out.println("contain aliass:" + keyStore.containsAlias(WORKDAY_CERT_ALIAS));
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            System.out.println("error:" + e.getMessage());
        }
    }
}
