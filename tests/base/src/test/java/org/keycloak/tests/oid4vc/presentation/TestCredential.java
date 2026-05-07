package org.keycloak.tests.oid4vc.presentation;

public class TestCredential {

    private final String sdJwt;

    TestCredential(String sdJwt) {
        this.sdJwt = sdJwt;
    }

    String sdJwt() {
        return sdJwt;
    }
}
