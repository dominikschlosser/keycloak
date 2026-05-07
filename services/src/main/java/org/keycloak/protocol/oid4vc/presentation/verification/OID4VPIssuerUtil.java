/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.protocol.oid4vc.presentation.verification;

import java.util.Optional;

import org.keycloak.OID4VCConstants;
import org.keycloak.common.VerificationException;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.consumer.HttpDataFetcher;
import org.keycloak.services.Urls;

import com.fasterxml.jackson.databind.JsonNode;

class OID4VPIssuerUtil {

    static String issuer(IssuerSignedJWT issuerSignedJWT) throws VerificationException {
        String issuer = Optional.ofNullable(issuerSignedJWT.getPayload().get(OID4VCConstants.CLAIM_NAME_ISSUER))
                .map(JsonNode::asText)
                .orElse(null);
        if (issuer == null || issuer.isBlank()) {
            throw new VerificationException("Missing SD-JWT issuer claim");
        }
        return issuer;
    }

    static String algorithm(IssuerSignedJWT issuerSignedJWT) throws VerificationException {
        JWSHeader header = issuerSignedJWT.getJwsHeader();
        String algorithm = header != null && header.getAlgorithm() != null ? header.getAlgorithm().name() : null;
        if (algorithm == null) {
            throw new VerificationException("Missing SD-JWT issuer signature algorithm");
        }
        return algorithm;
    }

    static boolean isRealmIssuer(KeycloakSession session, String issuer) {
        if (session == null || session.getContext() == null || session.getContext().getRealm() == null
                || session.getContext().getUri() == null) {
            return false;
        }

        RealmModel realm = session.getContext().getRealm();
        String realmIssuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        return realmIssuer.equals(issuer);
    }

    static HttpDataFetcher httpDataFetcher(KeycloakSession session) {
        return uri -> SimpleHttp.create(session).doGet(uri).acceptJson().asJson();
    }

    private OID4VPIssuerUtil() {
    }
}
