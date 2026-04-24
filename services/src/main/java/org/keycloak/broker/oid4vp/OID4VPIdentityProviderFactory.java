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
package org.keycloak.broker.oid4vp;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class OID4VPIdentityProviderFactory extends AbstractIdentityProviderFactory<OID4VPIdentityProvider> {

    public static final String PROVIDER_ID = "oid4vp";

    @Override
    public String getName() {
        return "OpenID for Verifiable Presentations";
    }

    @Override
    public OID4VPIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new OID4VPIdentityProvider(session, new OID4VPIdentityProviderConfig(model));
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new OID4VPIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
