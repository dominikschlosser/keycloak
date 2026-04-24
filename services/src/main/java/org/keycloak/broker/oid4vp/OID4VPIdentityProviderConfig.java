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

import org.keycloak.models.IdentityProviderModel;

public class OID4VPIdentityProviderConfig extends IdentityProviderModel {

    public static final String REQUEST_OBJECT_LIFESPAN = "requestObjectLifespan";
    public static final int DEFAULT_REQUEST_OBJECT_LIFESPAN = 300;

    public OID4VPIdentityProviderConfig() {
    }

    public OID4VPIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public int getRequestObjectLifespan() {
        String configured = getConfig().get(REQUEST_OBJECT_LIFESPAN);
        if (configured == null) {
            return DEFAULT_REQUEST_OBJECT_LIFESPAN;
        }

        try {
            return Integer.parseInt(configured);
        } catch (NumberFormatException nfe) {
            return DEFAULT_REQUEST_OBJECT_LIFESPAN;
        }
    }
}
