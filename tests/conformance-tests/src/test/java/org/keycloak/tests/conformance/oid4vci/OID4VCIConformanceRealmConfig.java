package org.keycloak.tests.conformance.oid4vci;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.keycloak.OID4VCConstants;
import org.keycloak.VCFormat;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.common.Profile;
import org.keycloak.constants.OID4VCIConstants;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.GeneratedRsaEncKeyProviderFactory;
import org.keycloak.keys.JavaKeystoreKeyProviderFactory;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.issuance.mappers.OID4VCGeneratedIdMapper;
import org.keycloak.protocol.oid4vc.issuance.mappers.OID4VCIssuedAtTimeClaimMapper;
import org.keycloak.protocol.oid4vc.model.CredentialScopeRepresentation;
import org.keycloak.protocol.oid4vc.model.DisplayObject;
import org.keycloak.representations.idm.ComponentExportRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.realm.UserBuilder;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.util.JsonSerialization;

import static org.keycloak.OID4VCConstants.OID4VCI_ENABLED_ATTRIBUTE_KEY;
import static org.keycloak.models.Constants.CREATE_DEFAULT_CLIENT_SCOPES;

public final class OID4VCIConformanceRealmConfig implements RealmConfig {

    public static final String KEYCLOAK_EXTERNAL_BASE_URL_PROPERTY = "keycloak.conformance.keycloakBaseUrl";
    public static final String KEYCLOAK_EXTERNAL_HOST = "host.testcontainers.internal";
    public static final String REALM = "oid4vci";
    public static final String HOLDER = "alice";
    public static final String PASSWORD = "password";
    public static final String CLIENT = "oid4vci-client";
    public static final String CLIENT2 = "oid4vci-client2";
    public static final String SD_JWT_SCOPE = "conformance_sd_jwt_vc";
    public static final String CREDENTIAL_CONFIGURATION_ID = "conformance_sd_jwt_vc";

    @Override
    public RealmBuilder configure(RealmBuilder realm) {
        realm.name(REALM)
                .eventsEnabled(true)
                .eventsListeners("jboss-logging")
                .verifiableCredentialsEnabled(true)
                .attribute(CREATE_DEFAULT_CLIENT_SCOPES, "true")
                .defaultSignatureAlgorithm(Algorithm.ES256)
                .clientScopes(createSdJwtCredentialScope())
                .users(UserBuilder.create()
                        .username(HOLDER)
                        .enabled(true)
                        .email("alice@example.test")
                        .emailVerified(true)
                        .firstName("Alice")
                        .lastName("Wonderland")
                        .password(PASSWORD)
                        .attribute("did", "did:key:alice")
                        .attribute("address_street_address", "221B Baker Street")
                        .attribute("address_locality", "London")
                        .realmRoles("account", "manage-account", "view-profile")
                        .verifiableCredential(SD_JWT_SCOPE)
                        .build())
                .clients(conformanceClient(CLIENT, false), conformanceClient(CLIENT2, true))
                .update(rep -> {
                    MultivaluedHashMap<String, ComponentExportRepresentation> components = rep.getComponents();
                    if (components == null) {
                        components = new MultivaluedHashMap<>();
                        rep.setComponents(components);
                    }
                    components.add(KeyProvider.class.getName(), conformanceSigningKeyProvider());
                    components.add(KeyProvider.class.getName(), conformanceEncryptionKeyProvider());
                });
        return realm;
    }

    private ClientBuilder conformanceClient(String clientId, boolean wildcardRedirect) {
        return ClientBuilder.create(clientId)
                .serviceAccountsEnabled(false)
                .directAccessGrantsEnabled(false)
                .authenticatorType("client-secret")
                .defaultClientScopes("basic", "profile", "roles")
                .optionalClientScopes(SD_JWT_SCOPE, "email")
                .attribute(OID4VCI_ENABLED_ATTRIBUTE_KEY, "true")
                .redirectUris("https://conformance.invalid/test/a/keycloak/callback" + (wildcardRedirect ? "*" : ""))
                .webOrigins("https://conformance.invalid");
    }

    private CredentialScopeRepresentation createSdJwtCredentialScope() {
        CredentialScopeRepresentation scope = new CredentialScopeRepresentation(SD_JWT_SCOPE)
                .setIncludeInTokenScope(true)
                .setExpiryInSeconds(300)
                .setCredentialConfigurationId(CREDENTIAL_CONFIGURATION_ID)
                .setCredentialIdentifier(CREDENTIAL_CONFIGURATION_ID)
                .setFormat(VCFormat.SD_JWT_VC)
                .setSigningAlg(Algorithm.ES256)
                .setVct("https://credentials.example.com/SD-JWT-Credential");

        scope.setDisplay(JsonSerialization.valueAsString(List.of(new DisplayObject().setName(CREDENTIAL_CONFIGURATION_ID).setLocale("en-EN"))));
        scope.setProtocolMappers(protocolMappers(SD_JWT_SCOPE));

        Map<String, String> attributes = Optional.ofNullable(scope.getAttributes()).orElseGet(HashMap::new);
        attributes.put(CredentialScopeModel.VC_BINDING_REQUIRED, "true");
        attributes.put(CredentialScopeModel.VC_BINDING_REQUIRED_PROOF_TYPES, "jwt");
        attributes.put(CredentialScopeModel.VC_CRYPTOGRAPHIC_BINDING_METHODS, CredentialScopeModel.CRYPTOGRAPHIC_BINDING_METHODS_DEFAULT);
        scope.setAttributes(attributes);
        return scope;
    }

    private ComponentExportRepresentation conformanceSigningKeyProvider() {
        ComponentExportRepresentation keyProvider = new ComponentExportRepresentation();
        keyProvider.setName("oid4vci-conformance-signing-key");
        keyProvider.setId(UUID.randomUUID().toString());
        keyProvider.setProviderId(JavaKeystoreKeyProviderFactory.ID);
        keyProvider.setConfig(new MultivaluedHashMap<>(Map.of(
                Attributes.PRIORITY_KEY, List.of("0"),
                Attributes.ENABLED_KEY, List.of("true"),
                Attributes.ACTIVE_KEY, List.of("true"),
                Attributes.ALGORITHM_KEY, List.of(Algorithm.ES256),
                Attributes.KEY_USE, List.of(KeyUse.SIG.name()),
                JavaKeystoreKeyProviderFactory.KEYSTORE_KEY, List.of(OID4VCITestSigningKey.keyStorePath()),
                JavaKeystoreKeyProviderFactory.KEYSTORE_PASSWORD_KEY, List.of(OID4VCITestSigningKey.PASSWORD),
                JavaKeystoreKeyProviderFactory.KEYSTORE_TYPE_KEY, List.of("PKCS12"),
                JavaKeystoreKeyProviderFactory.KEY_ALIAS_KEY, List.of(OID4VCITestSigningKey.KEY_ALIAS),
                JavaKeystoreKeyProviderFactory.KEY_PASSWORD_KEY, List.of(OID4VCITestSigningKey.PASSWORD))));
        return keyProvider;
    }

    private ComponentExportRepresentation conformanceEncryptionKeyProvider() {
        ComponentExportRepresentation keyProvider = new ComponentExportRepresentation();
        keyProvider.setName("oid4vci-conformance-encryption-key");
        keyProvider.setId(UUID.randomUUID().toString());
        keyProvider.setProviderId(GeneratedRsaEncKeyProviderFactory.ID);
        keyProvider.setConfig(new MultivaluedHashMap<>(Map.of(
                Attributes.PRIORITY_KEY, List.of("0"),
                Attributes.ENABLED_KEY, List.of("true"),
                Attributes.ACTIVE_KEY, List.of("true"),
                Attributes.ALGORITHM_KEY, List.of(Algorithm.RSA_OAEP),
                Attributes.KEY_SIZE_KEY, List.of("2048"))));
        return keyProvider;
    }

    private List<ProtocolMapperRepresentation> protocolMappers(String scopeName) {
        return List.of(
                mapper("did-mapper", "oid4vc-subject-id-mapper", Map.of("claim.name", OID4VCConstants.CLAIM_NAME_SUBJECT_ID, "userAttribute", "did")),
                mapper("email-mapper", "oid4vc-user-attribute-mapper", Map.of("claim.name", "email", "userAttribute", "email")),
                mapper("first-name-mapper", "oid4vc-user-attribute-mapper", Map.of("claim.name", "firstName", "userAttribute", "firstName")),
                mapper("last-name-mapper", "oid4vc-user-attribute-mapper", Map.of("claim.name", "lastName", "userAttribute", "lastName")),
                mapper("address-street-mapper", "oid4vc-user-attribute-mapper",
                        Map.of("claim.name", "address.street_address", "userAttribute", "address_street_address")),
                mapper("address-locality-mapper", "oid4vc-user-attribute-mapper",
                        Map.of("claim.name", "address.locality", "userAttribute", "address_locality")),
                mapper("generated-id-mapper", "oid4vc-generated-id-mapper", Map.of(OID4VCGeneratedIdMapper.CLAIM_NAME, "jti")),
                mapper("static-scope-mapper", "oid4vc-static-claim-mapper", Map.of("claim.name", "scope-name", "staticValue", scopeName)),
                mapper("issued-at-mapper", "oid4vc-issued-at-time-claim-mapper", Map.of(
                        OID4VCIssuedAtTimeClaimMapper.CLAIM_NAME, "iat",
                        OID4VCIssuedAtTimeClaimMapper.TRUNCATE_TO_TIME_UNIT_KEY, "HOURS",
                        OID4VCIssuedAtTimeClaimMapper.VALUE_SOURCE, "COMPUTE")),
                mapper("not-before-mapper", "oid4vc-issued-at-time-claim-mapper", Map.of(
                        OID4VCIssuedAtTimeClaimMapper.CLAIM_NAME, "nbf",
                        OID4VCIssuedAtTimeClaimMapper.VALUE_SOURCE, "COMPUTE")));
    }

    private ProtocolMapperRepresentation mapper(String name, String type, Map<String, String> config) {
        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setName(name);
        mapper.setId(UUID.randomUUID().toString());
        mapper.setProtocol(OID4VCIConstants.OID4VC_PROTOCOL);
        mapper.setProtocolMapper(type);
        mapper.setConfig(config);
        return mapper;
    }

    public static class ServerConfig implements KeycloakServerConfig {

        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.features(Profile.Feature.OID4VC_VCI, Profile.Feature.CLIENT_AUTH_ABCA)
                    .option("hostname", keycloakExternalBaseUrl());
        }
    }

    public static String keycloakExternalBaseUrl() {
        return System.getProperty(KEYCLOAK_EXTERNAL_BASE_URL_PROPERTY, "https://" + KEYCLOAK_EXTERNAL_HOST + ":8443");
    }
}
