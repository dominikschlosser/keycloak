package org.keycloak.tests.conformance.oid4vci;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testframework.annotations.InjectAdminClient;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.https.CertificatesConfig;
import org.keycloak.testframework.https.CertificatesConfigBuilder;
import org.keycloak.testframework.https.InjectCertificates;
import org.keycloak.testframework.https.ManagedCertificates;
import org.keycloak.testframework.injection.LifeCycle;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.server.KeycloakUrls;
import org.keycloak.tests.conformance.config.ConformanceProfile;
import org.keycloak.tests.conformance.config.ConformanceProfileLoader;
import org.keycloak.tests.conformance.containers.OpenIdConformanceSuite;
import org.keycloak.tests.conformance.runner.ConformanceApiClient.ModuleExecution;
import org.keycloak.tests.conformance.runner.ConformanceRunResult;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.Testcontainers;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.tests.conformance.oid4vci.OID4VCIConformanceRealmConfig.KEYCLOAK_EXTERNAL_BASE_URL_PROPERTY;
import static org.keycloak.tests.conformance.oid4vci.OID4VCIConformanceRealmConfig.KEYCLOAK_EXTERNAL_HOST;

@KeycloakIntegrationTest(config = OID4VCIConformanceRealmConfig.ServerConfig.class)
public class OID4VCIConformanceTest {

    private static final String TRUST_IDP_ALIAS = "conformance-client-attester";
    private static final String TRUST_IDP_PROVIDER = "default-trust";
    private static final String TRUSTED_JWKS = "trustedJwks";
    private static final String ATTESTER_TRUST_IDPS = "attester_trust_idps";
    private static final List<String> MANAGED_CLIENT_ATTRIBUTES = List.of(
            ATTESTER_TRUST_IDPS,
            "request.object.required",
            "tls.client.certificate.bound.access.tokens");
    private static final List<String> MANAGED_REALM_ATTRIBUTES = List.of(
            OID4VCIssuerWellKnownProvider.SIGNED_METADATA_ALG_ATTR,
            OID4VCIssuerWellKnownProvider.SIGNED_METADATA_LIFESPAN_ATTR);

    @InjectRealm(config = OID4VCIConformanceRealmConfig.class, lifecycle = LifeCycle.METHOD)
    ManagedRealm realm;

    @InjectAdminClient
    org.keycloak.admin.client.Keycloak adminClient;

    @InjectKeycloakUrls
    KeycloakUrls keycloakUrls;

    @InjectCertificates(config = TlsCertificates.class)
    ManagedCertificates certificates;

    @ParameterizedTest(name = "{0}")
    @MethodSource("profiles")
    public void oid4vciConformance(ConformanceProfile profile) {
        exposeKeycloakHostPort();

        try (OpenIdConformanceSuite suite = OpenIdConformanceSuite.start(profile)) {
            JsonNode suiteConfig = suiteConfig(profile, suite.internalBaseUri());
            ConformanceRunResult result = suite.client().run(profile, suiteConfig,
                    execution -> configureRealmForConformance(keycloakConfig(profile, execution), suite.internalBaseUri()));
            assertTrue(result.passed(), result.failureSummary());
        }
    }

    static List<ConformanceProfile> profiles() {
        return ConformanceProfileLoader.loadSelectedProfiles();
    }

    private void exposeKeycloakHostPort() {
        URI baseUri = URI.create(keycloakUrls.getBase());
        Testcontainers.exposeHostPorts(baseUri.getPort());
    }

    private void configureRealmForConformance(ConformanceProfile.KeycloakConfig keycloak, URI conformanceBaseUri) {
        RealmResource realmResource = realm.admin();
        configureRealmAttributes(realmResource, keycloak);
        configureTrustIdentityProvider(realmResource);

        String callback = conformanceBaseUri + "/test/a/keycloak/callback";
        String origin = conformanceBaseUri.toString();
        for (ConformanceProfile.ClientConfig clientConfig : keycloak.clients()) {
            ClientRepresentation client = realmResource.clients().findByClientId(clientConfig.clientId()).get(0);
            client.setConsentRequired(false);
            client.setWebOrigins(List.of(origin));
            client.setRedirectUris(List.of(callback + (clientConfig.redirectUriWildcard() ? "*" : "")));
            if (clientConfig.authenticatorType() != null && !clientConfig.authenticatorType().isBlank()) {
                client.setClientAuthenticatorType(clientConfig.authenticatorType());
            }
            Map<String, String> attributes = new HashMap<>(client.getAttributes() == null ? Map.of() : client.getAttributes());
            MANAGED_CLIENT_ATTRIBUTES.forEach(attributes::remove);
            attributes.putAll(clientConfig.attributes() == null ? Map.of() : clientConfig.attributes());
            client.setAttributes(attributes);
            realmResource.clients().get(client.getId()).update(client);
        }
    }

    private void configureRealmAttributes(RealmResource realmResource, ConformanceProfile.KeycloakConfig keycloak) {
        RealmRepresentation representation = realmResource.toRepresentation();
        Map<String, String> attributes = new HashMap<>(representation.getAttributes() == null ? Map.of() : representation.getAttributes());
        MANAGED_REALM_ATTRIBUTES.forEach(attributes::remove);
        attributes.putAll(keycloak.realmAttributes() == null ? Map.of() : keycloak.realmAttributes());
        representation.setAttributes(attributes);
        realmResource.update(representation);
    }

    private void configureTrustIdentityProvider(RealmResource realmResource) {
        IdentityProviderRepresentation trust = new IdentityProviderRepresentation();
        trust.setAlias(TRUST_IDP_ALIAS);
        trust.setProviderId(TRUST_IDP_PROVIDER);
        trust.setEnabled(true);
        trust.setConfig(Map.of(TRUSTED_JWKS, attesterJwks().toString()));

        if (realmResource.identityProviders().findAll().stream().anyMatch(idp -> TRUST_IDP_ALIAS.equals(idp.getAlias()))) {
            realmResource.identityProviders().get(TRUST_IDP_ALIAS).update(trust);
        } else {
            realmResource.identityProviders().create(trust).close();
        }
    }

    private JsonNode suiteConfig(ConformanceProfile profile, URI conformanceBaseUri) {
        ObjectNode config = ConformanceProfileLoader.mapper().createObjectNode();
        config.put("alias", "keycloak");

        ObjectNode vci = config.putObject("vci");
        vci.put("credential_issuer_url", keycloakBaseUriFromConformance() + "/realms/" + profile.keycloak().realm());
        vci.put("credential_configuration_id", profile.keycloak().credentialConfigurationId());
        vci.put("client_attestation_issuer", "https://example.com/client-attester");
        vci.set("client_attester_keys_jwks", attesterJwks());
        vci.set("key_attestation_jwks", attesterJwks());

        ObjectNode credential = config.putObject("credential");
        credential.put("trust_anchor_pem", OID4VCITestSigningKey.caCertificatePem());
        credential.put("status_list_trust_anchor_pem", OID4VCITestSigningKey.caCertificatePem());

        config.putObject("client").put("client_id", profile.keycloak().clients().get(0).clientId());
        if (profile.keycloak().clients().size() > 1) {
            config.putObject("client2").put("client_id", profile.keycloak().clients().get(1).clientId());
        }

        ArrayNode browser = config.putArray("browser");
        ObjectNode flow = browser.addObject();
        flow.put("match", "https://*/realms/" + profile.keycloak().realm() + "/protocol/openid-connect/auth*");
        ArrayNode tasks = flow.putArray("tasks");
        ObjectNode login = tasks.addObject();
        login.put("task", "Keycloak Login");
        login.put("match", "https://*/realms/" + profile.keycloak().realm() + "/login-actions/authenticate*");
        login.put("optional", true);
        ArrayNode loginCommands = login.putArray("commands");
        loginCommands.addArray().add("text").add("id").add("username").add(profile.keycloak().holderUsername());
        loginCommands.addArray().add("text").add("id").add("password").add(profile.keycloak().holderPassword());
        loginCommands.addArray().add("click").add("id").add("kc-login");

        ObjectNode complete = tasks.addObject();
        complete.put("task", "Verify Complete");
        complete.put("match", conformanceBaseUri + "/test/a/keycloak/callback*");
        complete.putArray("commands").addArray().add("wait").add("id").add("submission_complete").add(10);
        return config;
    }

    private URI keycloakBaseUriFromConformance() {
        String override = System.getProperty(KEYCLOAK_EXTERNAL_BASE_URL_PROPERTY);
        if (override != null && !override.isBlank()) {
            return URI.create(override);
        }
        URI baseUri = URI.create(keycloakUrls.getBase());
        return URI.create(baseUri.getScheme() + "://" + KEYCLOAK_EXTERNAL_HOST + ":" + baseUri.getPort());
    }

    private JsonNode attesterJwks() {
        try (InputStream input = getClass().getResourceAsStream("/conformance/oid4vci-attester-jwks.json")) {
            if (input == null) {
                throw new IllegalStateException("Missing OID4VCI conformance attester JWKS");
            }
            return ConformanceProfileLoader.mapper().readTree(input);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load OID4VCI conformance attester JWKS", e);
        }
    }

    private ConformanceProfile.KeycloakConfig keycloakConfig(ConformanceProfile profile, ModuleExecution execution) {
        ConformanceProfile.KeycloakConfig baseline = profile.keycloak();
        Map<String, String> realmAttributes = new HashMap<>(baseline.realmAttributes() == null ? Map.of() : baseline.realmAttributes());
        Map<String, ConformanceProfile.ClientConfig> clients = new LinkedHashMap<>();
        baseline.clients().forEach(client -> clients.put(client.clientId(), client));

        applyKeycloakOverride(realmAttributes, clients, execution.plan().keycloak());
        applyKeycloakOverride(realmAttributes, clients, execution.planVariant().keycloak());
        applyKeycloakOverride(realmAttributes, clients, execution.module().keycloak());
        applyKeycloakOverride(realmAttributes, clients, execution.moduleVariant().keycloak());

        return new ConformanceProfile.KeycloakConfig(
                baseline.realm(),
                baseline.holderUsername(),
                baseline.holderPassword(),
                baseline.credentialConfigurationId(),
                realmAttributes,
                List.copyOf(clients.values()));
    }

    private void applyKeycloakOverride(Map<String, String> realmAttributes,
            Map<String, ConformanceProfile.ClientConfig> clients,
            ConformanceProfile.KeycloakOverride override) {
        if (override == null) {
            return;
        }
        realmAttributes.putAll(override.realmAttributes() == null ? Map.of() : override.realmAttributes());
        if (override.clients() == null) {
            return;
        }
        for (ConformanceProfile.ClientOverride clientOverride : override.clients()) {
            ConformanceProfile.ClientConfig client = clients.get(clientOverride.clientId());
            if (client == null) {
                throw new IllegalArgumentException("Keycloak override references unknown client: " + clientOverride.clientId());
            }
            Map<String, String> attributes = new HashMap<>(client.attributes() == null ? Map.of() : client.attributes());
            attributes.putAll(clientOverride.attributes() == null ? Map.of() : clientOverride.attributes());
            clients.put(client.clientId(), new ConformanceProfile.ClientConfig(
                    client.clientId(),
                    client.redirectUriWildcard(),
                    clientOverride.authenticatorType() == null ? client.authenticatorType() : clientOverride.authenticatorType(),
                    attributes));
        }
    }

    public static class TlsCertificates implements CertificatesConfig {

        @Override
        public CertificatesConfigBuilder configure(CertificatesConfigBuilder config) {
            return config.tlsEnabled(true);
        }
    }
}
