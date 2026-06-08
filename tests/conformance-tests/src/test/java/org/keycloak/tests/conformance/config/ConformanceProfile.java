package org.keycloak.tests.conformance.config;

import java.util.List;
import java.util.Map;

public record ConformanceProfile(String id, KeycloakConfig keycloak, ConformanceConfig conformance) {

    @Override
    public String toString() {
        return id;
    }

    public record KeycloakConfig(
            String realm,
            String holderUsername,
            String holderPassword,
            String credentialConfigurationId,
            Map<String, String> realmAttributes,
            List<ClientConfig> clients) {
    }

    public record ClientConfig(String clientId, boolean redirectUriWildcard, String authenticatorType, Map<String, String> attributes) {
    }

    public record ConformanceConfig(
            String imageTag,
            List<PlanConfig> plans) {
    }

    public record PlanConfig(String name, List<VariantConfig> variants, KeycloakOverride keycloak, List<ModuleConfig> modules) {
    }

    public record ModuleConfig(String name, List<VariantConfig> variants, KeycloakOverride keycloak) {
    }

    public record VariantConfig(String id, Map<String, String> values, KeycloakOverride keycloak) {
    }

    public record KeycloakOverride(Map<String, String> realmAttributes, List<ClientOverride> clients) {
    }

    public record ClientOverride(String clientId, String authenticatorType, Map<String, String> attributes) {
    }
}
