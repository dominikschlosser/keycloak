package org.keycloak.tests.conformance.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

public final class ConformanceProfileLoader {

    public static final String PROFILE_PROPERTY = "keycloak.conformance.profile";
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .findAndRegisterModules()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    private ConformanceProfileLoader() {
    }

    public static List<ConformanceProfile> loadSelectedProfiles() {
        String profile = System.getProperty(PROFILE_PROPERTY);
        if (profile == null || profile.isBlank()) {
            return loadAll();
        }
        return Arrays.stream(profile.split(","))
                .map(String::trim)
                .filter(name -> !name.isBlank())
                .map(ConformanceProfileLoader::load)
                .toList();
    }

    public static List<ConformanceProfile> loadAll() {
        return loadProfileNames().stream()
                .map(ConformanceProfileLoader::load)
                .toList();
    }

    public static ConformanceProfile load(String profile) {
        String resource = "/conformance/" + profile + ".json";
        try (InputStream input = ConformanceProfileLoader.class.getResourceAsStream(resource)) {
            if (input == null) {
                throw new IllegalArgumentException("Unknown conformance profile: " + profile);
            }
            return MAPPER.readValue(input, ConformanceProfile.class);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load conformance profile: " + profile, e);
        }
    }

    public static ObjectMapper mapper() {
        return MAPPER;
    }

    private static List<String> loadProfileNames() {
        try (InputStream input = ConformanceProfileLoader.class.getResourceAsStream("/conformance/profiles.json")) {
            if (input == null) {
                throw new IllegalStateException("Missing conformance profile index: /conformance/profiles.json");
            }
            ArrayNode profiles = (ArrayNode) MAPPER.readTree(input);
            return profiles.findValuesAsText("id");
        } catch (IOException e) {
            throw new RuntimeException("Failed to load conformance profile index", e);
        }
    }
}
