package org.keycloak.tests.conformance.runner;

import com.fasterxml.jackson.databind.JsonNode;

public record ConformanceModuleResult(
        String plan,
        String planVariant,
        String module,
        String moduleVariant,
        String planId,
        String moduleId,
        String status,
        String result,
        JsonNode logs) {

    public boolean passed() {
        return "FINISHED".equals(status) && "PASSED".equals(result);
    }
}
