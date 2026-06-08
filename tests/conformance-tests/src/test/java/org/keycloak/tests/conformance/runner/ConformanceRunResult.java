package org.keycloak.tests.conformance.runner;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.databind.JsonNode;

public record ConformanceRunResult(List<ConformanceModuleResult> modules) {

    public boolean passed() {
        return modules.stream().allMatch(ConformanceModuleResult::passed);
    }

    public String failureSummary() {
        return modules.stream()
                .filter(module -> !module.passed())
                .map(this::formatFailure)
                .collect(Collectors.joining("\n\n"));
    }

    private String formatFailure(ConformanceModuleResult module) {
        return "Conformance module failed"
                + "\n  plan=" + module.plan()
                + "\n  planVariant=" + module.planVariant()
                + "\n  module=" + module.module()
                + "\n  moduleVariant=" + module.moduleVariant()
                + "\n  planId=" + module.planId()
                + "\n  moduleId=" + module.moduleId()
                + "\n  status=" + module.status()
                + "\n  result=" + module.result()
                + "\n  logExcerpt=" + failureLogExcerpt(module.logs());
    }

    private String failureLogExcerpt(JsonNode logs) {
        if (logs == null || !logs.isArray()) {
            return "<no logs>";
        }
        String excerpt = StreamSupport.stream(logs.spliterator(), false)
                .filter(log -> "FAILURE".equals(log.path("result").asText())
                        || "WARNING".equals(log.path("result").asText()))
                .limit(20)
                .map(this::formatLog)
                .collect(Collectors.joining(" | "));
        return excerpt.isBlank() ? "<no failure or warning log entries>" : excerpt;
    }

    private String formatLog(JsonNode log) {
        String source = log.path("src").asText(log.path("condition").asText(""));
        String message = log.path("msg").asText(log.path("message").asText(log.path("error").asText("")));
        return log.path("result").asText() + ":" + source + " " + message;
    }
}
