package org.keycloak.tests.conformance.runner;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.keycloak.tests.conformance.config.ConformanceProfile;
import org.keycloak.tests.conformance.config.ConformanceProfile.ModuleConfig;
import org.keycloak.tests.conformance.config.ConformanceProfile.PlanConfig;
import org.keycloak.tests.conformance.config.ConformanceProfile.VariantConfig;
import org.keycloak.tests.conformance.config.ConformanceProfileLoader;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

public final class ConformanceApiClient {

    private final URI baseUri;
    private final HttpClient httpClient;

    public ConformanceApiClient(URI baseUri) {
        this.baseUri = baseUri;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(20))
                .sslContext(trustAllSslContext())
                .build();
    }

    public void waitUntilAvailable(Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        RuntimeException lastFailure = null;
        while (System.nanoTime() < deadline) {
            try {
                HttpResponse<String> response = send(request("/api/runner/available").GET().build());
                if (response.statusCode() == 200) {
                    return;
                }
                lastFailure = new IllegalStateException("Conformance server returned HTTP " + response.statusCode());
            } catch (RuntimeException e) {
                lastFailure = e;
            }
            sleep(Duration.ofSeconds(2));
        }
        throw new IllegalStateException("Conformance server did not become available at " + baseUri, lastFailure);
    }

    public ConformanceRunResult run(ConformanceProfile profile, JsonNode suiteConfig, Consumer<ModuleExecution> beforeModule) {
        List<ConformanceModuleResult> results = new ArrayList<>();

        for (PlanConfig planConfig : profile.conformance().plans()) {
            for (VariantConfig planVariant : variants(planConfig.variants())) {
                JsonNode plan = createPlan(planConfig.name(), suiteConfig, values(planVariant));
                String planId = requiredText(plan, "id");

                for (ModuleConfig moduleConfig : planConfig.modules()) {
                    for (VariantConfig moduleVariant : variants(moduleConfig.variants())) {
                        ModuleExecution execution = new ModuleExecution(planConfig, planVariant, moduleConfig, moduleVariant);
                        beforeModule.accept(execution);

                        JsonNode moduleNode = createModule(planId, moduleConfig.name(), values(moduleVariant));
                        String moduleId = requiredText(moduleNode, "id");
                        JsonNode info = waitForRunnableOrFinished(moduleId);
                        if ("CONFIGURED".equals(info.path("status").asText())) {
                            startModule(moduleId);
                        }
                        info = waitForFinished(moduleId);
                        JsonNode logs = getLogs(moduleId);
                        results.add(new ConformanceModuleResult(planConfig.name(), variantId(planVariant),
                                moduleConfig.name(), variantId(moduleVariant), planId, moduleId,
                                info.path("status").asText(), info.path("result").asText("UNKNOWN"), logs));
                    }
                }
            }
        }

        return new ConformanceRunResult(results);
    }

    private JsonNode createPlan(String planName, JsonNode suiteConfig, Map<String, String> variants) {
        StringBuilder path = new StringBuilder("/api/plan?planName=").append(encode(planName));
        if (variants != null && !variants.isEmpty()) {
            path.append("&variant=").append(encode(toJson(variants)));
        }
        HttpRequest request = request(path.toString())
                .POST(HttpRequest.BodyPublishers.ofString(suiteConfig.toString()))
                .header("Content-Type", "application/json")
                .build();
        return expectJson(request, 201);
    }

    private JsonNode createModule(String planId, String module, Map<String, String> variants) {
        StringBuilder path = new StringBuilder("/api/runner?test=")
                .append(encode(module))
                .append("&plan=")
                .append(encode(planId));
        if (variants != null && !variants.isEmpty()) {
            path.append("&variant=").append(encode(toJson(variants)));
        }
        return expectJson(request(path.toString()).POST(HttpRequest.BodyPublishers.noBody()).build(), 201);
    }

    private void startModule(String moduleId) {
        expectJson(request("/api/runner/" + moduleId).POST(HttpRequest.BodyPublishers.noBody()).build(), 200);
    }

    private JsonNode waitForRunnableOrFinished(String moduleId) {
        return waitForState(moduleId, List.of("CONFIGURED", "WAITING", "FINISHED"), Duration.ofMinutes(4));
    }

    private JsonNode waitForFinished(String moduleId) {
        return waitForState(moduleId, List.of("FINISHED"), Duration.ofMinutes(8));
    }

    private JsonNode waitForState(String moduleId, List<String> states, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        JsonNode lastInfo = null;
        while (System.nanoTime() < deadline) {
            lastInfo = getInfo(moduleId);
            String status = lastInfo.path("status").asText();
            if (states.contains(status)) {
                return lastInfo;
            }
            if ("INTERRUPTED".equals(status)) {
                return lastInfo;
            }
            sleep(Duration.ofSeconds(1));
        }
        throw new IllegalStateException("Timed out waiting for conformance module " + moduleId
                + " to reach " + states + "; last info: " + lastInfo);
    }

    private JsonNode getInfo(String moduleId) {
        return expectJson(request("/api/info/" + moduleId).GET().build(), 200);
    }

    private JsonNode getLogs(String moduleId) {
        return expectJson(request("/api/log/" + moduleId).GET().build(), 200);
    }

    private JsonNode expectJson(HttpRequest request, int expectedStatus) {
        HttpResponse<String> response = send(request);
        if (response.statusCode() != expectedStatus) {
            throw new IllegalStateException("Conformance API " + request.method() + " " + request.uri()
                    + " returned HTTP " + response.statusCode() + ": " + response.body());
        }
        try {
            return ConformanceProfileLoader.mapper().readTree(response.body());
        } catch (IOException e) {
            throw new RuntimeException("Conformance API returned invalid JSON from " + request.uri(), e);
        }
    }

    private HttpResponse<String> send(HttpRequest request) {
        IOException lastFailure = null;
        for (int attempt = 1; attempt <= 5; attempt++) {
            try {
                return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (IOException e) {
                lastFailure = e;
                sleep(Duration.ofSeconds(Math.min(attempt * 2L, 10L)));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted while calling conformance API: " + request.uri(), e);
            }
        }
        throw new RuntimeException("Conformance API request failed: " + request.uri(), lastFailure);
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(baseUri.resolve(path))
                .timeout(Duration.ofMinutes(2))
                .header("Accept", "application/json");
    }

    private static String requiredText(JsonNode node, String field) {
        String value = node.path(field).asText(null);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Conformance API response missing '" + field + "': " + node);
        }
        return value;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String toJson(Map<String, String> value) {
        ObjectNode node = ConformanceProfileLoader.mapper().createObjectNode();
        value.forEach(node::put);
        return node.toString();
    }

    private static List<VariantConfig> variants(List<VariantConfig> variants) {
        if (variants == null || variants.isEmpty()) {
            return List.of(new VariantConfig("default", Map.of(), null));
        }
        return variants;
    }

    private static Map<String, String> values(VariantConfig variant) {
        return emptyIfNull(variant.values());
    }

    private static String variantId(VariantConfig variant) {
        return variant.id() == null || variant.id().isBlank() ? "default" : variant.id();
    }

    private static Map<String, String> emptyIfNull(Map<String, String> value) {
        return value == null ? Map.of() : value;
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }

    private static SSLContext trustAllSslContext() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] { new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            } }, new SecureRandom());
            return context;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create conformance API SSL context", e);
        }
    }

    public record ModuleExecution(
            PlanConfig plan,
            VariantConfig planVariant,
            ModuleConfig module,
            VariantConfig moduleVariant) {
    }
}
