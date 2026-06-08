package org.keycloak.tests.conformance.containers;

import java.net.URI;
import java.time.Duration;
import java.util.List;

import org.keycloak.tests.conformance.config.ConformanceProfile;
import org.keycloak.tests.conformance.runner.ConformanceApiClient;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

public final class OpenIdConformanceSuite implements AutoCloseable {

    private final Network network;
    private final GenericContainer<?> mongo;
    private final GenericContainer<?> server;
    private final GenericContainer<?> nginx;
    private final URI baseUri;
    private final URI internalBaseUri;

    private OpenIdConformanceSuite(Network network, GenericContainer<?> mongo, GenericContainer<?> server,
            GenericContainer<?> nginx, URI baseUri, URI internalBaseUri) {
        this.network = network;
        this.mongo = mongo;
        this.server = server;
        this.nginx = nginx;
        this.baseUri = baseUri;
        this.internalBaseUri = internalBaseUri;
    }

    public static OpenIdConformanceSuite start(ConformanceProfile profile) {
        Network network = Network.newNetwork();
        String tag = profile.conformance().imageTag();
        URI internalBaseUri = URI.create("https://nginx:8443");

        GenericContainer<?> mongo = new GenericContainer<>(DockerImageName.parse("mongo:6.0.13"))
                .withNetwork(network)
                .withNetworkAliases("mongodb")
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(2)));

        GenericContainer<?> server = new GenericContainer<>(
                DockerImageName.parse("registry.gitlab.com/openid/conformance-suite:" + tag))
                .withNetwork(network)
                .withNetworkAliases("server")
                .withEnv("BASE_URL", internalBaseUri.toString())
                .withEnv("MONGODB_HOST", "mongodb")
                .withEnv("SPRING_PROFILES_ACTIVE", "dev")
                .withEnv("OIDC_GOOGLE_CLIENTID", "google-client")
                .withEnv("OIDC_GOOGLE_SECRET", "google-secret")
                .withEnv("OIDC_GITLAB_CLIENTID", "gitlab-client")
                .withEnv("OIDC_GITLAB_SECRET", "gitlab-secret")
                .dependsOn(mongo)
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(4)));

        GenericContainer<?> nginx = new GenericContainer<>(
                DockerImageName.parse("registry.gitlab.com/openid/conformance-suite/nginx:" + tag))
                .withExposedPorts(8443)
                .withNetwork(network)
                .withNetworkAliases("nginx")
                .dependsOn(server)
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(2)));

        mongo.start();
        server.start();
        nginx.start();

        URI baseUri = URI.create("https://" + nginx.getHost() + ":" + nginx.getMappedPort(8443));
        OpenIdConformanceSuite suite = new OpenIdConformanceSuite(network, mongo, server, nginx, baseUri, internalBaseUri);
        suite.client().waitUntilAvailable(Duration.ofMinutes(4));
        return suite;
    }

    public URI baseUri() {
        return baseUri;
    }

    public URI internalBaseUri() {
        return internalBaseUri;
    }

    public ConformanceApiClient client() {
        return new ConformanceApiClient(baseUri);
    }

    @Override
    public void close() {
        List.of(nginx, server, mongo).forEach(GenericContainer::stop);
        network.close();
    }
}
