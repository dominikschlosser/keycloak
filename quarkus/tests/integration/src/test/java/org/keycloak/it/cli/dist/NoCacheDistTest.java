package org.keycloak.it.cli.dist;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.keycloak.it.junit5.extension.CLIResult;
import org.keycloak.it.junit5.extension.DistributionTest;
import org.keycloak.it.junit5.extension.RawDistOnly;
import org.keycloak.it.utils.KeycloakDistribution;

import io.quarkus.test.junit.main.Launch;

@DistributionTest(reInstall = DistributionTest.ReInstall.BEFORE_TEST)
@RawDistOnly(reason = "Test relies on specific server configuration not applicable to container.")
@Tag(DistributionTest.SMOKE)
public class NoCacheDistTest {

    @Test
    @Launch({ "start-dev", "--cache=none" })
    void testStartDevWithNoCache(CLIResult result) {
        result.assertStartedDevMode();
        // Assert that neither local nor clustered caches are initialized.
        // This can be done by checking for the absence of specific log messages.
        result.assertMessageLoggedNotRegEx(".*ISPN000078.*"); // JGroups channel started (clustered)
        result.assertMessageLoggedNotRegEx(".*local only cache.*"); // Specific message for local cache
        result.assertMessageLoggedNotRegEx(".*org.infinispan.manager.DefaultCacheManager.*"); // Infinispan Cache Manager starting
        // Ideally, we'd also have a positive assertion that "none" cache mode is active,
        // but that might require a specific log message to be added in Keycloak for this mode.
        // For now, the absence of Infinispan startup messages is a good indicator.
    }

    @Test
    @Launch({ "start", "--cache=none", "--http-enabled=true", "--hostname-strict=false" })
    void testStartProdWithNoCache(CLIResult result) {
        result.assertStarted();
        result.assertMessageLoggedNotRegEx(".*ISPN000078.*"); // JGroups channel started (clustered)
        result.assertMessageLoggedNotRegEx(".*local only cache.*"); // Specific message for local cache
        result.assertMessageLoggedNotRegEx(".*org.infinispan.manager.DefaultCacheManager.*"); // Infinispan Cache Manager starting
    }
}
