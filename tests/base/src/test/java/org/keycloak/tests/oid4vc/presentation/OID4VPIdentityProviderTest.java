package org.keycloak.tests.oid4vc.presentation;

import java.util.HashMap;
import java.util.List;

import jakarta.ws.rs.core.Response;

import org.keycloak.common.Profile;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.ImportedRsaKeyProviderFactory;
import org.keycloak.keys.KeyProvider;
import org.keycloak.protocol.oid4vc.model.presentation.AuthorizationRequest;
import org.keycloak.protocol.oid4vc.model.presentation.DcqlClaimQuery;
import org.keycloak.protocol.oid4vc.model.presentation.DcqlCredentialMeta;
import org.keycloak.protocol.oid4vc.model.presentation.DcqlCredentialQuery;
import org.keycloak.protocol.oid4vc.model.presentation.DcqlQuery;
import org.keycloak.protocol.oid4vc.model.presentation.DirectPostResponse;
import org.keycloak.protocol.oid4vc.presentation.OID4VPConstants;
import org.keycloak.protocol.oid4vc.presentation.OID4VPIdentityProviderConfig;
import org.keycloak.protocol.oid4vc.presentation.OID4VPIdentityProviderFactory;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.injection.LifeCycle;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.testframework.realm.ClientConfig;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.testframework.ui.annotations.InjectPage;
import org.keycloak.testframework.ui.annotations.InjectWebDriver;
import org.keycloak.testframework.ui.page.LoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.keycloak.tests.oid4vc.OID4VCTestContext;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.AuthorizationEndpointResponse;
import org.keycloak.util.JsonSerialization;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@KeycloakIntegrationTest(config = OID4VPIdentityProviderTest.DefaultServerConfigWithOid4Vp.class)
public class OID4VPIdentityProviderTest {

    private static final String CLIENT_ID = "oid4vp-test-client";
    private static final String CLIENT_SECRET = "oid4vp-test-secret";
    private static final String IDP_ALIAS = "oid4vp-idp";
    private static final String WALLET_SCHEME = OID4VPConstants.DEFAULT_WALLET_SCHEME;
    private static final String SUBJECT_CLAIM_NAME = "person_id";
    private static final String CREDENTIAL_TYPE = "urn:keycloak:oid4vp:credential";
    private static final String CREDENTIAL_QUERY_ID = "test_credential";

    @InjectRealm(lifecycle = LifeCycle.METHOD)
    ManagedRealm realm;

    @InjectOAuthClient(config = OID4VPClientConfig.class)
    OAuthClient oauth;

    @InjectPage
    LoginPage loginPage;

    @InjectWebDriver
    ManagedWebDriver driver;

    @AfterEach
    void cleanupBrowser() {
        driver.cookies().deleteAll();
        driver.open("about:blank");
    }

    @Test
    public void testBrowserCanResumeBrokerLoginFromCredentialTrustedByX5c() throws Exception {
        OID4VCTestContext ctx = testContext(personCredential());
        OID4VPBasicWallet wallet = setupWallet(ctx);

        fetchAuthorizationRequest(ctx, wallet);
        buildCredential(ctx);
        assertCredentialAccepted(ctx, wallet);
    }

    @Test
    public void testBrowserCanResumeBrokerLoginFromCredentialTrustedByIssuerMetadata() throws Exception {
        try (TestIssuerEndpoint issuerEndpoint = TestIssuerEndpoint.start()) {
            TestCredentialBuilder credentialBuilder = personCredential()
                    .withIssuer(issuerEndpoint.issuer())
                    .withoutX5cHeader();
            issuerEndpoint.metadata(credentialBuilder.jwtVcIssuerMetadata());
            OID4VCTestContext ctx = testContext(credentialBuilder);
            OID4VPBasicWallet wallet = setupWallet(ctx);

            fetchAuthorizationRequest(ctx, wallet);
            buildCredential(ctx);
            assertCredentialAccepted(ctx, wallet);
        }
    }

    @Test
    public void testBrowserCanResumeBrokerLoginFromCredentialSignedByRealmKey() throws Exception {
        TestCredentialBuilder credentialBuilder = personCredential()
                .withIssuer(realm.getBaseUrl())
                .withoutX5cHeader();
        importRealmSigningKey(credentialBuilder);
        OID4VCTestContext ctx = new OID4VCTestContext().withCredentialBuilder(credentialBuilder);
        OID4VPBasicWallet wallet = setupWalletTrustedByRealmKeys();

        fetchAuthorizationRequest(ctx, wallet);
        buildCredential(ctx);
        assertCredentialAccepted(ctx, wallet);
    }

    @Test
    public void testRequestObjectEndpointAndDirectPostRejectsUnverifiedToken() throws Exception {
        OID4VCTestContext ctx = testContext(trustedIssuer());
        OID4VPBasicWallet wallet = setupWallet(ctx);

        fetchAuthorizationRequest(ctx, wallet);
        assertAuthorizationRequest(ctx);

        // The wallet sends a spec-shaped DCQL response with an unverifiable presentation.
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(),
                wallet.submitDirectPostStatus(ctx, TestVpToken.unverifiablePresentation(ctx.getAuthorizationRequest())));
    }

    @Test
    public void testDirectPostRejectsMalformedVpToken() throws Exception {
        OID4VCTestContext ctx = testContext(trustedIssuer());
        OID4VPBasicWallet wallet = setupWallet(ctx);

        fetchAuthorizationRequest(ctx, wallet);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(),
                wallet.submitDirectPostStatus(ctx, TestVpToken.malformed()));
    }

    @Test
    public void testDirectPostRejectsCredentialSignedByUntrustedCertificate() throws Exception {
        TestCredentialBuilder trustedIssuer = trustedIssuer();
        TestCredentialBuilder untrustedCredentialBuilder = personCredential();
        OID4VCTestContext ctx = new OID4VCTestContext()
                .withTrustedIssuer(trustedIssuer)
                .withCredentialBuilder(untrustedCredentialBuilder);
        OID4VPBasicWallet wallet = setupWallet(ctx);

        fetchAuthorizationRequest(ctx, wallet);
        buildCredential(ctx);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(),
                wallet.submitDirectPostStatus(ctx, TestVpToken.forCredential(ctx.getAuthorizationRequest(), ctx.getCredential())));
    }

    public static class OID4VPClientConfig implements ClientConfig {

        @Override
        public ClientBuilder configure(ClientBuilder client) {
            return client.clientId(CLIENT_ID).secret(CLIENT_SECRET);
        }
    }

    public static class DefaultServerConfigWithOid4Vp implements KeycloakServerConfig {

        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.features(Profile.Feature.OID4VC_VP)
                    .option("spi-connections-http-client-default-disable-trust-manager", "true");
        }
    }

    private void createIdentityProvider(String trustedIssuerCertificate) {
        IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
        idp.setAlias(IDP_ALIAS);
        idp.setProviderId(OID4VPIdentityProviderFactory.PROVIDER_ID);
        idp.setEnabled(true);
        idp.setConfig(new HashMap<>());
        idp.getConfig().put(OID4VPIdentityProviderConfig.WALLET_SCHEME, WALLET_SCHEME);
        idp.getConfig().put(OID4VPIdentityProviderConfig.SUBJECT_CLAIM_NAME, SUBJECT_CLAIM_NAME);
        idp.getConfig().put(OID4VPIdentityProviderConfig.DCQL_QUERY, dcqlQuery());
        if (trustedIssuerCertificate != null) {
            idp.getConfig().put(OID4VPIdentityProviderConfig.TRUSTED_ISSUER_CERTIFICATE, trustedIssuerCertificate);
        }
        idp.setTrustEmail(true);

        try (Response response = realm.admin().identityProviders().create(idp)) {
            String body = response.hasEntity() ? response.readEntity(String.class) : "";
            assertEquals(201, response.getStatus(), body);
            assertTrue(response.getLocation() != null, "Missing identity provider location");
        }

        IdentityProviderRepresentation created = realm.admin().identityProviders().get(IDP_ALIAS).toRepresentation();
        assertNotNull(created, "Missing created identity provider");
        assertEquals(IDP_ALIAS, created.getAlias());
    }

    private OID4VPBasicWallet setupWallet(OID4VCTestContext ctx) {
        oauth.realm(realm.getName()).client(CLIENT_ID, CLIENT_SECRET);
        oauth.scope("openid profile");
        createIdentityProvider(ctx.getTrustedIssuer().trustedIssuerCertificate());
        return new OID4VPBasicWallet(oauth, loginPage, driver);
    }

    private OID4VPBasicWallet setupWalletTrustedByRealmKeys() {
        oauth.realm(realm.getName()).client(CLIENT_ID, CLIENT_SECRET);
        oauth.scope("openid profile");
        createIdentityProvider(null);
        return new OID4VPBasicWallet(oauth, loginPage, driver);
    }

    private TestCredentialBuilder trustedIssuer() {
        return TestCredentialBuilder.create();
    }

    private String dcqlQuery() {
        DcqlCredentialQuery credentialQuery = new DcqlCredentialQuery()
                .setId(CREDENTIAL_QUERY_ID)
                .setFormat("dc+sd-jwt")
                .setMeta(new DcqlCredentialMeta().setVctValues(List.of(CREDENTIAL_TYPE)))
                .setClaims(List.of(
                        new DcqlClaimQuery().setPath(List.of(SUBJECT_CLAIM_NAME)),
                        new DcqlClaimQuery().setPath(List.of("given_name")),
                        new DcqlClaimQuery().setPath(List.of("family_name"))));

        return JsonSerialization.valueAsString(new DcqlQuery().setCredentials(List.of(credentialQuery)));
    }

    private OID4VCTestContext testContext(TestCredentialBuilder credentialBuilder) {
        return new OID4VCTestContext()
                .withTrustedIssuer(credentialBuilder)
                .withCredentialBuilder(credentialBuilder);
    }

    private TestCredentialBuilder personCredential() {
        return trustedIssuer()
                .withCredentialType(CREDENTIAL_TYPE)
                .withClaim(SUBJECT_CLAIM_NAME, "alice")
                .withClaim("given_name", "Alice")
                .withClaim("family_name", "Doe")
                .withClaim("email", "alice@example.org");
    }

    private void importRealmSigningKey(TestCredentialBuilder credentialBuilder) {
        ComponentRepresentation keyProvider = new ComponentRepresentation();
        keyProvider.setName("oid4vp-issuer-key");
        keyProvider.setParentId(realm.admin().toRepresentation().getId());
        keyProvider.setProviderId(ImportedRsaKeyProviderFactory.ID);
        keyProvider.setProviderType(KeyProvider.class.getName());

        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(Attributes.PRIVATE_KEY_KEY, credentialBuilder.issuerPrivateKey());
        config.putSingle(Attributes.CERTIFICATE_KEY, credentialBuilder.trustedIssuerCertificate());
        config.putSingle(Attributes.KID_KEY, credentialBuilder.issuerKeyId());
        config.putSingle(Attributes.PRIORITY_KEY, Long.toString(System.currentTimeMillis()));
        config.putSingle(Attributes.ALGORITHM_KEY, credentialBuilder.issuerAlgorithm());
        keyProvider.setConfig(config);

        try (Response response = realm.admin().components().add(keyProvider)) {
            String body = response.hasEntity() ? response.readEntity(String.class) : "";
            assertEquals(Response.Status.CREATED.getStatusCode(), response.getStatus(), body);
        }
    }

    private void buildCredential(OID4VCTestContext ctx) throws Exception {
        ctx.withCredential(ctx.getCredentialBuilder().build(ctx.getAuthorizationRequest()));
    }

    private void assertCredentialAccepted(OID4VCTestContext ctx, OID4VPBasicWallet wallet) throws Exception {
        DirectPostResponse directPostResponse = wallet.submitDirectPost(
                ctx, TestVpToken.forCredential(ctx.getAuthorizationRequest(), ctx.getCredential()));
        assertThat(directPostResponse.getRedirectUri(), startsWith(realm.getBaseUrl() + "/broker/" + IDP_ALIAS + "/endpoint/continue"));

        AuthorizationEndpointResponse authorizationResponse = wallet.continueInBrowser(directPostResponse);
        assertThat(driver.getCurrentUrl(), startsWith(oauth.getRedirectUri()));
        assertNotNull(authorizationResponse.getCode(), "No authorization code");

        AccessTokenResponse tokenResponse = oauth.accessTokenRequest(authorizationResponse.getCode()).send();
        assertTrue(tokenResponse.isSuccess(), tokenResponse.getErrorDescription());
    }

    private void fetchAuthorizationRequest(OID4VCTestContext ctx, OID4VPBasicWallet wallet) throws Exception {
        OID4VPBasicWallet.WalletAuthorizationRequest walletRequest = wallet.browserAuthorizationRequest(ctx, IDP_ALIAS);
        assertNotNull(walletRequest.getWalletUrl(), "No wallet URL");
        assertThat(walletRequest.getWalletUrl(), startsWith(WALLET_SCHEME));
        assertNotNull(walletRequest.getClientId(), "No wallet client_id");
        assertNotNull(walletRequest.getRequestUri(), "No request_uri");

        AuthorizationRequest authorizationRequest = wallet.fetchAuthorizationRequest(ctx);
        assertEquals(realm.getBaseUrl(), authorizationRequest.getIssuer());
        assertEquals(walletRequest.getClientId(), authorizationRequest.getClientId());
    }

    private void assertAuthorizationRequest(OID4VCTestContext ctx) {
        AuthorizationRequest authorizationRequest = ctx.getAuthorizationRequest();
        assertEquals(OID4VPConstants.RESPONSE_TYPE_VP_TOKEN, authorizationRequest.getResponseType());
        assertEquals(OID4VPConstants.RESPONSE_MODE_DIRECT_POST, authorizationRequest.getResponseMode());
        assertEquals(OID4VPConstants.AUD_SELF_ISSUED_V2, authorizationRequest.getAudience());
        assertNotNull(authorizationRequest.getResponseUri(), "No response_uri");
        assertNotNull(authorizationRequest.getDcqlQuery(), "No DCQL query");
        assertEquals(1, authorizationRequest.getDcqlQuery().getCredentials().size());
        assertEquals(List.of(SUBJECT_CLAIM_NAME), authorizationRequest.getDcqlQuery().getCredentials().get(0).getClaims().get(0).getPath());
    }

}
