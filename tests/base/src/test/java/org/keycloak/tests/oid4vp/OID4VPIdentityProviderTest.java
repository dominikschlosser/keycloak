package org.keycloak.tests.oid4vp;

import org.keycloak.broker.oid4vp.OID4VPIdentityProviderFactory;
import org.keycloak.protocol.oid4vp.OID4VPConstants;
import org.keycloak.protocol.oid4vp.model.OID4VPAuthorizationRequest;
import org.keycloak.protocol.oid4vp.model.OID4VPDirectPostResponse;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.injection.LifeCycle;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.testframework.realm.ClientConfig;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.ui.annotations.InjectPage;
import org.keycloak.testframework.ui.annotations.InjectWebDriver;
import org.keycloak.testframework.ui.page.LoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.keycloak.testsuite.util.IdentityProviderBuilder;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.AuthorizationEndpointResponse;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@KeycloakIntegrationTest
public class OID4VPIdentityProviderTest {

    private static final String CLIENT_ID = "oid4vp-test-client";
    private static final String CLIENT_SECRET = "oid4vp-test-secret";
    private static final String IDP_ALIAS = "oid4vp-idp";

    @InjectRealm(config = OID4VPRealmConfig.class, lifecycle = LifeCycle.METHOD)
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
    public void testRequestObjectAndDirectPostEndpoints() throws Exception {
        oauth.realm(realm.getName()).client(CLIENT_ID, CLIENT_SECRET);
        oauth.scope("openid profile");

        OID4VPBasicWallet wallet = new OID4VPBasicWallet(oauth);

        // The verifier redirects the authorization request directly to the selected wallet.
        OID4VPBasicWallet.WalletAuthorizationRequest walletRequest = wallet.authorizationRequest(IDP_ALIAS);
        assertNotNull(walletRequest.getWalletUrl(), "No wallet URL");
        assertThat(walletRequest.getWalletUrl(), startsWith("openid4vp://authorize?"));
        assertNotNull(walletRequest.getClientId(), "No wallet client_id");
        assertNotNull(walletRequest.getRequestUri(), "No request_uri");

        // The wallet fetches the Request Object from the verifier.
        OID4VPAuthorizationRequest authorizationRequest = wallet.fetchAuthorizationRequest(walletRequest);
        assertEquals(OID4VPConstants.RESPONSE_TYPE_VP_TOKEN, authorizationRequest.getResponseType());
        assertEquals(OID4VPConstants.RESPONSE_MODE_DIRECT_POST, authorizationRequest.getResponseMode());
        assertEquals(OID4VPConstants.AUD_SELF_ISSUED_V2, authorizationRequest.getAudience());
        assertEquals(walletRequest.getClientId(), authorizationRequest.getClientId());
        assertEquals(authorizationRequest.getClientId(), authorizationRequest.getResponseUri());
        assertNotNull(authorizationRequest.getDcqlQuery(), "No DCQL query");
        assertEquals(1, authorizationRequest.getDcqlQuery().getCredentials().size());

        // The wallet sends a background direct_post response and receives a redirect URI for the browser.
        OID4VPDirectPostResponse directPostResponse = wallet.submitDirectPost(authorizationRequest, "dummy-vp-token");
        assertNotNull(directPostResponse.getRedirectUri(), "No redirect_uri");
        assertThat(directPostResponse.getRedirectUri(), startsWith(oauth.getBaseUrl() + "/realms/" + realm.getName() + "/broker/" + IDP_ALIAS + "/endpoint/continue"));
    }

    @Test
    public void testBrowserCanResumeBrokerLoginFromDirectPostRedirectUri() throws Exception {
        oauth.realm(realm.getName()).client(CLIENT_ID, CLIENT_SECRET);
        oauth.scope("openid profile");

        OID4VPBasicWallet wallet = new OID4VPBasicWallet(oauth, loginPage, driver);

        // The browser initiates the broker login and receives the wallet URL.
        OID4VPBasicWallet.WalletAuthorizationRequest walletRequest = wallet.browserAuthorizationRequest(IDP_ALIAS);

        // The wallet processes the request object and performs a background direct_post callback.
        OID4VPAuthorizationRequest authorizationRequest = wallet.fetchAuthorizationRequest(walletRequest);
        OID4VPDirectPostResponse directPostResponse = wallet.submitDirectPost(authorizationRequest, "dummy-vp-token");

        // The browser resumes the login flow by following the redirect URI returned to the wallet.
        AuthorizationEndpointResponse authorizationResponse = wallet.continueInBrowser(directPostResponse);
        assertThat(driver.getCurrentUrl(), startsWith(oauth.getRedirectUri()));

        String code = authorizationResponse.getCode();
        assertNotNull(code, "No authorization code");
        AccessTokenResponse tokenResponse = oauth.accessTokenRequest(code).send();
        assertTrue(tokenResponse.isSuccess(), tokenResponse.getErrorDescription());
    }

    public static class OID4VPRealmConfig implements RealmConfig {

        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            IdentityProviderRepresentation idp = IdentityProviderBuilder.create()
                    .providerId(OID4VPIdentityProviderFactory.PROVIDER_ID)
                    .alias(IDP_ALIAS)
                    .build();
            idp.setTrustEmail(true);
            return realm.identityProvider(idp);
        }
    }

    public static class OID4VPClientConfig implements ClientConfig {

        @Override
        public ClientBuilder configure(ClientBuilder client) {
            return client.clientId(CLIENT_ID)
                    .directAccessGrantsEnabled(true)
                    .secret(CLIENT_SECRET);
        }
    }
}
