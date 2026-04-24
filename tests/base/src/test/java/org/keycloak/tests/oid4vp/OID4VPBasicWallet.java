package org.keycloak.tests.oid4vp;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import jakarta.ws.rs.core.HttpHeaders;

import org.apache.http.client.utils.URLEncodedUtils;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.protocol.oid4vp.OID4VPConstants;
import org.keycloak.protocol.oid4vp.model.OID4VPAuthorizationRequest;
import org.keycloak.protocol.oid4vp.model.OID4VPDirectPostResponse;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.ui.page.LoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.keycloak.testsuite.util.oauth.AuthorizationEndpointResponse;
import org.keycloak.util.JsonSerialization;

import org.apache.http.client.config.RequestConfig;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebElement;

public class OID4VPBasicWallet {

    private final SimpleHttp redirectlessHttp;
    private final OAuthClient oauth;
    private final LoginPage loginPage;
    private final ManagedWebDriver driver;

    public OID4VPBasicWallet(OAuthClient oauth) {
        this(oauth, null, null);
    }

    public OID4VPBasicWallet(OAuthClient oauth, LoginPage loginPage, ManagedWebDriver driver) {
        this.redirectlessHttp = SimpleHttp.create(oauth.httpClient().get())
                .withRequestConfig(RequestConfig.custom().setRedirectsEnabled(false).build());
        this.oauth = oauth;
        this.loginPage = loginPage;
        this.driver = driver;
    }

    public WalletAuthorizationRequest authorizationRequest(String idpAlias) throws Exception {
        String currentUrl = oauth.loginForm()
                .param(AdapterConstants.KC_IDP_HINT, idpAlias)
                .build();
        CookieJar cookies = new CookieJar();

        for (int i = 0; i < 5; i++) {
            try (SimpleHttpResponse response = doGet(currentUrl, cookies.headerValue()).asResponse()) {
                cookies.store(response.getHeader(HttpHeaders.SET_COOKIE));

                int status = response.getStatus();
                if (status != 302 && status != 303) {
                    throw new IllegalStateException("Unexpected broker redirect status: " + status);
                }

                String location = response.getFirstHeader(HttpHeaders.LOCATION);
                if (location != null && location.startsWith(OID4VPConstants.WALLET_AUTHORIZATION_SCHEME)) {
                    return new WalletAuthorizationRequest()
                            .setWalletUrl(location)
                            .setClientId(getQueryParam(location, "client_id"))
                            .setRequestUri(getQueryParam(location, "request_uri"));
                }

                currentUrl = location;
            }
        }

        throw new IllegalStateException("OID4VP wallet redirect was not reached");
    }

    public WalletAuthorizationRequest browserAuthorizationRequest(String idpAlias) throws Exception {
        requireBrowser();
        oauth.openLoginForm();

        // HtmlUnit resolves this link correctly through getAttribute(), while getDomAttribute()
        // returns a non-routable value for this test setup.
        String brokerLoginUrl = loginPage.findSocialButton(idpAlias).getAttribute("href");

        try (SimpleHttpResponse brokerLoginResponse = doGet(brokerLoginUrl, browserCookies()).asResponse()) {
            int status = brokerLoginResponse.getStatus();
            if (status != 302 && status != 303) {
                throw new IllegalStateException("Unexpected broker login status: " + status);
            }

            String walletUrl = brokerLoginResponse.getFirstHeader(HttpHeaders.LOCATION);
            return new WalletAuthorizationRequest()
                    .setWalletUrl(walletUrl)
                    .setClientId(getQueryParam(walletUrl, "client_id"))
                    .setRequestUri(getQueryParam(walletUrl, "request_uri"));
        }
    }

    public OID4VPAuthorizationRequest fetchAuthorizationRequest(WalletAuthorizationRequest walletRequest) throws Exception {
        try (SimpleHttpResponse requestObjectResponse = redirectlessHttp.doGet(walletRequest.getRequestUri()).asResponse()) {
            if (requestObjectResponse.getStatus() != 200) {
                throw new IllegalStateException("Unexpected request object status: " + requestObjectResponse.getStatus());
            }

            byte[] requestObjectContent = new JWSInput(requestObjectResponse.asString()).getContent();
            return JsonSerialization.readValue(requestObjectContent, OID4VPAuthorizationRequest.class);
        }
    }

    public OID4VPDirectPostResponse submitDirectPost(OID4VPAuthorizationRequest authorizationRequest, String vpToken) throws Exception {
        return redirectlessHttp.doPost(authorizationRequest.getResponseUri())
                .param(OID4VPConstants.STATE, authorizationRequest.getState())
                .param(OID4VPConstants.VP_TOKEN, vpToken)
                .asJson(OID4VPDirectPostResponse.class);
    }

    public AuthorizationEndpointResponse continueInBrowser(OID4VPDirectPostResponse directPostResponse) {
        requireBrowser();
        driver.open(directPostResponse.getRedirectUri());
        driver.waiting().until(d -> {
            String currentUrl = d.getCurrentUrl();
            return currentUrl.contains("/first-broker-login") || currentUrl.contains("code=") || currentUrl.contains("error=");
        });

        if (driver.getCurrentUrl().contains("/first-broker-login")) {
            completeFirstBrokerLogin();
        }

        return oauth.parseLoginResponse();
    }

    private SimpleHttpRequest doGet(String url, String cookieHeader) {
        SimpleHttpRequest request = redirectlessHttp.doGet(url);
        if (cookieHeader != null && !cookieHeader.isBlank()) {
            request.header(HttpHeaders.COOKIE, cookieHeader);
        }
        return request;
    }

    private String getQueryParam(String uri, String name) {
        return URLEncodedUtils.parse(URI.create(uri), StandardCharsets.UTF_8).stream()
                .filter(param -> name.equals(param.getName()))
                .map(param -> param.getValue())
                .findFirst()
                .orElse(null);
    }

    private String browserCookies() {
        return driver.cookies().getAll().stream()
                .map(this::toCookiePair)
                .collect(Collectors.joining("; "));
    }

    private void requireBrowser() {
        if (loginPage == null || driver == null) {
            throw new IllegalStateException("Browser-based OID4VP flow requires LoginPage and ManagedWebDriver");
        }
    }

    private String toCookiePair(Cookie cookie) {
        return cookie.getName() + "=" + cookie.getValue();
    }

    private void completeFirstBrokerLogin() {
        String uniqueUsername = "oid4vp-" + System.currentTimeMillis();

        fillIfPresent("username", uniqueUsername);
        fillIfPresent("email", uniqueUsername + "@example.org");
        fillIfPresent("firstName", "OID4VP");
        fillIfPresent("lastName", "User");

        WebElement submit = driver.findElement(By.cssSelector("input[type='submit'], button[type='submit']"));
        submit.click();
    }

    private void fillIfPresent(String field, String value) {
        try {
            WebElement input = driver.findElement(By.id(field));
            if (input.getDomProperty("value") == null || input.getDomProperty("value").isBlank()) {
                input.sendKeys(value);
            }
        } catch (NoSuchElementException ignored) {
        }
    }

    private static class CookieJar {

        private final Map<String, String> cookies = new LinkedHashMap<>();

        void store(List<String> setCookieHeaders) {
            if (setCookieHeaders == null) {
                return;
            }

            setCookieHeaders.forEach(this::store);
        }

        String headerValue() {
            if (cookies.isEmpty()) {
                return null;
            }

            return cookies.entrySet().stream()
                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                    .collect(Collectors.joining("; "));
        }

        private void store(String setCookieHeader) {
            String cookie = setCookieHeader.split(";", 2)[0];
            int separator = cookie.indexOf('=');
            if (separator <= 0) {
                return;
            }

            cookies.put(cookie.substring(0, separator), cookie.substring(separator + 1));
        }
    }

    public static class WalletAuthorizationRequest {

        private String walletUrl;
        private String clientId;
        private String requestUri;

        public String getWalletUrl() {
            return walletUrl;
        }

        public WalletAuthorizationRequest setWalletUrl(String walletUrl) {
            this.walletUrl = walletUrl;
            return this;
        }

        public String getClientId() {
            return clientId;
        }

        public WalletAuthorizationRequest setClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public String getRequestUri() {
            return requestUri;
        }

        public WalletAuthorizationRequest setRequestUri(String requestUri) {
            this.requestUri = requestUri;
            return this;
        }
    }
}
