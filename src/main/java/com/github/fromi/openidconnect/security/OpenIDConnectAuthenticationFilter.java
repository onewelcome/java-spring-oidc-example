package com.github.fromi.openidconnect.security;

import static java.util.Optional.empty;
import static org.springframework.security.core.authority.AuthorityUtils.NO_AUTHORITIES;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Map;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.discovery.ProviderConfiguration;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jndi.toolkit.url.Uri;

public class OpenIDConnectAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    @Value("${onegini.oauth2.clientId}")
    private String clientId;

    @Value("${onegini.oauth2.clientSecret}")
    private String clientSecret;

    @Value("${onegini.oauth2.issuer}")
    private String issuer;

    @Resource
    private OAuth2RestOperations restTemplate;

    @Resource
    private ProviderConfiguration providerConfiguration;

    @Resource
    private OAuth2ProtectedResourceDetails details;

    protected OpenIDConnectAuthenticationFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
        setAuthenticationManager(authentication -> authentication); // AbstractAuthenticationProcessingFilter requires an authentication manager.
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        //Use ID token to retrieve user info -> when we do this we also verify the ID token
        OAuth2AccessToken accessToken;

        try {
            accessToken = restTemplate.getAccessToken();
        } catch (OAuth2Exception e) {
            throw new BadCredentialsException("Could not obtain access token", e);
        }

        try {
            String idToken = accessToken.getAdditionalInformation().get("id_token").toString();
            String kid = JwtHelper.headers(idToken).get("kid");
            Jwt tokenDecoded = JwtHelper.decodeAndVerify(idToken, verifier(kid));
            Map<String, String> authInfo = new ObjectMapper().readValue(tokenDecoded.getClaims(), Map.class);
            verifyClaims(authInfo);

            UserInfo user = new UserInfo().setId(authInfo.get("sub")).setName(authInfo.get("sub"));
            return new PreAuthenticatedAuthenticationToken(user, empty(), NO_AUTHORITIES);

        }
        catch (InvalidTokenException e) {
            throw new BadCredentialsException("Could not obtain user details from token", e);
        }
        catch (InvalidPublicKeyException e){
            throw new AccessTokenRequiredException(e.getMessage(), details);
        }
        catch (JwkException e){
            throw new AccessTokenRequiredException(e.getMessage(), details);
        }

        //Use UserInfo endpoint to retrieve user info
        //final ResponseEntity<UserInfo> userInfoResponseEntity = restTemplate.getForEntity(providerConfiguration.getUserInfoEndpoint().toString(), UserInfo.class);
        //return new PreAuthenticatedAuthenticationToken(userInfoResponseEntity.getBody(), empty(), NO_AUTHORITIES);
    }

    private RsaVerifier verifier(final String kid) throws InvalidPublicKeyException, JwkException {
        JwkProvider provider = new UrlJwkProvider(providerConfiguration.getJwkSetUri());
        Jwk jwk = provider.get(kid);
        return new RsaVerifier((RSAPublicKey) jwk.getPublicKey());
    }

    public void verifyClaims(Map claims) throws MalformedURLException {
        int exp = (int) claims.get("exp");
        Date expireDate = new Date(exp * 1000L);
        Date now = new Date();
        if (expireDate.before(now) || !new Uri(issuer).getHost().equals(new Uri((String) claims.get("iss")).getHost()) ||
            !claims.get("aud").equals(clientId)) {
            throw new RuntimeException("Invalid claims");
        }
    }


}
