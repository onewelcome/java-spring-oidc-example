package com.onegini.oidc.security;

import static java.util.Optional.empty;
import static org.springframework.security.core.authority.AuthorityUtils.NO_AUTHORITIES;

import java.text.ParseException;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.onegini.oidc.encryption.JweDecrypterService;
import com.onegini.oidc.model.TokenDetails;
import com.onegini.oidc.model.UserInfo;

public class OpenIdConnectAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

  private static final Logger LOG = LoggerFactory.getLogger(OpenIdConnectAuthenticationFilter.class);

  @Resource
  private OAuth2RestOperations oAuth2RestOperations;
  @Resource
  private OAuth2ProtectedResourceDetails details;
  @Resource
  private OpenIdTokenValidatorWrapper openIdTokenValidatorWrapper;
  @Resource
  private JweDecrypterService jweDecrypterService;
  @Value("${id-token-encryption.enabled:false}")
  private boolean isEncryptionEnabled;

  protected OpenIdConnectAuthenticationFilter(final String defaultFilterProcessesUrl) {
    super(defaultFilterProcessesUrl);
    setAuthenticationManager(authentication -> authentication); // AbstractAuthenticationProcessingFilter requires an authentication manager.
  }

  @Override
  public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response) {
    try {
      // Use ID token inside the Access Token to retrieve user info
      final OAuth2AccessToken accessToken = getAccessToken();

      final String idToken = accessToken.getAdditionalInformation().get("id_token").toString();
      final JWT jwt = JWTParser.parse(idToken);

      //make sure the returned JWT matches our expectations
      validateEncryptionConfigurationMatchesServer(jwt);

      final TokenDetails tokenDetails = getTokenDetails(jwt);
      final JWTClaimsSet jwtClaimsSet = tokenDetails.getJwtClaimsSet();

      final UserInfo principal = createUserInfo(jwtClaimsSet, jwt);
      // We do not assign authorities here, but they can be based on claims in the ID token.
      final PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, empty(), NO_AUTHORITIES);
      token.setDetails(tokenDetails);
      return token;
    } catch (final ParseException e) {
      throw new BadCredentialsException("Could not obtain user details from token", e);
    }
  }

  private OAuth2AccessToken getAccessToken() {
    final OAuth2AccessToken accessToken;

    try {
      accessToken = oAuth2RestOperations.getAccessToken();
    } catch (final OAuth2Exception e) {
      LOG.error("Could not get Access Token", e);
      throw new AccessTokenRequiredException("Could not obtain access token", details, e);
    }
    return accessToken;
  }

  private TokenDetails getTokenDetails(final JWT jwt) {
    try {
      //If we support only signed JWT or encrypted JWT we can include only adequate part of code
      if (jwt instanceof SignedJWT) {
        openIdTokenValidatorWrapper.validateToken(jwt);
        return new TokenDetails(jwt.getJWTClaimsSet());
      } else if (jwt instanceof EncryptedJWT) {
        final JWT encryptedJWT = jweDecrypterService.decrypt((EncryptedJWT) jwt);
        openIdTokenValidatorWrapper.validateToken(encryptedJWT);
        return new TokenDetails(encryptedJWT.getJWTClaimsSet());
      } else {
        LOG.warn("Plain JWT detected. JWT should be signed.");
        return new TokenDetails(jwt.getJWTClaimsSet());
      }
    } catch (final ParseException e) {
      throw new BadCredentialsException("Could not obtain user details from token", e);
    }
  }

  private UserInfo createUserInfo(final JWTClaimsSet jwtClaimsSet, final JWT jwt) {
    Object name = jwtClaimsSet.getClaim("name");
    String idToken;
    String encryptedIdToken = null;
    if(jwt instanceof EncryptedJWT) {
      final EncryptedJWT encryptedJWT = (EncryptedJWT)jwt;
          encryptedIdToken = jwt.getParsedString();
          idToken = encryptedJWT.getPayload().toString();
    } else {
      idToken = jwt.getParsedString();
    }
    if (name == null) {
      name = jwtClaimsSet.getSubject();
    }

    return new UserInfo(jwtClaimsSet.getSubject(), (String) name, idToken, encryptedIdToken);
  }

  private void validateEncryptionConfigurationMatchesServer(final JWT jwt) {
    if (isEncryptionEnabled && !(jwt instanceof EncryptedJWT)) {
      throw new IllegalStateException("Server did not return an EncryptedJWT but encryption was enabled. Check your server side configuration");
    } else if (!isEncryptionEnabled && jwt instanceof EncryptedJWT) {
      throw new IllegalStateException("Server returned an EncryptedJWT but encryption was not enabled. Check your server side configuration.");
    }
  }

}