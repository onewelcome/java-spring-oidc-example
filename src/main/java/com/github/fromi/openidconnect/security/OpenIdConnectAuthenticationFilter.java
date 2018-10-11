package com.github.fromi.openidconnect.security;

import static java.util.Optional.empty;
import static org.springframework.security.core.authority.AuthorityUtils.NO_AUTHORITIES;

import java.text.ParseException;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import com.github.fromi.openidconnect.model.TokenDetails;
import com.github.fromi.openidconnect.model.UserInfo;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

public class OpenIdConnectAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

  @Resource
  private OAuth2RestOperations restTemplate;
  @Resource
  private OAuth2ProtectedResourceDetails details;
  @Resource
  private OpenIdTokenValidatorWrapper openIdTokenValidatorWrapper;

  protected OpenIdConnectAuthenticationFilter(final String defaultFilterProcessesUrl) {
    super(defaultFilterProcessesUrl);
    setAuthenticationManager(authentication -> authentication); // AbstractAuthenticationProcessingFilter requires an authentication manager.
  }

  @Override
  public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response) {
    // Use ID token inside the Access Token to retrieve user info
    final OAuth2AccessToken accessToken = getAccessToken();

    final String idToken = accessToken.getAdditionalInformation().get("id_token").toString();

    final TokenDetails tokenDetails = getTokenDetails(idToken);
    final JWTClaimsSet jwtClaimsSet = tokenDetails.getJwtClaimsSet();

    final UserInfo principal = createUser(jwtClaimsSet, idToken);
    // We do not assign authorities here, but they can be based on claims in the ID token.
    final PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, empty(), NO_AUTHORITIES);
    token.setDetails(tokenDetails);
    return token;
  }

  private OAuth2AccessToken getAccessToken() {
    final OAuth2AccessToken accessToken;

    try {
      accessToken = restTemplate.getAccessToken();
    } catch (final OAuth2Exception e) {
      throw new AccessTokenRequiredException("Could not obtain access token", details, e);
    }
    return accessToken;
  }

  private TokenDetails getTokenDetails(final String idToken) {
    try {
      final JWT jwt = JWTParser.parse(idToken);

      openIdTokenValidatorWrapper.validateToken(jwt);

      return new TokenDetails(jwt.getJWTClaimsSet());
    } catch (final ParseException e) {
      throw new BadCredentialsException("Could not obtain user details from token", e);
    }
  }

  private UserInfo createUser(final JWTClaimsSet jwtClaimsSet, final String idToken) {
    Object name = jwtClaimsSet.getClaim("name");
    if (name == null) {
      name = jwtClaimsSet.getSubject();
    }

    return new UserInfo(jwtClaimsSet.getSubject(), (String) name, idToken);
  }

}