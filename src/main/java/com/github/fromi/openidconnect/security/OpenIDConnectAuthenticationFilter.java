package com.github.fromi.openidconnect.security;

import static java.util.Optional.empty;
import static org.springframework.security.core.authority.AuthorityUtils.NO_AUTHORITIES;

import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.discovery.ProviderConfiguration;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

public class OpenIDConnectAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

  @Value("${onegini.oauth2.clientId}")
  private String clientId;

  @Value("${onegini.oauth2.issuer}")
  private String issuer;

  @Resource
  private OAuth2RestOperations restTemplate;

  @Resource
  private ProviderConfiguration providerConfiguration;

  @Resource
  private OAuth2ProtectedResourceDetails details;

  protected OpenIDConnectAuthenticationFilter(final String defaultFilterProcessesUrl) {
    super(defaultFilterProcessesUrl);
    setAuthenticationManager(authentication -> authentication); // AbstractAuthenticationProcessingFilter requires an authentication manager.
  }

  @Override
  public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response) {

    //Use ID token to retrieve user info -> when we do this we also verify the ID token
    final OAuth2AccessToken accessToken;

    try {
      accessToken = restTemplate.getAccessToken();
    } catch (final OAuth2Exception e) {
      throw new BadCredentialsException("Could not obtain access token", e);
    }

    // Option 1: Use claim to create UserInfo
    final String idToken = accessToken.getAdditionalInformation().get("id_token").toString();
    try {
      final JWT jwt = JWTParser.parse(idToken);
      // TODO OAUTH-3116: validate the JWT
      final JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();

      final Map<String, Object> authInfo = jwtClaimsSet.getClaims();
      // TODO OAUTH-3116: find a way to make them available in the modelMap

      verifyClaims(jwtClaimsSet);

      final UserInfo user = new UserInfo().setId(jwtClaimsSet.getSubject()).setName(jwtClaimsSet.getSubject());
      return new PreAuthenticatedAuthenticationToken(user, empty(), NO_AUTHORITIES);

    } catch (final ParseException e) {
      throw new BadCredentialsException("Could not obtain user details from token", e);
    }

    // Option 2: Use UserInfo endpoint to retrieve user info
    // final ResponseEntity<UserInfo> userInfoResponseEntity = restTemplate.getForEntity(providerConfiguration.getUserInfoEndpoint().toString(), UserInfo.class);
    // return new PreAuthenticatedAuthenticationToken(userInfoResponseEntity.getBody(), empty(), NO_AUTHORITIES);
  }

  private void verifyClaims(final JWTClaimsSet claims) {
    final Date expireDate = claims.getExpirationTime();
    final Date now = new Date();

    if (expireDate.before(now)) {
      throw new CredentialsExpiredException("Claim has expired");
    }

    if (!(Objects.equals(issuer, claims.getIssuer())
        && claims.getAudience().contains(clientId))) {
      throw new BadCredentialsException("Invalid claims");
    }
  }

}