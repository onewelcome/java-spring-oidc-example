package com.onegini.oidc.security;

import java.util.List;

import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

public class OidcRestTemplate extends OAuth2RestTemplate {
  public OidcRestTemplate(final OAuth2ProtectedResourceDetails resource) {
    super(resource);
  }

  public OidcRestTemplate(final OAuth2ProtectedResourceDetails resource, final OAuth2ClientContext context) {
    super(resource, context);
  }

  @Override
  protected OAuth2AccessToken acquireAccessToken(final OAuth2ClientContext oauth2Context) throws UserRedirectRequiredException {
    final OAuth2AccessToken oAuth2AccessToken = super.acquireAccessToken(oauth2Context);
    oAuth2AccessToken.getAdditionalInformation().put("sessionState", getSessionState(oauth2Context));
    return oAuth2AccessToken;
  }

  private String getSessionState(final OAuth2ClientContext oauth2Context) {
    final AccessTokenRequest accessTokenRequest = oauth2Context.getAccessTokenRequest();
    final List<String> list = accessTokenRequest.get("session_state");
    if (list == null || list.isEmpty()) {
      return "";
    }
    return list.get(0);
  }
}
