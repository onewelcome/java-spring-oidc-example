package com.onegini.oidc.security;

import static org.springframework.security.oauth2.common.AuthenticationScheme.header;

import java.util.Arrays;

import javax.annotation.Resource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.web.client.RestTemplate;

import com.onegini.oidc.config.ApplicationProperties;
import com.onegini.oidc.model.OpenIdWellKnownConfiguration;

@Configuration
@EnableOAuth2Client
public class OAuth2Client {

  private static final String WELL_KNOWN_CONFIG_PATH = "/.well-known/openid-configuration";

  @Resource
  private ApplicationProperties applicationProperties;
  @SuppressWarnings("SpringJavaAutowiringInspection") // Provided by Spring Boot
  @Resource
  private OAuth2ClientContext oAuth2ClientContext;
  @Resource
  private RestTemplate restTemplate;

  @Bean
  public OpenIdWellKnownConfiguration getOpenIdWellKnownConfiguration() {
    return restTemplate.getForObject(applicationProperties.getIssuer() + WELL_KNOWN_CONFIG_PATH, OpenIdWellKnownConfiguration.class);
  }

  @Bean
  public OAuth2ProtectedResourceDetails protectedResourceDetails(final OpenIdWellKnownConfiguration configuration) {

    //setup OAuth
    final AuthorizationCodeResourceDetails conf = new AuthorizationCodeResourceDetails();
    conf.setAuthenticationScheme(header);
    conf.setClientAuthenticationScheme(header);
    conf.setClientId(applicationProperties.getClientId());
    conf.setClientSecret(applicationProperties.getClientSecret());
    conf.setUserAuthorizationUri(configuration.getAuthorizationEndpoint());
    conf.setAccessTokenUri(configuration.getTokenEndpoint());
    conf.setScope(Arrays.asList("openid", "profile"));

    return conf;
  }

  @Bean
  @Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
  public OAuth2RestOperations oAuth2RestOperations(final OpenIdWellKnownConfiguration configuration) {
    return new OAuth2RestTemplate(protectedResourceDetails(configuration), oAuth2ClientContext);
  }
}