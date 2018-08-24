package com.github.fromi.openidconnect.security;

import static org.springframework.security.oauth2.common.AuthenticationScheme.header;
import javax.annotation.Resource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.discovery.ProviderConfiguration;
import org.springframework.security.oauth2.client.discovery.ProviderDiscoveryClient;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import java.util.Arrays;

@Configuration
@EnableOAuth2Client
public class OAuth2Client {
    @Value("${onegini.oauth2.clientId}")
    private String clientId;

    @Value("${onegini.oauth2.clientSecret}")
    private String clientSecret;

    @Value("${onegini.oauth2.issuer}")
    private String issuer;

    @Bean
    public ProviderConfiguration getProviderConfiguration(){
        return new ProviderDiscoveryClient(issuer).discover();
    }

    @Bean
    public OAuth2ProtectedResourceDetails googleOAuth2Details(final ProviderConfiguration providerConfiguration) {

        //setup OAuth
        AuthorizationCodeResourceDetails conf = new AuthorizationCodeResourceDetails();
        conf.setAuthenticationScheme(header);
        conf.setClientAuthenticationScheme(header);
        conf.setClientId(clientId);
        conf.setClientSecret(clientSecret);
        conf.setUserAuthorizationUri(providerConfiguration.getAuthorizationEndpoint().toString());
        conf.setAccessTokenUri(providerConfiguration.getTokenEndpoint().toString());
        conf.setScope(Arrays.asList("openid", "profile"));

        return conf;
    }

    @SuppressWarnings("SpringJavaAutowiringInspection") // Provided by Spring Boot
    @Resource
    private OAuth2ClientContext oAuth2ClientContext;

    @Bean
    @Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
    public OAuth2RestOperations googleOAuth2RestTemplate(final ProviderConfiguration providerConfiguration) {
        return new OAuth2RestTemplate(googleOAuth2Details(providerConfiguration), oAuth2ClientContext);
    }
}
