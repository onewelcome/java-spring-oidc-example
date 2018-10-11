package com.onegini.oidc.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import com.onegini.oidc.IndexController;
import com.onegini.oidc.LogoutController;
import com.onegini.oidc.SampleSecuredController;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

  private static final String LOGIN_URL = "/login";

  @Bean
  public AuthenticationEntryPoint authenticationEntryPoint() {
    return new LoginUrlAuthenticationEntryPoint(LOGIN_URL);
  }

  @Bean
  public OpenIdConnectAuthenticationFilter openIdConnectAuthenticationFilter() {
    return new OpenIdConnectAuthenticationFilter(LOGIN_URL);
  }

  @Bean
  public OAuth2ClientContextFilter oAuth2ClientContextFilter() {
    return new OAuth2ClientContextFilter();
  }

  @Override
  public void configure(final WebSecurity web) {
    web
        .ignoring()
        .antMatchers("/static/**", "/favicon.ico");
  }

  @Override
  protected void configure(final HttpSecurity http) throws Exception {
    http.addFilterAfter(oAuth2ClientContextFilter(), AbstractPreAuthenticatedProcessingFilter.class)
        .addFilterAfter(openIdConnectAuthenticationFilter(), OAuth2ClientContextFilter.class)
        .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
        .and()
        .authorizeRequests()
        .antMatchers("/", "/logout", "/signout-callback-oidc").permitAll()
        .antMatchers("/static/**", "/favicon.ico").permitAll()
        .antMatchers(SampleSecuredController.PAGE_SECURED).authenticated()
        .and()
        .logout()
        .logoutUrl(LogoutController.PAGE_LOGOUT)
        .logoutSuccessUrl(IndexController.PAGE_INDEX);

  }
}
