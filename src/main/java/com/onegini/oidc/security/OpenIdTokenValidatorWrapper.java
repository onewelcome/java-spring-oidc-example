package com.onegini.oidc.security;

import javax.annotation.Resource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.client.discovery.ProviderConfiguration;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

/**
 * This class is mostly just a wrapper around IDTokenValidator
 */
@Component
public class OpenIdTokenValidatorWrapper {

  @Value("${onegini.oauth2.clientId}")
  private String clientId;
  @Value("${onegini.oauth2.issuer}")
  private String issuer;
  @Resource
  private ProviderConfiguration providerConfiguration;

  void validateToken(final JWT idToken) {
    // JWT header contains the signing algorithm
    final JWSAlgorithm algorithm = (JWSAlgorithm) idToken.getHeader().getAlgorithm();
    // Get JWK Source from the .well-known/openid-configuration endpoint of the OpenID Connect provider (Onegini Token Server)
    final JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(providerConfiguration.getJwkSetUri());
    final JWSKeySelector jwsKeySelector = new JWSVerificationKeySelector<>(algorithm, jwkSource);

    final IDTokenValidator idTokenValidator = new IDTokenValidator(new Issuer(issuer), new ClientID(clientId), jwsKeySelector, null);
    try {
      idTokenValidator.validate(idToken, null);
    } catch (final Exception e) {
      throw new BadCredentialsException("idToken is not valid", e);
    }

  }
}