package com.onegini.oidc.security;

import java.net.MalformedURLException;
import java.net.URL;

import javax.annotation.Resource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
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
import com.onegini.oidc.model.OpenIdWellKnownConfiguration;

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
  private OpenIdWellKnownConfiguration openIdWellKnownConfiguration;

  void validateToken(final JWT idToken) {
    // JWT header contains the signing algorithm
    final JWSAlgorithm algorithm = (JWSAlgorithm) idToken.getHeader().getAlgorithm();
    // Get JWK Source from the .well-known/openid-configuration endpoint of the OpenID Connect provider (Onegini Token Server)
    final String jwksUri = openIdWellKnownConfiguration.getJwksUri();
    try {
      final JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL(jwksUri));
      final JWSKeySelector jwsKeySelector = new JWSVerificationKeySelector<>(algorithm, jwkSource);
      final IDTokenValidator idTokenValidator = new IDTokenValidator(new Issuer(issuer), new ClientID(clientId), jwsKeySelector, null);
      idTokenValidator.validate(idToken, null);
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException("Unable to convert '" + jwksUri + "' to URL.", e);
    } catch (final Exception e) {
      throw new BadCredentialsException("idToken is not valid", e);
    }

  }
}