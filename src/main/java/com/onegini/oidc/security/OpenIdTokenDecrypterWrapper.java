package com.onegini.oidc.security;

import java.text.ParseException;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.onegini.oidc.encryption.JweDecrypterService;

/**
 * This class is mostly just a wrapper around IDTokenValidator
 */
@Component
public class OpenIdTokenDecrypterWrapper {

  private static final Logger LOG = LoggerFactory.getLogger(OpenIdTokenDecrypterWrapper.class);

  @Resource
  private JweDecrypterService jweDecrypterService;

  JWT decryptJWE(final EncryptedJWT encryptedJWT) {
    try {
      final String idToken = jweDecrypterService.decrypt(encryptedJWT);
      return JWTParser.parse(idToken);
    } catch (final ParseException | JOSEException e) {
      throw new BadCredentialsException("Decrypting JWT went wrong", e);
    }
  }
}