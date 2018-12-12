package com.onegini.oidc.encryption;

import static org.apache.commons.lang3.StringUtils.isBlank;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class JweDecrypterService {

  @Resource
  private JwkSetProvider jwkSetProvider;

  public JWT decrypt(final JWEObject jweObject) {
    validateKeyIdExists(jweObject);

    final JWK relevantKey = getRelevantKey(jweObject);
    final JWEDecrypter decrypter = getDecrypter(relevantKey);

    try {
      jweObject.decrypt(decrypter);
      return jweObject.getPayload().toSignedJWT();
    } catch (final JOSEException e) {
      throw new IllegalStateException("Could not decrypt the JWT", e);
    }
  }

  private void validateKeyIdExists(final JWEObject jweObject) {
    if (isBlank(jweObject.getHeader().getKeyID())) {
      throw new IllegalArgumentException("JWE does not contain a key id");
    }
  }

  private JWK getRelevantKey(final JWEObject jweObject) {
    final JWKSet privateJWKS = jwkSetProvider.getPrivateJWKS(jweObject.getHeader().getAlgorithm());
    final JWK relevantKey = privateJWKS.getKeyByKeyId(jweObject.getHeader().getKeyID());

    if (relevantKey == null) {
      //The Server may have cached the JWKSet response and when this app was restarted, it generated new keys which would not match
      log.debug("Could not match the keyId with any of the private keys provided.");
      throw new IllegalArgumentException("JWK set does not contain a relevant JWK.");
    }

    return relevantKey;
  }

  private JWEDecrypter getDecrypter(final JWK jwk) {
    final KeyType keyType = jwk.getKeyType();
    try {
      if (KeyType.RSA.equals(keyType)) {
        return new RSADecrypter((RSAKey) jwk);
      }
      if (KeyType.EC.equals(keyType)) {
        return new ECDHDecrypter((ECKey) jwk);
      }
      throw new IllegalStateException(String.format("Unsupported KeyType (%s)", jwk.getKeyType()));
    } catch (final JOSEException e) {
      final String msg = String.format("Could not create the JWE decrypter for type (%s).", keyType);
      throw new IllegalStateException(msg, e);
    }
  }
}
