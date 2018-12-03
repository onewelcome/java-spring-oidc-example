package com.onegini.oidc.encryption;

import static com.nimbusds.oauth2.sdk.util.StringUtils.isBlank;

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

@Service
public class JweDecrypterService {

  @Resource
  private JwkSetProvider jwkSetProvider;

  public String decrypt(final JWEObject jweObject) throws JOSEException {
    validateKeyIdExists(jweObject);

    final JWK relevantKey = getRelevantKey(jweObject);
    final JWEDecrypter decrypter = getDecrypter(relevantKey);

    jweObject.decrypt(decrypter);
    return jweObject.getPayload().toString();
  }

  private void validateKeyIdExists(final JWEObject jweObject) {
    if (isBlank(jweObject.getHeader().getKeyID())) {
      throw new IllegalArgumentException("JWE doesn't contains a key id");
    }
  }

  private JWK getRelevantKey(final JWEObject jweObject) {
    final JWKSet privateJWKS = jwkSetProvider.getPrivateJWKS();
    final JWK relevantKey = privateJWKS.getKeyByKeyId(jweObject.getHeader().getKeyID());
    if (relevantKey != null) {
      return relevantKey;
    } else {
      throw new IllegalArgumentException("JWK set isn't contains a relevant JWK.");
    }
  }

  private JWEDecrypter getDecrypter(final JWK jwk) {
    final KeyType keyType = jwk.getKeyType();
    try {
      if (KeyType.RSA.equals(keyType)) {
        return new RSADecrypter((RSAKey) jwk);
      } else if (KeyType.EC.equals(keyType)) {
        return new ECDHDecrypter((ECKey) jwk);
      } else {
        throw new IllegalStateException(String.format("Unsupported type of key (%s)", jwk.getKeyType()));
      }
    } catch (final JOSEException e) {
      final String msg = String.format("Could not create the JWE decrypter for type (%s).", keyType);
      throw new RuntimeException(msg, e);
    }
  }

}
