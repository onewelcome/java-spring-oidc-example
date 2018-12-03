package com.onegini.oidc.encryption;

import java.util.List;
import java.util.stream.Collectors;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.onegini.oidc.model.EncryptionAlgorithms;
import net.minidev.json.JSONObject;

@Service
public class JwkSetProvider {

  @Resource
  private JweKeyGenerator jweKeyGenerator;

  /* For demo purpose, keys are generated each time application starts, but keys should be store in persistence storage */
  private final Supplier<JWKSet> jwkSetSupplier = Suppliers.memoize(this::jwksSupplier);

  private JWKSet jwksSupplier() {
    final List<JWK> jwksList = EncryptionAlgorithms.ENCRYPTION_ALGORITHMS_PRIORITY.stream()
        .map(jweAlgorithm -> jweKeyGenerator.generateKey(KeyType.RSA, jweAlgorithm))
        .collect(Collectors.toList());
    final JWKSet jwkSet = new JWKSet(jwksList);
    return jwkSet;
  }

  private JWKSet getJWKS() {
    return jwkSetSupplier.get();
  }

  public JSONObject getPublicJWKS(final JWEAlgorithm encryptionAlgorithm) {
    final JWKSet jwkSet = getJWKS();
    final JWKMatcher matcher = new JWKMatcher.Builder().algorithm(encryptionAlgorithm).build();

    final List<JWK> matches = new JWKSelector(matcher).select(jwkSet);

    if (matches != null && !matches.isEmpty()) {
      return new JWKSet(matches).toJSONObject(true);
    } else {
      final String details = "Not supported JWK was found.";
      throw new IllegalArgumentException(details);
    }
  }

  public JWKSet getPrivateJWKS() {
    return getJWKS();
  }


}
