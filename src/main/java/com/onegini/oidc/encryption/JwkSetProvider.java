package com.onegini.oidc.encryption;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import com.google.common.collect.Lists;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import net.minidev.json.JSONObject;

@Service
public class JwkSetProvider {

  @Resource
  private JweKeyGenerator jweKeyGenerator;

  private final Map<String, JWKSet> jwksSetMapCache = new HashMap<>();

  public JSONObject getPublicJWKS(final JWEAlgorithm jweAlgorithm) {
    return getJWKSet(jweAlgorithm).toJSONObject(true);
  }

  JWKSet getPrivateJWKS(final JWEAlgorithm jweAlgorithm) {
    return getJWKSet(jweAlgorithm);
  }

  private JWKSet getJWKSet(final JWEAlgorithm jweAlgorithm) {
    if (jwksSetMapCache.get(jweAlgorithm.getName()) == null) {
      jwksSetMapCache.put(jweAlgorithm.getName(), createJwksSetForKeyType(jweAlgorithm));
    }
    return jwksSetMapCache.get(jweAlgorithm.getName());
  }

  private JWKSet createJwksSetForKeyType(final JWEAlgorithm jweAlgorithm) {
    final JWK jwk1 = jweKeyGenerator.generateKey(jweAlgorithm);
    final JWK jwk2 = jweKeyGenerator.generateKey(jweAlgorithm);
    return new JWKSet(Lists.newArrayList(jwk1, jwk2));
  }

}
