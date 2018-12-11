package com.onegini.oidc.encryption;

import static com.nimbusds.jose.jwk.Curve.P_256;
import static com.nimbusds.jose.jwk.KeyType.EC;
import static com.nimbusds.jose.jwk.KeyType.RSA;
import static com.nimbusds.jose.jwk.KeyUse.ENCRYPTION;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.onegini.oidc.JweWellKnownJwksController;

@Service
class JweKeyGenerator {

  private static final Logger LOG = LoggerFactory.getLogger(JweWellKnownJwksController.class);
  private static final int RSA_KEYSIZE = 2048;

  JWK generateKey(final JWEAlgorithm jweAlgorithm) {
    if (JWEAlgorithm.Family.RSA.contains(jweAlgorithm)) {
      return generateRSAKey(jweAlgorithm);
    } else if (JWEAlgorithm.Family.ECDH_ES.contains(jweAlgorithm)) {
      return generateECKey(jweAlgorithm);
    } else {
      LOG.error("Unsupported Algorithm ({})", jweAlgorithm);
      return null;
    }
  }

  private JWK generateRSAKey(final JWEAlgorithm jweAlgorithm) {
    try {
      final KeyPairGenerator gen = KeyPairGenerator.getInstance(RSA.getValue());
      gen.initialize(RSA_KEYSIZE);
      final KeyPair keyPair = gen.generateKeyPair();

      return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
          .privateKey((RSAPrivateKey) keyPair.getPrivate())
          .keyUse(ENCRYPTION)
          .keyID(UUID.randomUUID().toString())
          .algorithm(jweAlgorithm)
          .build();
    } catch (final NoSuchAlgorithmException e) {
      LOG.error("Generating a RSA key failed.", e);
    }
    return null;
  }

  private JWK generateECKey(final JWEAlgorithm jweAlgorithm) {
    try {
      final KeyPairGenerator gen = KeyPairGenerator.getInstance(EC.getValue());
      gen.initialize(P_256.toECParameterSpec());
      final KeyPair keyPair = gen.generateKeyPair();

      return new ECKey.Builder(P_256, (ECPublicKey) keyPair.getPublic())
          .privateKey((ECPrivateKey) keyPair.getPrivate())
          .keyUse(ENCRYPTION)
          .keyID(UUID.randomUUID().toString())
          .algorithm(jweAlgorithm)
          .build();
    } catch (final NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      LOG.error("Generating a EC key failed.", e);
    }
    return null;
  }
}
