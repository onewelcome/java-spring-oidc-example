package com.onegini.oidc.encryption;

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
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.onegini.oidc.WellKnownJwksController;

@Service
public class JweKeyGenerator {

  private static final Logger LOG = LoggerFactory.getLogger(WellKnownJwksController.class);
  private static final int RSA_KEYSIZE = 2048;

  public JWK generateKey(final KeyType keyType, final JWEAlgorithm jweAlgorithm) {
    if (KeyType.RSA.equals(keyType)) {
      return generateRSAKey(keyType, jweAlgorithm);
    } else if (KeyType.EC.equals(keyType)) {
      return generateECKey(keyType, jweAlgorithm);
    } else {
      LOG.error("No supported KeyType ({})", keyType);
      return null;
    }
  }

  private JWK generateRSAKey(final KeyType keyType, final JWEAlgorithm jweAlgorithm) {
    try {
      final KeyPairGenerator gen = KeyPairGenerator.getInstance(keyType.getValue());
      gen.initialize(RSA_KEYSIZE);
      final KeyPair keyPair = gen.generateKeyPair();

      final JWK jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
          .privateKey((RSAPrivateKey) keyPair.getPrivate())
          .keyUse(KeyUse.ENCRYPTION)
          .keyID(UUID.randomUUID().toString())
          .algorithm(jweAlgorithm)
          .build();
      return jwk;
    } catch (final NoSuchAlgorithmException e) {
      LOG.error("Generating a RSA key failed.", e);
    }
    return null;
  }

  private JWK generateECKey(final KeyType keyType, final JWEAlgorithm jweAlgorithm) {
    try {
      final KeyPairGenerator gen = KeyPairGenerator.getInstance(keyType.getValue());
      gen.initialize(Curve.P_256.toECParameterSpec());
      final KeyPair keyPair = gen.generateKeyPair();

      final JWK jwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
          .privateKey((ECPrivateKey) keyPair.getPrivate())
          .keyUse(KeyUse.ENCRYPTION)
          .keyID(UUID.randomUUID().toString())
          .algorithm(jweAlgorithm)
          .build();
      return jwk;
    } catch (final NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      LOG.error("Generating a EC key failed.", e);
    }
    return null;
  }
}
