package com.onegini.oidc;

import static com.nimbusds.jose.JWEAlgorithm.ECDH_ES;
import static java.util.concurrent.TimeUnit.SECONDS;
import static javax.servlet.http.HttpServletResponse.SC_OK;

import javax.annotation.Resource;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.onegini.oidc.encryption.JwkSetProvider;
import com.onegini.oidc.model.OpenIdDiscovery;

@RestController
@ConditionalOnProperty(value = "onegini.oidc.idTokenEncryptionEnabled", havingValue = "true")
public class JweWellKnownJwksController {
  public static final String JWKS_KEYS_PATH = "/.well-known/jwks.json"; // NOSONAR
  private static final JWEAlgorithm ASYMMETRIC_ENCRYPTION_ALGORITHM = ECDH_ES;
  //Configure this value based on your key rotation plan. The server will cache this response based on this value. Keys should be persisted
  //they are not changing at startup.
  private static final long MAX_AGE = 30;

  @Resource
  private JwkSetProvider jwkSetProvider;
  @Resource
  private OpenIdDiscovery openIdDiscovery;

  @GetMapping(JWKS_KEYS_PATH)
  public ResponseEntity<JWKSet> getJwks() {
    final JWEAlgorithm chosenAlgorithm = ASYMMETRIC_ENCRYPTION_ALGORITHM;
    validateAlgorithmSupport(chosenAlgorithm);
    jwkSetProvider.getPublicJWKS(chosenAlgorithm);

    return ResponseEntity.status(SC_OK)
        .cacheControl(CacheControl.maxAge(MAX_AGE, SECONDS))
        .body(jwkSetProvider.getPublicJWKS(chosenAlgorithm));
  }

  private void validateAlgorithmSupport(final JWEAlgorithm jweAlgorithm) {
    final boolean algorithmNotSupported = openIdDiscovery.getIdTokenEncryptionAlgValuesSupported().stream()
        .map(JWEAlgorithm::parse).noneMatch(alg -> alg.equals(jweAlgorithm));

    if (algorithmNotSupported) {
      throw new IllegalStateException("Algorithm is not supported by OP. Supported algorithms: " +
          StringUtils.collectionToCommaDelimitedString(openIdDiscovery.getIdTokenEncryptionAlgValuesSupported()));
    }
  }

}
