package com.onegini.oidc;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.JWEAlgorithm;
import com.onegini.oidc.config.ApplicationProperties;
import com.onegini.oidc.encryption.JwkSetProvider;
import com.onegini.oidc.model.EncryptionAlgorithms;
import net.minidev.json.JSONObject;

@RestController
public class WellKnownJwksController {
  public static final String PAGE_WELL_KNOWN_JWKS = "/.well-known/jwks.json";
  private static final String WELL_KNOWN_CONFIG_PATH = "/.well-known/openid-configuration";

  @Resource
  private ApplicationProperties applicationProperties;
  @Resource
  private RestTemplate restTemplate;
  @Resource
  private JwkSetProvider jwkSetProvider;

  @GetMapping(PAGE_WELL_KNOWN_JWKS)
  private JSONObject getJwks(final HttpServletRequest request, final HttpServletResponse response) {
    final JWEAlgorithm encryptionAlgorithm = getMostAdequateSupportedAlgorithm();
    //We return filtered list with the encryption keys (only public part). Token Server use first one that match its criteria.
    return jwkSetProvider.getPublicJWKS(encryptionAlgorithm);
  }

  private JWEAlgorithm getMostAdequateSupportedAlgorithm() {
    //We should get a list of supported encryption algorithms from Token Server and select one which is also proper for us
    final Map configuration = restTemplate.getForObject(applicationProperties.getIssuer() + WELL_KNOWN_CONFIG_PATH, Map.class);
    @SuppressWarnings("squid:S2583") final List<String> supportedEncryptionAlgorithms = (List<String>) configuration
        .get("id_token_encryption_alg_values_supported");

    final Optional<JWEAlgorithm> mostAdequateSupportedAlgorithm = EncryptionAlgorithms.ENCRYPTION_ALGORITHMS_PRIORITY.stream()
        .filter(alg -> supportedEncryptionAlgorithms.contains(alg.getName()))
        .findFirst();

    return mostAdequateSupportedAlgorithm.orElseThrow(() -> new RuntimeException("Supported algorithm wasn't found in Token Server"));
  }

}