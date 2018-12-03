package com.onegini.oidc.model;

import java.util.Arrays;
import java.util.List;

import com.nimbusds.jose.JWEAlgorithm;

public interface EncryptionAlgorithms {

  JWEAlgorithm RSA_OAEP_256 = JWEAlgorithm.RSA_OAEP_256;
  JWEAlgorithm ECDH_ES = JWEAlgorithm.ECDH_ES;
  JWEAlgorithm RSA_OAEP = JWEAlgorithm.RSA_OAEP;

  List<JWEAlgorithm> ENCRYPTION_ALGORITHMS_PRIORITY = Arrays.asList(new JWEAlgorithm[]{ RSA_OAEP_256, ECDH_ES, RSA_OAEP });
}
