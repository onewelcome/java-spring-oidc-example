package com.onegini.oidc.model;

import com.nimbusds.jwt.JWTClaimsSet;

public class TokenDetails {

  private final JWTClaimsSet jwtClaimsSet;

  public TokenDetails(final JWTClaimsSet jwtClaimsSet) {
    this.jwtClaimsSet = jwtClaimsSet;
  }

  public JWTClaimsSet getJwtClaimsSet() {
    return jwtClaimsSet;
  }

}