package com.onegini.oidc.model;

import com.nimbusds.jwt.JWTClaimsSet;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class TokenDetails {
  private final JWTClaimsSet jwtClaimsSet;
}