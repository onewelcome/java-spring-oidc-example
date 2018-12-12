package com.onegini.oidc.model;

import static org.apache.commons.lang3.StringUtils.isNotBlank;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class UserInfo {

  private final String id;
  private final String name;
  private final String idToken;
  private final String encryptedIdToken;

  public boolean isEncryptionEnabled() {
    return isNotBlank(encryptedIdToken);
  }
}