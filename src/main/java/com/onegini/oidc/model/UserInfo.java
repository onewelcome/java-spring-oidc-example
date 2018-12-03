package com.onegini.oidc.model;

public class UserInfo {

  private final String id;
  private final String name;
  private final String idToken;
  private final boolean encryptionEnabled;

  public UserInfo(final String id, final String name, final String idToken, final boolean encryptionEnabled) {
    this.id = id;
    this.name = name;
    this.idToken = idToken;
    this.encryptionEnabled = encryptionEnabled;
  }

  public String getId() {
    return id;
  }

  public String getName() {
    return name;
  }

  public String getIdToken() {
    return idToken;
  }

  public boolean isEncryptionEnabled() {
    return encryptionEnabled;
  }
}