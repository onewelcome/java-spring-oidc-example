package com.github.fromi.openidconnect.security;

public class UserInfo {
    private String id;
    private String name;
    private String givenName;
    private String familyName;
    private String locale;
    private String preferred_username;

    public UserInfo(){

    }

    public UserInfo setId(final String id) {
        this.id = id;
        return this;
    }

    public UserInfo setName(final String name) {
        this.name = name;
        return this;
    }

    public UserInfo setGivenName(final String givenName) {
        this.givenName = givenName;
        return this;
    }

    public UserInfo setFamilyName(final String familyName) {
        this.familyName = familyName;
        return this;
    }

    public UserInfo setLocale(final String locale) {
        this.locale = locale;
        return this;
    }

    public UserInfo setPreferred_username(final String preferred_username) {
        this.preferred_username = preferred_username;
        return this;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getGivenName() {
        return givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public String getLocale() {
        return locale;
    }

    public String getPreferred_username() {
        return preferred_username;
    }
}
