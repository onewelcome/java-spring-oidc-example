package com.github.fromi.openidconnect.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class UserInfo {
    private final String id;
    private final String name;
//    private final String givenName;
//    private final String familyName;
//    private final String locale;
//    private final String preferred_username;

    @JsonCreator
    public UserInfo(@JsonProperty("sub") String id//,
                    //@JsonProperty("name") String name,
                    //@JsonProperty("given_name") String givenName,
                    //@JsonProperty("family_name") String familyName,
                    //@JsonProperty("locale") String locale,
                    //@JsonProperty("preferred_username") String preferred_username
    ){
        this.id = id;
        this.name = id;
        //this.name = name;
        //this.givenName = givenName;
        //this.familyName = familyName;
        //this.locale = locale;
        //this.preferred_username = preferred_username;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

//    public String getGivenName() {
//        return givenName;
//    }
//
//    public String getFamilyName() {
//        return familyName;
//    }
//
//    public String getLocale() {
//        return locale;
//    }
//
//    public String getPreferred_username() {
//        return preferred_username;
//    }
}
