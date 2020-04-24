package com.onegini.oidc;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;

@Component
public class CookieUtil {

  public static final String SESSION_STATE_COOKIE_NAME = "session_state";
  public static final String ID_TOKEN_COOKIE_NAME = "id_token";

  public void setCookie(final String key, final String value, final int maxAge, final HttpServletResponse response) {
    final Cookie cookie = new Cookie(key, value);
    cookie.setMaxAge(maxAge);
    cookie.setPath("/");
    cookie.setHttpOnly(false);
    cookie.setSecure(false);
    response.addCookie(cookie);
  }

  public void expireCookie(final String key, final HttpServletResponse response) {
    setCookie(key, "", 0, response);
  }
}
