package com.onegini.oidc;

import static com.onegini.oidc.CookieUtil.ID_TOKEN_COOKIE_NAME;
import static com.onegini.oidc.CookieUtil.SESSION_STATE_COOKIE_NAME;
import static org.springframework.web.servlet.view.UrlBasedViewResolver.REDIRECT_URL_PREFIX;

import java.security.Principal;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import com.onegini.oidc.model.OpenIdDiscovery;
import com.onegini.oidc.model.UserInfo;
import lombok.extern.slf4j.Slf4j;

@Controller
@Slf4j
public class LogoutController {
  public static final String PAGE_LOGOUT = "/logout";
  public static final String PAGE_LOCAL_LOGOUT = "/logout-local";
  public static final String PAGE_SIGNOUT_CALLBACK_OIDC = "/signout-callback-oidc";
  private static final String PARAM_POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";
  private static final String PARAM_ID_TOKEN_HINT = "id_token_hint";
  private static final String REDIRECT_TO_INDEX = "redirect:/";

  @Resource
  private OpenIdDiscovery openIdDiscovery;
  @Resource
  private CookieUtil cookieUtil;

  @GetMapping(PAGE_LOGOUT)
  public String logout(final HttpServletRequest request, final HttpServletResponse response, final Principal principal) {
    // Fetch UserInfo before authentication is cleared
    final UserInfo userInfo = getUserInfo(principal);

    endSessionInSpringSecurity(request, response);

    if (userInfo != null && StringUtils.isNotBlank(userInfo.getIdToken())) {
      log.info("Has idToken {}", userInfo.getIdToken());
      final String endSessionEndpoint = openIdDiscovery.getEndSessionEndpoint();
      if (StringUtils.isNotBlank(endSessionEndpoint)) {
        return endOpenIdSession(userInfo, endSessionEndpoint);
      }
    }

    return REDIRECT_TO_INDEX;
  }

  // Called when the session frame has detected that the session at the OpenID Provider is no longer valid
  @GetMapping(PAGE_LOCAL_LOGOUT)
  public String logoutInvalidSession(final HttpServletRequest request, final HttpServletResponse response) {
    endSessionInSpringSecurity(request, response);
    return REDIRECT_TO_INDEX;
  }

  @GetMapping(PAGE_SIGNOUT_CALLBACK_OIDC)
  public String callbackOidc() {
    log.info("Signout callback from OP");
    return REDIRECT_TO_INDEX;
  }

  private UserInfo getUserInfo(final Principal principal) {
    if (principal instanceof PreAuthenticatedAuthenticationToken) {
      final PreAuthenticatedAuthenticationToken authenticationToken = (PreAuthenticatedAuthenticationToken) principal;
      return (UserInfo) authenticationToken.getPrincipal();
    }
    return null;
  }

  private void endSessionInSpringSecurity(final HttpServletRequest request, final HttpServletResponse response) {
    final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    cookieUtil.expireCookie(SESSION_STATE_COOKIE_NAME, response);
    cookieUtil.expireCookie(ID_TOKEN_COOKIE_NAME, response);

    if (auth == null) {
      return;
    }
    log.info("End user session in Spring Security");
    new SecurityContextLogoutHandler().logout(request, response, auth);
  }

  private String endOpenIdSession(final UserInfo userInfo, final String endSessionEndpoint) {
    final MultiValueMap<String, String> requestParameters = new LinkedMultiValueMap<>();

    final String postLogoutRedirectUri = ServletUriComponentsBuilder.fromCurrentContextPath().path(PAGE_SIGNOUT_CALLBACK_OIDC).build().toUriString();
    requestParameters.add(PARAM_POST_LOGOUT_REDIRECT_URI, postLogoutRedirectUri);

    // Token Server doesn't know how to decode the token id and it doesn't store encoded token id so passing that won't help to detect which session should be logged out.
    if (!userInfo.isEncryptionEnabled()) {
      requestParameters.add(PARAM_ID_TOKEN_HINT, userInfo.getIdToken());
    }

    final String redirectUri = UriComponentsBuilder.fromUriString(endSessionEndpoint)
        .queryParams(requestParameters)
        .build().toUriString();

    log.info("Redirect to OP end session");
    return REDIRECT_URL_PREFIX + redirectUri;
  }

}