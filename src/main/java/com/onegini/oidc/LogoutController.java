package com.onegini.oidc;

import static org.springframework.web.servlet.view.UrlBasedViewResolver.REDIRECT_URL_PREFIX;

import java.security.Principal;
import java.util.Map;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import com.onegini.oidc.config.ApplicationProperties;
import com.onegini.oidc.model.UserInfo;

@Controller
public class LogoutController {
  public static final String PAGE_LOGOUT = "/logout";
  private static final Logger LOG = LoggerFactory.getLogger(LogoutController.class);
  @SuppressWarnings("squid:S1075")
  private static final String WELL_KNOWN_CONFIG_PATH = "/.well-known/openid-configuration";
  private static final String KEY_END_SESSION_ENDPOINT = "end_session_endpoint";
  private static final String PARAM_POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";
  private static final String PARAM_ID_TOKEN_HINT = "id_token_hint";
  private static final String PAGE_SIGNOUT_CALLBACK_OIDC = "/signout-callback-oidc";
  private static final String REDIRECT_TO_INDEX = "redirect:/";

  @Resource
  private ApplicationProperties applicationProperties;
  @Resource
  private RestTemplate restTemplate;

  @GetMapping(PAGE_LOGOUT)
  private String logout(final HttpServletRequest request, final HttpServletResponse response, final Principal principal) {
    // Save idToken before authentication is cleared
    final UserInfo userInfo = getUserInfo(principal);

    endSessionInSpringSecurity(request, response);

    if (userInfo != null && StringUtils.hasLength(userInfo.getIdToken())) {
      LOG.info("Has idToken {}", userInfo.getIdToken());
      final Map configuration = restTemplate.getForObject(applicationProperties.getIssuer() + WELL_KNOWN_CONFIG_PATH, Map.class);

      @SuppressWarnings("squid:S2583") final String endSessionEndpoint = configuration == null ? null : (String) configuration.get(KEY_END_SESSION_ENDPOINT);

      if (StringUtils.hasLength(endSessionEndpoint)) {
        return endOpenIdSession(userInfo, endSessionEndpoint);
      }
    }

    return REDIRECT_TO_INDEX;
  }

  @GetMapping(PAGE_SIGNOUT_CALLBACK_OIDC)
  public String callbackOidc() {
    LOG.info("Signout callback from OP");
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
    if (auth != null) {
      LOG.info("End user session in Spring Security");
      new SecurityContextLogoutHandler().logout(request, response, auth);
    }
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

    LOG.info("Redirect to OP end session");
    return REDIRECT_URL_PREFIX + redirectUri;
  }

}