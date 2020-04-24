package com.onegini.oidc;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;

import com.onegini.oidc.config.ApplicationProperties;

@Controller
public class RelyingPartySessionController {

  private static final String CLIENT_ID = "clientId";
  @Resource
  private ApplicationProperties applicationProperties;
  @Resource
  private SessionFrameService sessionFrameService;

  @GetMapping("/rpiframe")
  public String sessionFrame(final ModelMap modelMap, final HttpServletRequest request) {
    modelMap.addAttribute(CLIENT_ID, applicationProperties.getClientId());
    sessionFrameService.addSessionFramesAttributes(modelMap, request);

    return "rpiframe";
  }


}
