package com.onegini.oidc;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

  public static final String PAGE_INDEX = "/";

  @GetMapping(PAGE_INDEX)
  public String index() {
    return "index";
  }

}