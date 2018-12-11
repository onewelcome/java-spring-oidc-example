package com.onegini.oidc.config;

import static com.fasterxml.jackson.databind.PropertyNamingStrategy.SNAKE_CASE;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
public class RestTemplateConfiguration {

  @Bean
  public RestTemplate restTemplate(final MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter) {
    final RestTemplate template = new RestTemplate();
    template.setMessageConverters(Arrays.asList(mappingJackson2HttpMessageConverter));
    return template;
  }

  @Bean
  public MappingJackson2HttpMessageConverter jackson2ObjectMapperBuilder(final ObjectMapper objectMapper) {
    return new MappingJackson2HttpMessageConverter(objectMapper);
  }

  @Bean
  public ObjectMapper jacksonObjectMapper() {
    return new Jackson2ObjectMapperBuilder().propertyNamingStrategy(SNAKE_CASE).build();
  }

}