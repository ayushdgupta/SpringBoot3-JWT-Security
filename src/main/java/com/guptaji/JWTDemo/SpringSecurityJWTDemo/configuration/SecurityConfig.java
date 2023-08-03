package com.guptaji.JWTDemo.SpringSecurityJWTDemo.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
        .csrf(
            httpSecurityCsrfConfigurer ->
                httpSecurityCsrfConfigurer.ignoringRequestMatchers("/DbUserHandling/createNewUser"))
        .authorizeHttpRequests(
            authorizeHttpRequest -> authorizeHttpRequest.anyRequest().authenticated())
        .formLogin(Customizer.withDefaults());
    return httpSecurity.build();
  }

  //    @Bean
  //    public PasswordEncoder passwordEncoder() {
  //      return new BCryptPasswordEncoder();
  //    }
}
