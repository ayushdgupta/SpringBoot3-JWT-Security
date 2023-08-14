package com.guptaji.JWTDemo.SpringSecurityJWTDemo.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

  @Value("${user1.name}")
  private String user1Name;

  @Value("${user2.name}")
  private String user2Name;

  @Value("${user3.name}")
  private String user3Name;

  @Value("${user1.pass}")
  private String user1Pass;

  @Value("${user2.pass}")
  private String user2Pass;

  @Value("${user3.pass}")
  private String user3Pass;

  @Value("${user1.role}")
  private String user1Role;

  @Value("${user2.role}")
  private String user2Role;

  @Value("${user3.role}")
  private String user3Role;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
        .csrf(
            httpSecurityCsrfConfigurer ->
                httpSecurityCsrfConfigurer.ignoringRequestMatchers(
                    "/DbUserHandling/createNewUser", "/DbUserHandling/getJwtToken"))
        .authorizeHttpRequests(
            authorizeHttpRequest ->
                authorizeHttpRequest
                    .requestMatchers("/DbUserHandling/getJwtToken")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .httpBasic(Customizer.withDefaults());
    return httpSecurity.build();
  }

  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails user1 =
        User.withUsername(user1Name)
            .password(passwordEncoder().encode(user1Pass))
            .roles(user1Role)
            .build();

    UserDetails user2 =
        User.withUsername(user2Name)
            .password(passwordEncoder().encode(user2Pass))
            .roles(user2Role)
            .build();

    UserDetails user3 =
        User.withUsername(user3Name)
            .password(passwordEncoder().encode(user3Pass))
            .roles(user3Role)
            .build();

    InMemoryUserDetailsManager inMemoryUserDetailsManager =
        new InMemoryUserDetailsManager(user1, user2, user3);
    return inMemoryUserDetailsManager;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration)
      throws Exception {
    return configuration.getAuthenticationManager();
  }
}
