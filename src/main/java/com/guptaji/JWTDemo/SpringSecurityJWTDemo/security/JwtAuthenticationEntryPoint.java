 package com.guptaji.JWTDemo.SpringSecurityJWTDemo.security;

 import jakarta.servlet.http.HttpServletRequest;
 import jakarta.servlet.http.HttpServletResponse;

 import java.io.IOException;
 import java.io.PrintWriter;

 import org.springframework.security.core.AuthenticationException;
 import org.springframework.security.web.AuthenticationEntryPoint;
 import org.springframework.stereotype.Component;

 @Component
 public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

  @Override
  public void commence(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException authException)
      throws IOException {
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setHeader("ErrorMessage", "Sahi JWT bhej bhootni ke");
    PrintWriter printWriter = response.getWriter();
    printWriter.println("Access Denied !! " + authException.getMessage());
  }
 }
