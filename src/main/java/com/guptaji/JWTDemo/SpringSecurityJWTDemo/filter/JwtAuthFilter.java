package com.guptaji.JWTDemo.SpringSecurityJWTDemo.filter;

import com.guptaji.JWTDemo.SpringSecurityJWTDemo.service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

  Logger LOG = LogManager.getLogger(JwtAuthFilter.class);

  private final String AUTHORIZATION = "Authorization";
  private final String BEARER = "Bearer ";

  @Autowired private JwtService jwtService;

  @Autowired private UserDetailsService userDetailsService;

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    LOG.info("Running OncePerRequest filter");
    String authHeader = request.getHeader(AUTHORIZATION);
    String token = null, userName = null;

    if (authHeader != null && authHeader.startsWith(BEARER)) {
      token = authHeader.substring(BEARER.length());
      userName = jwtService.extractUserName(token);
      LOG.info("UserName fetched from Jwt {}", userName);
    }

    if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
      LOG.info("fetched userDetails to verify token");
      if (jwtService.validateToken(token, userDetails)) {
        UsernamePasswordAuthenticationToken authenticationToken =
            new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
      }
    }
    filterChain.doFilter(request, response);
  }
}
