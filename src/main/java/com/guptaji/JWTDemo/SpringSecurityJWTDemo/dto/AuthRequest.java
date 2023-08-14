package com.guptaji.JWTDemo.SpringSecurityJWTDemo.dto;

public class AuthRequest {

  private String userName;
  private String password;

  public AuthRequest() {
    // Default constructor
  }

  public AuthRequest(String userName, String password) {
    this.userName = userName;
    this.password = password;
  }

  public String getUserName() {
    return userName;
  }

  public void setUserName(String userName) {
    this.userName = userName;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  @Override
  public String toString() {
    return "AuthRequest{" + "userName='" + userName + '\'' + ", password='" + password + '\'' + '}';
  }
}
