package com.guptaji.JWTDemo.SpringSecurityJWTDemo.controller;

import com.guptaji.JWTDemo.SpringSecurityJWTDemo.entiry.UserSecurityInfo;
import com.guptaji.JWTDemo.SpringSecurityJWTDemo.service.UserSecurityService;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/DbUserHandling")
public class DBUserController {

  Logger LOG = LogManager.getLogger(DBUserController.class);

  @Autowired public UserSecurityService userSecurityService;

  @PostMapping("/createNewUser")
  public ResponseEntity<?> createUser(@RequestBody UserSecurityInfo userSecurityInfo) {
    LOG.info("Hit create user in DB API");
    userSecurityService.createUserInDB(userSecurityInfo);
    return new ResponseEntity<>("user created", HttpStatus.CREATED);
  }

  @GetMapping("/getAllUser")
  public ResponseEntity<?> getUser() {
    LOG.info("Hit getUser from DB API");
    List<UserSecurityInfo> userSecurityInfo = userSecurityService.fetchAllUsers();
    return new ResponseEntity<>(userSecurityInfo, HttpStatus.OK);
  }
}