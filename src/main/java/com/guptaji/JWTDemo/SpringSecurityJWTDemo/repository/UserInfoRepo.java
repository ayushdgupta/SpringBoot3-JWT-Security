package com.guptaji.JWTDemo.SpringSecurityJWTDemo.repository;

import com.guptaji.JWTDemo.SpringSecurityJWTDemo.entiry.UserSecurityInfo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserInfoRepo extends JpaRepository<UserSecurityInfo, String> {}
