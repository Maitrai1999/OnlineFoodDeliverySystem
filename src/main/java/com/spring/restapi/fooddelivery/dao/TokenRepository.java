package com.spring.restapi.fooddelivery.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.spring.restapi.fooddelivery.model.Admin;
import com.spring.restapi.fooddelivery.model.AuthenticationToken;
import com.spring.restapi.fooddelivery.model.User;

@Repository
public interface TokenRepository extends JpaRepository<AuthenticationToken, Integer> {
    AuthenticationToken findTokenByUser(User user);
    AuthenticationToken findTokenByToken(String token);
}
