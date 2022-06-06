package com.spring.restapi.fooddelivery.dao;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.spring.restapi.fooddelivery.model.Admin;


@Repository
public interface AdminRepository extends JpaRepository<Admin, Integer> {

    List<Admin> findAll();

	Admin findByEmail(String email);
}