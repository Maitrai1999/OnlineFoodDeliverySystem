package com.spring.restapi.fooddelivery.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.spring.restapi.fooddelivery.model.OrderItem;

public interface OrderItemsRepository extends JpaRepository<OrderItem, Integer> {

}