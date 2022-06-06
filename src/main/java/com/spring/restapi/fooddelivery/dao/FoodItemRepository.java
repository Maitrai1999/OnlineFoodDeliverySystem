package com.spring.restapi.fooddelivery.dao;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.spring.restapi.fooddelivery.model.FoodItem;

@Repository
public interface FoodItemRepository extends JpaRepository<FoodItem, Integer> {
	@Query("select f from FoodItem f where concat(f.name,f.description) like %?3%")
	public List<FoodItem> search(String keyword);

}