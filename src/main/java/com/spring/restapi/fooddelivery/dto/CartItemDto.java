package com.spring.restapi.fooddelivery.dto;

import javax.validation.constraints.NotNull;

import com.spring.restapi.fooddelivery.model.Cart;
import com.spring.restapi.fooddelivery.model.FoodItem;

public class CartItemDto {
	private Integer id;
	private @NotNull Integer quantity;
	private @NotNull FoodItem fooditem;

	public CartItemDto() {
	}

	public CartItemDto(Cart cart) {
		this.setId(cart.getId());
		this.setQuantity(cart.getQuantity());
		this.setFooditem(cart.getFooditem());
	}

	@Override
	public String toString() {
		return "CartDto{" + "id=" + id + ", quantity=" + quantity + ", fooditemName=" + fooditem.getName() + '}';
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public Integer getQuantity() {
		return quantity;
	}

	public void setQuantity(Integer quantity) {
		this.quantity = quantity;
	}

	public FoodItem getFooditem() {
		return fooditem;
	}

	public void setFooditem(FoodItem fooditem) {
		this.fooditem = fooditem;
	}
}