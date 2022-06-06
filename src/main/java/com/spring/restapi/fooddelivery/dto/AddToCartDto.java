package com.spring.restapi.fooddelivery.dto;

import javax.validation.constraints.NotNull;

public class AddToCartDto {
	private Integer id;
	private @NotNull Integer fooditemId;
	private @NotNull Integer quantity;

	public AddToCartDto() {
	}

	@Override
	public String toString() {
		return "CartDto{" + "id=" + id + ", fooditemId=" + fooditemId + ", quantity=" + quantity + ",";
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public Integer getFooditemId() {
		return fooditemId;
	}

	public void setFooditemId(Integer fooditemId) {
		this.fooditemId = fooditemId;
	}

	public Integer getQuantity() {
		return quantity;
	}

	public void setQuantity(Integer quantity) {
		this.quantity = quantity;
	}
}