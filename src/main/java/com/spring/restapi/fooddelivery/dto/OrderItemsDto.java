package com.spring.restapi.fooddelivery.dto;

import javax.validation.constraints.NotNull;

public class OrderItemsDto {

    private @NotNull double price;
    private @NotNull int quantity;
    private @NotNull int orderId;
    private @NotNull int fooditemId;

    public OrderItemsDto () {}

    public OrderItemsDto(@NotNull double price, @NotNull int quantity, @NotNull int orderId, @NotNull int fooditemId) {
        this.price = price;
        this.quantity = quantity;
        this.orderId = orderId;
        this.fooditemId = fooditemId;
    }

	public double getPrice() {
		return price;
	}

	public void setPrice(double price) {
		this.price = price;
	}

	public int getQuantity() {
		return quantity;
	}

	public void setQuantity(int quantity) {
		this.quantity = quantity;
	}

	public int getOrderId() {
		return orderId;
	}

	public void setOrderId(int orderId) {
		this.orderId = orderId;
	}

	public int getFooditemId() {
		return fooditemId;
	}

	public void setFooditemId(int fooditemId) {
		this.fooditemId = fooditemId;
	}
}