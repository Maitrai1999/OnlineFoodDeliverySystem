package com.spring.restapi.fooddelivery.model;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "orderitems")
public class OrderItem {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

	@NotNull
	@Column(name = "quantity")
	private @NotNull int quantity;

	@NotNull
	@Column(name = "price")
	private @NotNull double price;

	@NotNull
	@Column(name = "created_date")
	private Date createdDate;

	@ManyToOne
	@JsonIgnore
	@JoinColumn(name = "order_id", referencedColumnName = "id")
	private Order order;

	@OneToOne
	@JoinColumn(name = "fooditem_id", referencedColumnName = "id")
	private FoodItem fooditem;

	public OrderItem() {
	}

	public OrderItem(Integer id, @NotNull @NotNull int quantity, @NotNull @NotNull double price,
			@NotNull Date createdDate, Order order, FoodItem fooditem) {
		super();
		this.id = id;
		this.quantity = quantity;
		this.price = price;
		this.createdDate = createdDate;
		this.order = order;
		this.fooditem = fooditem;
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public int getQuantity() {
		return quantity;
	}

	public void setQuantity(int quantity) {
		this.quantity = quantity;
	}

	public double getPrice() {
		return price;
	}

	public void setPrice(double price) {
		this.price = price;
	}

	public Date getCreatedDate() {
		return createdDate;
	}

	public void setCreatedDate(Date createdDate) {
		this.createdDate = createdDate;
	}

	public Order getOrder() {
		return order;
	}

	public void setOrder(Order order) {
		this.order = order;
	}

	public FoodItem getFooditem() {
		return fooditem;
	}

	public void setFooditem(FoodItem fooditem) {
		this.fooditem = fooditem;
	}
}