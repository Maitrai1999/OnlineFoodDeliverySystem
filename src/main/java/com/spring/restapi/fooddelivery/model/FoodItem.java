package com.spring.restapi.fooddelivery.model;

import java.util.List;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.spring.restapi.fooddelivery.dto.FoodItemDto;

@Entity
@Table(name = "fooditems")
public class FoodItem {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

	private @NotNull String name;
	private @NotNull String imageURL;
	private @NotNull double price;
	private @NotNull String description;

	@JsonIgnore
	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "category_id", nullable = false)
	Category category;

	@JsonIgnore
	@OneToMany(fetch = FetchType.LAZY, mappedBy = "fooditem")
	private List<Cart> carts;

	public FoodItem(FoodItemDto fooditemDto, Category category) {
		this.name = fooditemDto.getName();
		this.imageURL = fooditemDto.getImageURL();
		this.description = fooditemDto.getDescription();
		this.price = fooditemDto.getPrice();
		this.category = category;
	}

	public FoodItem(String name, String imageURL, double price, String description, Category category) {
		super();
		this.name = name;
		this.imageURL = imageURL;
		this.price = price;
		this.description = description;
		this.category = category;
	}

	public FoodItem() {
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getImageURL() {
		return imageURL;
	}

	public void setImageURL(String imageURL) {
		this.imageURL = imageURL;
	}

	public double getPrice() {
		return price;
	}

	public void setPrice(double price) {
		this.price = price;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public Category getCategory() {
		return category;
	}

	public void setCategory(Category category) {
		this.category = category;
	}

	@Override
	public String toString() {
		return "FoodItem{" + "id=" + id + ", name='" + name + '\'' + ", imageURL='" + imageURL + '\'' + ", price="
				+ price + ", description='" + description + '\'' + '}';
	}
}