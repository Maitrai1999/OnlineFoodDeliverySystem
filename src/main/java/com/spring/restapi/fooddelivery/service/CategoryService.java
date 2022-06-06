package com.spring.restapi.fooddelivery.service;

import java.util.List;
import java.util.Optional;
import javax.transaction.Transactional;
import org.springframework.stereotype.Service;

import com.spring.restapi.fooddelivery.dao.CategoryRepository;
import com.spring.restapi.fooddelivery.model.Category;

@Service
@Transactional
public class CategoryService {

	private final CategoryRepository categoryrepository;

	public CategoryService(CategoryRepository categoryrepository) {
		this.categoryrepository = categoryrepository;
	}

	public List<Category> listCategories() {
		return categoryrepository.findAll();
	}

	public void createCategory(Category category) {
		categoryrepository.save(category);
	}

	public Category readCategory(String categoryName) {
		return categoryrepository.findByCategoryName(categoryName);
	}

	public Optional<Category> readCategory(Integer categoryId) {
		return categoryrepository.findById(categoryId);
	}

	public void updateCategory(Integer categoryID, Category newCategory) {
		Category category = categoryrepository.findById(categoryID).get();
		category.setCategoryName(newCategory.getCategoryName());
		category.setDescription(newCategory.getDescription());
		category.setFooditems(newCategory.getFooditems());
		category.setImageUrl(newCategory.getImageUrl());

		categoryrepository.save(category);
	}
}