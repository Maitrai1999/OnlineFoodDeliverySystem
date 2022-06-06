package com.spring.restapi.fooddelivery.controller;

import java.util.List;
import java.util.Optional;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.repository.query.Param;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring.restapi.fooddelivery.dto.FoodItemDto;
import com.spring.restapi.fooddelivery.model.Category;
import com.spring.restapi.fooddelivery.model.FoodItem;
import com.spring.restapi.fooddelivery.response.ApiResponse;
import com.spring.restapi.fooddelivery.service.CategoryService;
import com.spring.restapi.fooddelivery.service.FoodItemService;

@RestController
@RequestMapping("/fooditems")
public class FoodItemController {
    @Autowired FoodItemService fooditemService;
    @Autowired
    CategoryService categoryService;

    @GetMapping("/")
    public ResponseEntity<List<FoodItemDto>> getfooditems() {
        List<FoodItemDto> body = fooditemService.listFoodItems();
        return new ResponseEntity<List<FoodItemDto>>(body, HttpStatus.OK);
    }
    @PostMapping("/add")
    public ResponseEntity<ApiResponse> addProduct(@RequestBody FoodItemDto fooditemDto) {
        Optional<Category> optionalCategory = categoryService.readCategory(fooditemDto.getCategoryId());
        if (!optionalCategory.isPresent()) {
            return new ResponseEntity<ApiResponse>(new ApiResponse(false, "category is invalid"), HttpStatus.CONFLICT);
        }
        Category category = optionalCategory.get();
        fooditemService.addProduct(fooditemDto, category);
        return new ResponseEntity<ApiResponse>(new ApiResponse(true, "FoodItem has been added"), HttpStatus.CREATED);
    }
    @PostMapping("/update/{fooditemID}")
    public ResponseEntity<ApiResponse> updateProduct(@PathVariable("fooditemID") Integer fooditemID, @RequestBody @Valid FoodItemDto fooditemDto) {
        Optional<Category> optionalCategory = categoryService.readCategory(fooditemDto.getCategoryId());
        if (!optionalCategory.isPresent()) {
            return new ResponseEntity<ApiResponse>(new ApiResponse(false, "category is invalid"), HttpStatus.CONFLICT);
        }
        Category category = optionalCategory.get();
        fooditemService.updateFoodItem(fooditemID, fooditemDto, category);
        return new ResponseEntity<ApiResponse>(new ApiResponse(true, "FoodItem has been updated"), HttpStatus.OK);
    }
    @GetMapping("/search/{fooditemID}")
    public ResponseEntity<List<FoodItem>> viewHomePage(@Param("keyword") String keyword) {
    	List<FoodItem> body = fooditemService.listAll(keyword);
    	return new ResponseEntity<List<FoodItem>>(body,HttpStatus.OK);
    }
}