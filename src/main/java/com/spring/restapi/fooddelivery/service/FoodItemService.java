package com.spring.restapi.fooddelivery.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.spring.restapi.fooddelivery.dao.FoodItemRepository;
import com.spring.restapi.fooddelivery.dto.FoodItemDto;
import com.spring.restapi.fooddelivery.exceptions.FoodItemNotExistException;
import com.spring.restapi.fooddelivery.model.Category;
import com.spring.restapi.fooddelivery.model.FoodItem;

@Service
public class FoodItemService {
    @Autowired
    private FoodItemRepository fooditemRepository;

    public List<FoodItemDto> listFoodItems() {
        List<FoodItem> fooditems = fooditemRepository.findAll();
        List<FoodItemDto> fooditemDtos = new ArrayList<>();
        for(FoodItem fooditem : fooditems) {
            FoodItemDto fooditemDto = getDtoFromFoodItem(fooditem);
            fooditemDtos.add(fooditemDto);
        }
        return fooditemDtos;
    }

    public static FoodItemDto getDtoFromFoodItem(FoodItem fooditem) {
        FoodItemDto fooditemDto = new FoodItemDto(fooditem);
        return fooditemDto;
    }

    public static FoodItem getFoodItemFromDto(FoodItemDto fooditemDto, Category category) {
        FoodItem fooditem = new FoodItem(fooditemDto, category);
        return fooditem;
    }
    public void addProduct(FoodItemDto fooditemDto, Category category) {
        FoodItem fooditem = getFoodItemFromDto(fooditemDto, category);
        fooditemRepository.save(fooditem);
    }

    public void updateFoodItem(Integer fooditemID, FoodItemDto fooditemDto, Category category) {
        FoodItem fooditem = getFoodItemFromDto(fooditemDto, category);
        fooditem.setId(fooditemID);
        fooditemRepository.save(fooditem);
    }

    public FoodItem getFoodItemById(Integer fooditemId) throws FoodItemNotExistException {
        Optional<FoodItem> optionalFoodItem = fooditemRepository.findById(fooditemId);
        if (!optionalFoodItem.isPresent())
            throw new FoodItemNotExistException("FoodItem id is invalid " + fooditemId);
        return optionalFoodItem.get();
    }
    
    public List<FoodItem> listAll(String keyword) {
    	if(keyword!= null) {
    		return fooditemRepository.search(keyword);
    	}
    	return fooditemRepository.findAll();
    }
}