package com.spring.restapi.fooddelivery.exceptions;
public class FoodItemNotExistException extends IllegalArgumentException {
    public FoodItemNotExistException(String msg) {
        super(msg);
    }
}