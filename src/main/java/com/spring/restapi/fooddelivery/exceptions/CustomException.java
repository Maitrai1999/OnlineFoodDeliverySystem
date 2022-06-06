package com.spring.restapi.fooddelivery.exceptions;
public class CustomException extends IllegalArgumentException {
    public CustomException(String msg) {
        super(msg);
    }
}