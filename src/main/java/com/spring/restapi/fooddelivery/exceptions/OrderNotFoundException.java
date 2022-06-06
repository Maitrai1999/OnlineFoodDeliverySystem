package com.spring.restapi.fooddelivery.exceptions;
public class OrderNotFoundException extends IllegalArgumentException {
    public OrderNotFoundException(String msg) {
        super(msg);
    }
}