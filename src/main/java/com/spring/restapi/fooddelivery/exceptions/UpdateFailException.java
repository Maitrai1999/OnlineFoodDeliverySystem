package com.spring.restapi.fooddelivery.exceptions;
public class UpdateFailException extends IllegalArgumentException {
    public UpdateFailException(String msg) {
        super(msg);
    }
}