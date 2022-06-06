package com.spring.restapi.fooddelivery.exceptions;
public class AuthenticationFailException extends IllegalArgumentException {
    public AuthenticationFailException(String msg) {
        super(msg);
    }
}
