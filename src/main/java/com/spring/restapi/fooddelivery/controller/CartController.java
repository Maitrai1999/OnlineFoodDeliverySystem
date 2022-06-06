package com.spring.restapi.fooddelivery.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.spring.restapi.fooddelivery.dto.AddToCartDto;
import com.spring.restapi.fooddelivery.dto.CartDto;
import com.spring.restapi.fooddelivery.exceptions.AuthenticationFailException;
import com.spring.restapi.fooddelivery.exceptions.CartItemNotExistException;
import com.spring.restapi.fooddelivery.exceptions.FoodItemNotExistException;
import com.spring.restapi.fooddelivery.model.FoodItem;
import com.spring.restapi.fooddelivery.model.User;
import com.spring.restapi.fooddelivery.response.ApiResponse;
import com.spring.restapi.fooddelivery.service.AuthenticationService;
import com.spring.restapi.fooddelivery.service.CartService;
import com.spring.restapi.fooddelivery.service.FoodItemService;

@RestController
@RequestMapping("/cart")
public class CartController {
    @Autowired
    private CartService cartService;

    @Autowired
    private FoodItemService fooditemService;

    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/add")
    public ResponseEntity<ApiResponse> addToCart(@RequestBody AddToCartDto addToCartDto,
                                                 @RequestParam("token") String token, @RequestParam("quant") int quant) throws AuthenticationFailException, FoodItemNotExistException {
        authenticationService.authenticate(token);
        User user = authenticationService.getUser(token);
        FoodItem fooditem = fooditemService.getFoodItemById(addToCartDto.getFooditemId());
        System.out.println("product to add"+  fooditem.getName());
        System.out.println("Quantity===>"+quant);
        cartService.addToCart(addToCartDto, fooditem, user, quant);
        return new ResponseEntity<ApiResponse>(new ApiResponse(true, "Added to cart"), HttpStatus.CREATED);
    }
    @GetMapping("/")
    public ResponseEntity<CartDto> getCartItems(@RequestParam("token") String token) throws AuthenticationFailException {
        authenticationService.authenticate(token);
        User user = authenticationService.getUser(token);
        CartDto cartDto = cartService.listCartItems(user);
        return new ResponseEntity<CartDto>(cartDto,HttpStatus.OK);
    }
    @PutMapping("/update/{cartItemId}")
    public ResponseEntity<ApiResponse> updateCartItem(@RequestBody @Valid AddToCartDto cartDto,
                                                      @RequestParam("token") String token) throws AuthenticationFailException,FoodItemNotExistException {
        authenticationService.authenticate(token);
        User user = authenticationService.getUser(token);
        FoodItem fooditem = fooditemService.getFoodItemById(cartDto.getFooditemId());
        cartService.updateCartItem(cartDto, user,fooditem);
        return new ResponseEntity<ApiResponse>(new ApiResponse(true, "FoodItem has been updated"), HttpStatus.OK);
    }

    @DeleteMapping("/delete/{cartItemId}")
    public ResponseEntity<ApiResponse> deleteCartItem(@PathVariable("cartItemId") int itemID,@RequestParam("token") String token) throws AuthenticationFailException, CartItemNotExistException {
        authenticationService.authenticate(token);
        int userId = authenticationService.getUser(token).getId();
        cartService.deleteCartItem(itemID, userId);
        return new ResponseEntity<ApiResponse>(new ApiResponse(true, "Item has been removed"), HttpStatus.OK);
    }
}