package com.spring.restapi.fooddelivery.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.spring.restapi.fooddelivery.dao.AdminRepository;
import com.spring.restapi.fooddelivery.dto.FoodItemUpdateDto;
import com.spring.restapi.fooddelivery.dto.ResponseDto;
import com.spring.restapi.fooddelivery.dto.SignInDto;
import com.spring.restapi.fooddelivery.dto.SignInResponseDto;
import com.spring.restapi.fooddelivery.dto.SignupDto;
import com.spring.restapi.fooddelivery.exceptions.AuthenticationFailException;
import com.spring.restapi.fooddelivery.exceptions.CustomException;
import com.spring.restapi.fooddelivery.exceptions.FoodItemNotExistException;
import com.spring.restapi.fooddelivery.response.ApiResponse;
import com.spring.restapi.fooddelivery.service.AdminService;
import com.spring.restapi.fooddelivery.service.AuthenticationService;

@RequestMapping("admin")
@CrossOrigin(origins = "*", allowedHeaders = "*")
@RestController
public class AdminController {

    @Autowired
    AdminRepository adminRepository;

    @Autowired
    AuthenticationService authenticationService;

    @Autowired
    AdminService adminService;

    //TODO token should be updated
    
    @PostMapping("/signup")
    public ResponseDto Signup(@RequestBody SignupDto signupDto) throws CustomException {
        return adminService.signUp(signupDto);
    }
    
    @PostMapping("/signIn")
    public SignInResponseDto Signup(@RequestBody SignInDto signInDto) throws CustomException {
        return adminService.signIn(signInDto);
    }
    
   @PostMapping("/updateFoodItem")
   public ResponseDto updateFoodItem(@RequestParam("token") String token, @RequestBody FoodItemUpdateDto fooditemUpdateDto) {
   authenticationService.authenticate(token);
    return adminService.updateFoodItem(token, fooditemUpdateDto);
   }
   
  /* @DeleteMapping("/deleteFoodItem")
   public ResponseDto deleteFoodItem(@RequestParam("token") String token, @RequestBody FoodItemDeleteDto fooditemDeleteDto) {
   authenticationService.authenticate(token);
    return adminService.deleteFoodItem(token, fooditemDeleteDto);
   }*/
   @DeleteMapping("/delete/{FoodItemId}")
   public ResponseEntity<ApiResponse> deleteFoodItem(@PathVariable("FoodItemId") int itemID,@RequestParam("token") String token) throws AuthenticationFailException, FoodItemNotExistException {
       authenticationService.authenticate(token);
       int userId = authenticationService.getUser(token).getId();
       adminService.deleteFoodItem(itemID, userId);
       return new ResponseEntity<ApiResponse>(new ApiResponse(true, "Item has been removed"), HttpStatus.OK);
   }
}