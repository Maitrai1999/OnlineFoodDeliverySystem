package com.spring.restapi.fooddelivery.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.spring.restapi.fooddelivery.dao.UserRepository;
import com.spring.restapi.fooddelivery.dto.ResponseDto;
import com.spring.restapi.fooddelivery.dto.SignInDto;
import com.spring.restapi.fooddelivery.dto.SignInResponseDto;
import com.spring.restapi.fooddelivery.dto.SignupDto;
import com.spring.restapi.fooddelivery.dto.UserUpdateDto;
import com.spring.restapi.fooddelivery.exceptions.AuthenticationFailException;
import com.spring.restapi.fooddelivery.exceptions.CustomException;
import com.spring.restapi.fooddelivery.model.User;
import com.spring.restapi.fooddelivery.service.AuthenticationService;
import com.spring.restapi.fooddelivery.service.UserService;

@RequestMapping("user")
@CrossOrigin(origins = "*", allowedHeaders = "*")
@RestController
public class UserController {

	@Autowired
	UserRepository userRepository;

	@Autowired
	AuthenticationService authenticationService;

	@Autowired
	UserService userService;

	@GetMapping("/all")
	public List<User> findAllUser(@RequestParam("token") String token) throws AuthenticationFailException {
		authenticationService.authenticate(token);
		return userRepository.findAll();
	}

	@PostMapping("/signup")
	public ResponseDto Signup(@RequestBody SignupDto signupDto) throws CustomException {
		return userService.signUp(signupDto);
	}

	// TODO token should be updated
	@PostMapping("/signIn")
	public SignInResponseDto Signup(@RequestBody SignInDto signInDto) throws CustomException {
		return userService.signIn(signInDto);
	}

	@PostMapping("/updateUser")
	public User updateUser(@RequestBody User user) {
		return this.userService.updateUser(user);
	}
}