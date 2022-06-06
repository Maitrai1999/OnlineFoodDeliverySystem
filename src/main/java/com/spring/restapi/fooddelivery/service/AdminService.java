package com.spring.restapi.fooddelivery.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.spring.restapi.fooddelivery.configuration.MessageStrings;
import com.spring.restapi.fooddelivery.dao.AdminRepository;
import com.spring.restapi.fooddelivery.dao.UserRepository;
import com.spring.restapi.fooddelivery.dto.AdminCreateDto;
import com.spring.restapi.fooddelivery.dto.FoodItemUpdateDto;
import com.spring.restapi.fooddelivery.dto.ResponseDto;
import com.spring.restapi.fooddelivery.dto.SignInDto;
import com.spring.restapi.fooddelivery.dto.SignInResponseDto;
import com.spring.restapi.fooddelivery.dto.SignupDto;
import com.spring.restapi.fooddelivery.dto.UserCreateDto;
import com.spring.restapi.fooddelivery.dto.UserUpdateDto;
import com.spring.restapi.fooddelivery.enums.ResponseStatus;
import com.spring.restapi.fooddelivery.enums.Role;
import com.spring.restapi.fooddelivery.exceptions.AuthenticationFailException;
import com.spring.restapi.fooddelivery.exceptions.CartItemNotExistException;
import com.spring.restapi.fooddelivery.exceptions.CustomException;
import com.spring.restapi.fooddelivery.exceptions.FoodItemNotExistException;
import com.spring.restapi.fooddelivery.model.Admin;
import com.spring.restapi.fooddelivery.model.AuthenticationToken;
import com.spring.restapi.fooddelivery.model.User;
import com.spring.restapi.fooddelivery.utils.Helper;

@Service
public class AdminService {

    @Autowired
    AdminRepository adminRepository;

    @Autowired
    AuthenticationService authenticationService;

    Logger logger = LoggerFactory.getLogger(AdminService.class);


    public ResponseDto signUp(SignupDto signupDto)  throws CustomException {
        // Check to see if the current email address has already been registered.
        if (Helper.notNull(adminRepository.findByEmail(signupDto.getEmail()))) {
            // If the email address has been registered then throw an exception.
            throw new CustomException("Admin already exists");
        }
     // first encrypt the password
        String encryptedPassword = signupDto.getPassword();
        try {
            encryptedPassword = hashPassword(signupDto.getPassword());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error("hashing password failed {}", e.getMessage());
        }
    
        Admin admin = new Admin(signupDto.getFirstName(), signupDto.getLastName(), signupDto.getEmail(), Role.admin, encryptedPassword );
	
        Admin createdAdmin;
        try {
        	// save the User
            createdAdmin = adminRepository.save(admin);
            // generate token for user
            final AuthenticationToken authenticationToken = new AuthenticationToken(createdAdmin);
            // save token in database
            authenticationService.saveConfirmationToken(authenticationToken);
            // success in creating
            return new ResponseDto(ResponseStatus.success.toString(), encryptedPassword);
        } catch (Exception e) {
            // handle signup error
            throw new CustomException(e.getMessage());
        }
    }
    public SignInResponseDto signIn(SignInDto signInDto) throws CustomException {
        // first find User by email
        Admin admin = adminRepository.findByEmail(signInDto.getEmail());
        if(!Helper.notNull(admin)){
            throw  new AuthenticationFailException("admin not present");
        }
        try {
            // check if password is right
            if (!admin.getPassword().equals(hashPassword(signInDto.getPassword()))){
                // passowrd doesnot match
                throw  new AuthenticationFailException(MessageStrings.WRONG_PASSWORD);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error("hashing password failed {}", e.getMessage());
            throw new CustomException(e.getMessage());
        }
        AuthenticationToken token = authenticationService.getToken(admin);

        if(!Helper.notNull(token)) {
            // token not present
            throw new CustomException("token not present");
        }

        return new SignInResponseDto ("success", token.getToken());
    }


    String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes());
        byte[] digest = md.digest();
        String myHash = DatatypeConverter
                .printHexBinary(digest).toUpperCase();
        return myHash;
    }

    public ResponseDto createAdmin(String token, AdminCreateDto adminCreateDto) throws CustomException, AuthenticationFailException {
        User creatingUser = authenticationService.getUser(token);
        if (!canCrudUser(creatingUser.getRole())) {
            // user can't create new user
            throw  new AuthenticationFailException(MessageStrings.USER_NOT_PERMITTED);
        }
        String encryptedPassword = adminCreateDto.getPassword();
        try {
            encryptedPassword = hashPassword(adminCreateDto.getPassword());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error("hashing password failed {}", e.getMessage());
        }
       Admin admin = new Admin(adminCreateDto.getFirstName(), adminCreateDto.getLastName(), adminCreateDto.getEmail(), adminCreateDto.getRole(), encryptedPassword );
        Admin createdAdmin;
        try {
            createdAdmin = adminRepository.save(admin);
            final AuthenticationToken authenticationToken = new AuthenticationToken(createdAdmin);
            authenticationService.saveConfirmationToken(authenticationToken);
            return new ResponseDto(ResponseStatus.success.toString(), encryptedPassword);
        } catch (Exception e) {
            // handle user creation fail error
            throw new CustomException(e.getMessage());
        }

    }
    boolean canCrudUser(Role role) {
        if (role == Role.admin || role == Role.manager) {
            return true;
        }
        return false;
    }

   
	public Admin updateAdmin(Admin admin) {
		return adminRepository.save(admin);
	}

	public ResponseDto updateFoodItem(String token, FoodItemUpdateDto fooditemUpdateDto) {
		// TODO Auto-generated method stub
		return null;
	}

	
	 public void deleteFoodItem(int id,int userId) throws FoodItemNotExistException {
	        if (!adminRepository.existsById(id))
	            throw new FoodItemNotExistException("Fooditem id is invalid : " + id);
	        adminRepository.deleteById(id);

	    }
	
}