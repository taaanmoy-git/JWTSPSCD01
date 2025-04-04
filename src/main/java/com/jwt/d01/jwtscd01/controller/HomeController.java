package com.jwt.d01.jwtscd01.controller;

import java.security.Principal;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.jwt.d01.jwtscd01.models.User;
import com.jwt.d01.jwtscd01.service.UserService;

//@RestController 
// if we use @RestController  it will return response as text hometest
@Controller
@RequestMapping("/home")
public class HomeController {
	
	@Autowired
	private UserService userService;

    Logger logger = LoggerFactory.getLogger(HomeController.class);

    @RequestMapping("/test")
    public String test() {
        logger.info("This is working message");
        return "hometest"; // This will call html page hometest.html
    }

    @GetMapping("/user")
    @ResponseBody
    public List<User> getUsers() {
    	return userService.getAllUsers();
    }
    
    @GetMapping("/user/current")
    @ResponseBody
    public String getLoggedInUser(Principal principal) {
    	return principal.getName();
    }
    
    @GetMapping("/user/string") // We didn't use RestController, 
    @ResponseBody    		    // for that @ResponseBody need, to pass String or JSON
    public String getString() {
    	return userService.getAllUsers().toString();
    }

}