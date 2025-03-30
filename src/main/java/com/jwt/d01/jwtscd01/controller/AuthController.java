package com.jwt.d01.jwtscd01.controller;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import com.jwt.d01.jwtscd01.models.JwtRequest;
import com.jwt.d01.jwtscd01.models.JwtResponse;
import com.jwt.d01.jwtscd01.security.JwtHelper;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtHelper jwtHelper;

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest request) {
        logger.info("Login attempt for user: {}", request.getEmail());

        this.doAuthenticate(request.getEmail(), request.getPassword());

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
        String token = this.jwtHelper.generateToken(userDetails);

        logger.info("Login successful for user: {}", request.getEmail());

        JwtResponse response = new JwtResponse.Builder()
                .setJwtToken(token)
                .setUsername(userDetails.getUsername())
                .build();

        return ResponseEntity.ok(response);
    }

    private void doAuthenticate(String email, String password) {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(email, password);
        try {
            authenticationManager.authenticate(authentication);
            logger.info("Authentication successful for user: {}", email);
        } catch (BadCredentialsException e) {
            logger.error("Authentication failed for user: {}", email);
            throw new BadCredentialsException("Invalid Username or Password!");
        }
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, String>> exceptionHandler(BadCredentialsException ex) {
        logger.warn("Authentication failed: {}", ex.getMessage());
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", "Invalid Username or Password!");
        //  return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Credentials!!");
        return new ResponseEntity<Map<String, String>>(errorResponse, HttpStatus.UNAUTHORIZED);
    }
}
