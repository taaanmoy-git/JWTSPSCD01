package com.jwt.d01.jwtscd01.security;

import java.io.IOException;
import java.io.PrintWriter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
	// Initialize the logger
	private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);

	@Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        // Log the unauthorized access attempt with details
        logger.error("Access Denied ! Unauthorized access attempt. Message : {}", authException.getMessage());

		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		PrintWriter writter = response.getWriter();
		writter.println("Access Denied !" + authException.getMessage());
		
	}

}
