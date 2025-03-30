package com.jwt.d01.jwtscd01.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // Logger to keep track of filter actions and potential issues
    private Logger logger = LoggerFactory.getLogger(OncePerRequestFilter.class);

    // Helper class for handling JWT (generation, validation, etc.)
    @Autowired
    private JwtHelper jwtHelper;

    // Service to load user details from the database or authentication source
    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * This method intercepts every incoming HTTP request to check the Authorization header 
     * for a valid JWT token. It performs authentication if a valid token is present.
     *
     * @param request     The HTTP request object
     * @param response    The HTTP response object
     * @param filterChain The filter chain for processing subsequent filters
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Extract the "Authorization" header from the incoming request
    	// Authorization Header Look like  = Bearer 2352345235sdfrsfgsdfsdf
    	// token = 2352345235sdfrsfgsdfsdf
    	// username = it it inside token
        String requestHeader = request.getHeader("Authorization");
        
        logger.info("Authorization Header: {}", requestHeader);
        
        // Bearer 2352345235sdfrsfgsdfsdf
        // token look like after Bearer ,token = 2352345235sdfrsfgsdfsdf
        // username = it it inside token
        
        String username = null; // Will store the username extracted from the JWT token
        String token = null;    // Will store the actual JWT token

        // Check if the Authorization header is present and starts with "Bearer"
        if (requestHeader != null && requestHeader.startsWith("Bearer ")) {
            // Remove the "Bearer " prefix to get the actual token
            token = requestHeader.substring(7);

            try {
                // Extract the username from the token
                username = this.jwtHelper.getUsernameFromToken(token);
            } catch (IllegalArgumentException e) {
                logger.error("Error while fetching username from token: Illegal Argument", e);
            } catch (ExpiredJwtException e) {
                logger.error("Token has expired", e);
            } catch (MalformedJwtException e) {
                logger.error("Token is malformed or has been tampered with", e);
            } catch (Exception e) {
                logger.error("An unexpected error occurred while processing the token", e);
            }
        } else {
            // If the Authorization header is missing or invalid
            logger.warn("Invalid Authorization Header: No Bearer token found");
        }

        // If a valid username is extracted and no authentication is set in the SecurityContext
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Load the user details from the database or service
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // Validate the token using the user details
            boolean isValidToken = this.jwtHelper.validateToken(token, userDetails);

            if (isValidToken) {
                // If the token is valid, create an authentication object
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                // Attach additional details about the request to the authentication object
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the authentication object in the SecurityContext
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                logger.warn("Token validation failed");
            }
        }

        // Pass the request and response to the next filter in the filter chain
        filterChain.doFilter(request, response);
    }
}