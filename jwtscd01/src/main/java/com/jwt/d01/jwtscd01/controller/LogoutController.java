package com.jwt.d01.jwtscd01.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/logout")
public class LogoutController {

    Logger logger = LoggerFactory.getLogger(LogoutController.class);

    @RequestMapping
    public String logout() {
        logger.info("Logout endpoint accessed.");
        // Perform logout logic here, like invalidating the session
        return "redirect:/login"; // Redirects to the login page after logout
    }
}
