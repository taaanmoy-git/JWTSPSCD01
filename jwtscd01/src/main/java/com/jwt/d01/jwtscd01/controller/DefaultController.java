package com.jwt.d01.jwtscd01.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
// http://localhost:8080/
@Controller
public class DefaultController {

    @RequestMapping("/")
    public String Index() {
        return "index"; //  index.html exists in the templates folder
    }
}
// With in index will be all pages mapping button
