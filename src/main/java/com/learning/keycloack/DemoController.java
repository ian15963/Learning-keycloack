package com.learning.keycloack;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/keycloack")
public class DemoController {

    @GetMapping
    @PreAuthorize("hasRole('client_user')")
    public String hello(){
        return "Hello World";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('client_admin')")
    public String hello2(){
        return "Hello Adm";
    }
}
