package com.lkc1009.resource.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    @GetMapping("/message1")
    public String getMessage1() {
        return "Get /message1";
    }

    @GetMapping("/message2")
    @PreAuthorize("hasAuthority('SCOPE_profile')")
    public String getMessage2() {
        return "Get /message2";
    }

    @GetMapping("/message3")
    @PreAuthorize("hasAuthority('SCOPE_Message')")
    public String getMessage3() {
        return "Get /message3";
    }
}
